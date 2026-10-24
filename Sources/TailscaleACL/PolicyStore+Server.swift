import Foundation

/// The workspace's server: the guarded client, devices and users, drift
/// against the last pull or push (or GitHub), and network traffic.
extension PolicyStore {
    /// Load the last `days` days of flow logs, a day per request so a busy
    /// tailnet's logs never have to fit in one response.
    /// Flow logs for the last `days` days, an hour per request (three at a time,
    /// newest first), so progress moves and one slow hour doesn't hold up the
    /// rest. If the load is cancelled, the hours already in are kept. Returns
    /// how many hours were loaded.
    @discardableResult
    func loadTraffic(days: Int, client given: PolicyServer? = nil) async throws -> Int {
        guard let client = given ?? serverClient() else { return 0 }
        let workspace = currentWorkspaceID
        let hours = days * 24
        defer { trafficProgress = nil; trafficStarted = nil }
        // A 1Password key may first wait for approval in 1Password; say so.
        if given == nil, let stored = HeadscaleKeychain.load(account: workspace.uuidString),
           OnePassword.isReference(stored), !OnePassword.isCached(stored) {
            trafficProgress = "Waiting for 1Password approval…"
            _ = try await OnePassword.read(stored)
        }
        let end = Date()
        trafficStarted = Date()
        trafficProgress = "Hour 1 of \(hours)"
        var acc = TrafficAccumulator()
        var arrived: [Int: [FlowRecord]] = [:]   // hour (0 = newest) → records, until folded in
        var folded = 0, done = 0, records = 0
        do {
            try await withThrowingTaskGroup(of: (Int, [FlowRecord]?).self) { group in
                var pending = (0..<hours).makeIterator()
                func hour(_ i: Int) -> @Sendable () async throws -> (Int, [FlowRecord]?) {
                    let to = end.addingTimeInterval(-Double(i) * 3600)
                    return { (i, try await client.flowRecords(from: to.addingTimeInterval(-3600), to: to)) }
                }
                for _ in 0..<3 { if let i = pending.next() { group.addTask(operation: hour(i)) } }
                while let (i, result) = try await group.next() {
                    guard let result else { throw ServerError(status: 0, message: "\(serverDisplayName) doesn't keep network flow logs.") }
                    arrived[i] = result
                    done += 1
                    records += result.count
                    // Fold in newest-first, so a cancelled load keeps an unbroken recent window.
                    while let r = arrived.removeValue(forKey: folded) { acc.add(r); folded += 1 }
                    trafficProgress = "Hour \(done) of \(hours) · \(records.formatted()) flow records"
                    if let next = pending.next() { group.addTask(operation: hour(next)) }
                }
            }
        } catch {
            // Cancelled (the button, or leaving): keep what's in, if anything.
            guard Task.isCancelled, folded > 0 else { throw error }
        }
        guard workspace == currentWorkspaceID, folded > 0 else { return folded }
        traffic = TrafficSummary(start: end.addingTimeInterval(-Double(folded) * 3600), end: end, connections: acc.connections)
        return folded
    }

    /// Check whether the server's policy changed since the last pull/push.
    func checkServerDrift() async {
        if isGitOps, let client = serverClient(), let file = linkedFileURL {
            // Git mode: the server should match the default branch on GitHub.
            let workspace = currentWorkspaceID
            guard let repo = await GitRepo.containing(file),
                  let base = await repo.fileOnDefaultBranch(repo.relativePath(file)),
                  let current = try? await client.getPolicy(), workspace == currentWorkspaceID else { return }
            serverDrift = current == base ? nil : current
            driftGitBase = serverDrift == nil ? nil : base
            return
        }
        driftGitBase = nil
        guard let client = serverClient(), let last = currentWorkspace.lastSyncedPolicy else {
            serverDrift = nil
            return
        }
        let workspace = currentWorkspaceID
        guard let current = try? await client.getPolicy(), workspace == currentWorkspaceID else { return }
        serverDrift = current == last ? nil : current
        driftAuthor = nil
        if serverDrift != nil, let latest = try? await client.policyChanges(days: 30)?.first,
           workspace == currentWorkspaceID {
            let ago = RelativeDateTimeFormatter().localizedString(for: latest.date, relativeTo: Date())
            driftAuthor = "\(latest.who)\(latest.origin.isEmpty ? "" : " via the \(latest.origin)"), \(ago)"
        }
    }

    /// Client for the current workspace's server (Headscale or Tailscale),
    /// or nil if not configured.
    /// Every change through it asks for Touch ID (if enabled) and is logged.
    func serverClient() -> PolicyServer? {
        let ws = currentWorkspace
        return makeServer(kind: ws.kind, serverURL: ws.serverURL, tailnet: ws.tailnet ?? "-",
                          credential: HeadscaleKeychain.load(account: currentWorkspaceID.uuidString) ?? "")
            .map { GuardedServer($0, workspace: ws.name, requireAuth: SecuritySettings.requireAuth) }
    }

    var serverDisplayName: String {
        let ws = currentWorkspace
        return serverName(kind: ws.kind, serverURL: ws.serverURL, tailnet: ws.tailnet ?? "-")
    }

    /// Show what the server returned last time, until a refresh replaces it.
    func loadServerCache() {
        guard let cache = ServerCache.load(currentWorkspaceID) else { return }
        let users = ServerUsers(accounts: cache.accounts)
        headscaleNodes = cache.nodes
        serverAccounts = cache.accounts
        serverLogins = cache.accounts.isEmpty ? nil : users.logins
        serverUserAutogroups = users.autogroups
        policyChanges = cache.policyChanges
        serverDataSaved = cache.saved
    }

    func saveServerCache() {
        ServerCache(saved: Date(), nodes: headscaleNodes, accounts: serverAccounts, policyChanges: policyChanges)
            .save(currentWorkspaceID)
    }

    /// Reload devices from the current workspace's server, if one is configured.
    func refreshNodes() async throws {
        guard let client = serverClient() else { return }
        let workspace = currentWorkspaceID
        var nodes = try await client.listNodes()
        // Keep the attributes already loaded until fresh ones arrive.
        let known = Dictionary(headscaleNodes.map { ($0.id, $0.attributes) }, uniquingKeysWith: { a, _ in a })
        for i in nodes.indices { nodes[i].attributes = known[nodes[i].id] ?? nil }
        if workspace == currentWorkspaceID { headscaleNodes = nodes }
        var users: ServerUsers?
        var usersError: Error?
        do { users = try await client.serverUsers() } catch { usersError = error }
        if workspace == currentWorkspaceID {
            serverUsersError = usersError
            serverAccounts = users?.accounts ?? []
            serverLogins = users?.logins
            serverUserAutogroups = users?.autogroups ?? [:]
        }
        // Fetched at most every 5 minutes, and for devices that are new since.
        let stale = postureAttributesFetched.map { Date().timeIntervalSince($0) > 300 } ?? true
        if currentWorkspace.kind == .tailscale,
           stale || (postureAttributesError == nil && nodes.contains { $0.attributes == nil }) {
            await loadPostureAttributes(client, nodes: nodes, workspace: workspace)
        }
        guard workspace == currentWorkspaceID else { return }
        serverDataSaved = nil
        saveServerCache()
    }

    /// Tailscale has one request per device for posture attributes (Huntress,
    /// custom:…), so a few run at a time. Without the scope, devices keep
    /// no attributes and posture-gated rules stay conditional.
    func loadPostureAttributes(_ client: PolicyServer, nodes: [HeadscaleNode], workspace: UUID) async {
        var loaded: [String: [String: String]] = [:]
        var failure: Error?
        await withTaskGroup(of: (String, Result<[String: String]?, Error>).self) { group in
            // The plain next()/addTask loop: an earlier version added tasks from a
            // nested function while iterating with for-await, and release builds
            // aborted when a request outlived the group (1.26.0–1.26.1).
            var pending = nodes.map(\.id).makeIterator()
            func request(_ id: String) -> @Sendable () async -> (String, Result<[String: String]?, Error>) {
                { do { return (id, .success(try await client.postureAttributes(nodeID: id))) } catch { return (id, .failure(error)) } }
            }
            for _ in 0..<6 { if let id = pending.next() { group.addTask(operation: request(id)) } }
            while let (id, result) = await group.next() {
                switch result {
                case .success(let attrs): loaded[id] = attrs
                case .failure(let error): failure = failure ?? error
                }
                if failure == nil, let next = pending.next() { group.addTask(operation: request(next)) }
            }
        }
        guard workspace == currentWorkspaceID else { return }
        postureAttributesFetched = Date()
        if let failure {
            let denied = (failure as? ServerError).map { $0.status == 403 || $0.status == 401 } ?? false
            postureAttributesError = denied
                ? "Device posture isn't loaded: give the OAuth client the devices:posture_attributes:read scope."
                : "Device posture isn't loaded: \(failure.localizedDescription)"
            return
        }
        postureAttributesError = nil
        headscaleNodes = headscaleNodes.map { n in
            var n = n
            if let attrs = loaded[n.id] { n.attributes = attrs }
            return n
        }
    }
}
