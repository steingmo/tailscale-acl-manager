import Foundation

/// The workspace's server: the guarded client, devices and users, drift
/// against the last pull or push (or GitHub), and network traffic.
extension PolicyStore {
    /// Load the last `days` days of flow logs, a day per request so a busy
    /// tailnet's logs never have to fit in one response.
    func loadTraffic(days: Int) async throws {
        guard let client = serverClient() else { return }
        let workspace = currentWorkspaceID
        let end = Date()
        var acc = TrafficAccumulator()
        defer { trafficProgress = nil }
        for day in 0..<days {
            trafficProgress = "Loading day \(day + 1) of \(days)…"
            let from = end.addingTimeInterval(-Double(days - day) * 86_400)
            guard let records = try await client.flowRecords(from: from, to: from.addingTimeInterval(86_400)) else {
                throw ServerError(status: 0, message: "\(serverDisplayName) doesn't keep network flow logs.")
            }
            acc.add(records)
            guard workspace == currentWorkspaceID else { return }
        }
        traffic = TrafficSummary(start: end.addingTimeInterval(-Double(days) * 86_400), end: end, connections: acc.connections)
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

    /// Reload devices from the current workspace's server, if one is configured.
    func refreshNodes() async throws {
        guard let client = serverClient() else { return }
        let workspace = currentWorkspaceID
        let nodes = try await client.listNodes()
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
    }
}
