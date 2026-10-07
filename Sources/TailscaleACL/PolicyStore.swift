import SwiftUI
import AppKit
import UniformTypeIdentifiers

@MainActor
final class PolicyStore: ObservableObject {
    @Published var text: String = "" {
        // Typing triggers a short debounce so the parse + evaluation + full
        // app re-render doesn't run on every keystroke.
        didSet { if text != oldValue { scheduleReparse() } }
    }
    @Published private(set) var tree: JSON?
    @Published private(set) var model = PolicyModel()
    @Published private(set) var parseError: HuJSONError?
    @Published private(set) var testResults: [TestResult] = []
    @Published private(set) var sshTestResults: [SSHTestResult] = []
    @Published private(set) var lintIssues: [LintIssue] = []
    /// Nodes last fetched from Headscale (shared by the Headscale and simulator screens).
    @Published var headscaleNodes: [HeadscaleNode] = [] {
        didSet { if isValid { lintIssues = allLint() } }
    }
    /// The server's user logins, for spotting users who left; nil when
    /// unknown (no server, or the credential can't list users).
    @Published var serverLogins: Set<String>? {
        didSet { if isValid { lintIssues = allLint() } }
    }
    /// Network traffic from the server's flow logs, once loaded.
    @Published var traffic: TrafficSummary?
    /// Set (e.g. from the Access Map) to show the Traffic screen filtered to
    /// a device, user, group, tag, or IP; the screen clears it.
    @Published var trafficFilterRequest: String?
    /// "Loading day 2 of 7…" while traffic loads.
    @Published var trafficProgress: String?

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

    /// The server's users (empty when unknown).
    @Published var serverAccounts: [ServerAccount] = []
    /// Role autogroups of the server's users; re-evaluates the policy when set.
    @Published var serverUserAutogroups: [String: Set<String>] = [:] {
        didSet { if serverUserAutogroups != oldValue { reparseNow() } }
    }

    private func allLint() -> [LintIssue] {
        lintPolicy(model) + lintNodes(model, nodes: headscaleNodes) + lintUsers(model, logins: serverLogins)
    }

    /// Set (e.g. from Problems) to show the Policy Editor at a 1-based line;
    /// the editor clears it once revealed.
    @Published var editorLineRequest: Int?
    /// Names and definitions for editor completion and hover, per parse.
    private(set) var vocabulary = EditorVocabulary()
    /// Set (e.g. by quick search) to make the Access Map focus an entity;
    /// "node:<id>" focuses a device. The map clears it once applied.
    @Published var mapFocusRequest: String?
    /// The server's policy when it changed since this workspace's last
    /// pull or push (someone edited it elsewhere); nil when in sync or unknown.
    @Published var serverDrift: String?
    /// The latest policy change in the server's audit log while drifted
    /// (Tailscale only), e.g. "Amy Lee via the admin console, 2 hr. ago".
    @Published var driftAuthor: String?
    /// Git mode: the policy file on GitHub's default branch, when the server differs from it.
    @Published var driftGitBase: String?
    @Published private(set) var workspaces: [Workspace]
    @Published private(set) var currentWorkspaceID: UUID
    /// The window's undo manager; visual edits register here so Cmd-Z works everywhere.
    weak var undoManager: UndoManager?

    private var parseTask: Task<Void, Never>?
    /// The linked file's contents as last read or written; nil until read
    /// this session, so a stale editor never overwrites the file.
    private var linkedFileContents: String?
    private var fileWatchTask: Task<Void, Never>?
    /// Why the linked file couldn't be read or written, if it couldn't.
    @Published private(set) var linkedFileError: String?

    var evaluator: Evaluator { Evaluator(model: model) }
    var isValid: Bool { parseError == nil && tree != nil }

    var currentWorkspace: Workspace {
        workspaces.first { $0.id == currentWorkspaceID } ?? workspaces[0]
    }

    init() {
        var list = WorkspaceStore.load()
        if list.isEmpty { list = [WorkspaceStore.migrateLegacy()] }
        let saved = UserDefaults.standard.string(forKey: "currentWorkspaceID").flatMap(UUID.init)
        workspaces = list
        currentWorkspaceID = list.first { $0.id == saved }?.id ?? list[0].id
        text = currentWorkspace.policy
        reparseNow()
        SnapshotStore.record(currentWorkspaceID, text: text, reason: "opened")
        startLinkedFile()
    }

    // MARK: - Workspaces

    func switchWorkspace(to id: UUID) {
        guard id != currentWorkspaceID, workspaces.contains(where: { $0.id == id }) else { return }
        currentWorkspaceID = id
        UserDefaults.standard.set(id.uuidString, forKey: "currentWorkspaceID")
        headscaleNodes = []
        serverLogins = nil
        serverUserAutogroups = [:]
        serverAccounts = []
        traffic = nil
        serverDrift = nil
        linkedFileContents = nil
        text = currentWorkspace.policy
        reparseNow()
        SnapshotStore.record(id, text: text, reason: "opened")
        undoManager?.removeAllActions() // undo must not cross into another workspace
        startLinkedFile()
    }

    // MARK: - Linked file (GitOps)

    var linkedFileURL: URL? { currentWorkspace.linkedFile.map { URL(fileURLWithPath: $0) } }

    /// Changes go to Tailscale as GitHub pull requests (see GitOps.swift).
    var isGitOps: Bool { currentWorkspace.gitOps == true && linkedFileURL != nil }

    /// Link the workspace to a policy file in a Git repository, managed by
    /// pull requests; nil turns Git mode off (the file stays linked).
    func setGitOps(file: URL?) {
        guard let i = workspaces.firstIndex(where: { $0.id == currentWorkspaceID }) else { return }
        workspaces[i].gitOps = file != nil ? true : nil
        saveWorkspaces()
        if let file { setLinkedFile(file.path) }
        serverDrift = nil
    }

    /// Keep the workspace in sync with a policy file, e.g. in the Git repo a
    /// GitOps workflow pushes from. The file's contents replace the editor's.
    func linkFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json, .text, .plainText, .data]
        panel.allowsOtherFileTypes = true
        panel.message = "Choose the policy file to keep in sync (its contents replace the editor's)"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        setLinkedFile(url.path)
    }

    func setLinkedFile(_ path: String?) {
        guard let i = workspaces.firstIndex(where: { $0.id == currentWorkspaceID }) else { return }
        workspaces[i].linkedFile = path
        saveWorkspaces()
        linkedFileContents = nil
        startLinkedFile()
    }

    /// Read the linked file now, then poll it for outside changes (git pull,
    /// another editor). Edits in the app are written back by `reparseNow`.
    private func startLinkedFile() {
        fileWatchTask?.cancel()
        linkedFileError = nil
        guard linkedFileURL != nil else { return }
        readLinkedFile()
        // ponytail: polls every 1.5 s; fine for one small file, use FSEvents if it ever watches many.
        fileWatchTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                guard !Task.isCancelled else { return }
                self?.readLinkedFile()
            }
        }
    }

    private func readLinkedFile() {
        guard let url = linkedFileURL else { return }
        guard let contents = try? String(contentsOf: url, encoding: .utf8) else {
            linkedFileError = "Can't read \(url.lastPathComponent)"
            return
        }
        linkedFileError = nil
        guard contents != linkedFileContents else { return }
        linkedFileContents = contents
        if contents != text { loadPolicy(contents, reason: "changed in \(url.lastPathComponent)") }
    }

    /// Write a valid policy back to the linked file (only once it has been read).
    private func writeLinkedFile() {
        guard let url = linkedFileURL, let known = linkedFileContents, known != text else { return }
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
            linkedFileContents = text
            linkedFileError = nil
        } catch {
            linkedFileError = "Can't write \(url.lastPathComponent): \(error.localizedDescription)"
        }
    }

    /// New workspace, empty or a copy of the current one (policy, server, API key).
    func addWorkspace(name: String, duplicatingCurrent: Bool) {
        var ws = Workspace(name: name, serverURL: "", policy: "{\n}\n")
        if duplicatingCurrent {
            ws.serverURL = currentWorkspace.serverURL
            ws.policy = text
            if let key = HeadscaleKeychain.load(account: currentWorkspaceID.uuidString) {
                HeadscaleKeychain.save(key, account: ws.id.uuidString)
            }
        }
        workspaces.append(ws)
        saveWorkspaces()
        switchWorkspace(to: ws.id)
    }

    func renameWorkspace(_ id: UUID, to name: String) {
        guard let i = workspaces.firstIndex(where: { $0.id == id }), !name.isEmpty else { return }
        workspaces[i].name = name
        saveWorkspaces()
    }

    func deleteWorkspace(_ id: UUID) {
        guard workspaces.count > 1 else { return }
        if id == currentWorkspaceID {
            switchWorkspace(to: workspaces.first { $0.id != id }!.id)
        }
        workspaces.removeAll { $0.id == id }
        HeadscaleKeychain.save("", account: id.uuidString)
        SnapshotStore.delete(id)
        saveWorkspaces()
    }

    /// Record what the server holds after a pull or push.
    func markSynced(_ serverPolicy: String) {
        guard let i = workspaces.firstIndex(where: { $0.id == currentWorkspaceID }) else { return }
        workspaces[i].lastSyncedPolicy = serverPolicy
        saveWorkspaces()
        serverDrift = nil
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

    /// Save the current policy as a snapshot (skipped if unchanged since the last one).
    func snapshot(reason: String) {
        SnapshotStore.record(currentWorkspaceID, text: text, reason: reason)
    }

    /// Write a change into other workspaces' saved policies (not the open one).
    /// Each target gets a snapshot before and after, since there's no undo there.
    func modifyWorkspaces(_ targets: [UUID], reason: String,
                          _ change: (String) -> (text: String?, outcome: CopyOutcome)) -> [(name: String, outcome: CopyOutcome)] {
        var results: [(name: String, outcome: CopyOutcome)] = []
        for id in targets where id != currentWorkspaceID {
            guard let i = workspaces.firstIndex(where: { $0.id == id }) else { continue }
            let (text, outcome) = change(workspaces[i].policy)
            if let text, text != workspaces[i].policy {
                SnapshotStore.record(id, text: workspaces[i].policy, reason: "before \(reason)")
                workspaces[i].policy = text
                SnapshotStore.record(id, text: text, reason: reason)
                // Its linked file wins when that workspace opens, so it gets the change too.
                if let path = workspaces[i].linkedFile { try? text.write(toFile: path, atomically: true, encoding: .utf8) }
            }
            results.append((workspaces[i].name, outcome))
        }
        saveWorkspaces()
        return results
    }

    /// Groups whose members include any of `names` (case-insensitive).
    func groups(containing names: [String]) -> [String] {
        let wanted = Set(names.map { $0.lowercased() })
        return model.groupOrder.filter { g in (model.groups[g] ?? []).contains { wanted.contains($0.lowercased()) } }
    }

    /// Add a user to groups (skipping ones they're in) in one undoable step.
    func addUser(_ login: String, toGroups groups: [String]) {
        guard !groups.isEmpty else { return }
        mutate { tree in
            var list = tree["groups"]?.members ?? []
            for g in groups {
                if let i = list.firstIndex(where: { $0.key == g }) {
                    var members = list[i].value.elements ?? []
                    guard !members.contains(where: { $0.value.stringValue?.lowercased() == login.lowercased() }) else { continue }
                    members.append(JSON.Element(comments: [], value: .string(login)))
                    list[i].value = .array(members)
                } else {
                    list.append(JSON.Member(comments: [], key: g, value: stringArrayJSON([login])))
                }
            }
            tree["groups"] = .object(list)
        }
    }

    /// Offboarding: remove every name of a user from all groups and tag
    /// owners in one undoable step. Rules naming them directly are left for
    /// Problems to flag, since editing those changes other people's access.
    func removeUserEverywhere(_ names: [String]) {
        let wanted = Set(names.map { $0.lowercased() })
        mutate { tree in
            for section in ["groups", "tagOwners"] {
                guard var list = tree[section]?.members else { continue }
                for i in list.indices {
                    list[i].value.elements?.removeAll { wanted.contains($0.value.stringValue?.lowercased() ?? "") }
                }
                tree[section] = .object(list)
            }
        }
    }

    /// Rewrite ACL rules as grants in one undoable step.
    func convertToGrants() {
        mutate { convertACLsToGrants(&$0) }
    }

    /// Add a template's rules and definitions in one undoable step.
    func applyTemplate(_ template: PolicyTemplate, values: [String: String]) {
        mutate { template.apply(&$0, values) }
    }

    func setServerURL(_ url: String) {
        guard let i = workspaces.firstIndex(where: { $0.id == currentWorkspaceID }) else { return }
        workspaces[i].serverURL = url
        saveWorkspaces()
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

    func setServerKind(_ kind: ServerKind) {
        guard let i = workspaces.firstIndex(where: { $0.id == currentWorkspaceID }) else { return }
        workspaces[i].serverKind = kind
        // Sync state belongs to the previous server.
        workspaces[i].lastSyncedPolicy = nil
        serverDrift = nil
        headscaleNodes = []
        serverLogins = nil
        serverUserAutogroups = [:]
        serverAccounts = []
        traffic = nil
        saveWorkspaces()
    }

    func setTailnet(_ tailnet: String) {
        guard let i = workspaces.firstIndex(where: { $0.id == currentWorkspaceID }) else { return }
        workspaces[i].tailnet = tailnet
        saveWorkspaces()
    }

    /// Reload devices from the current workspace's server, if one is configured.
    func refreshNodes() async throws {
        guard let client = serverClient() else { return }
        let workspace = currentWorkspaceID
        let nodes = try await client.listNodes()
        if workspace == currentWorkspaceID { headscaleNodes = nodes }
        let users = try? await client.serverUsers()
        if workspace == currentWorkspaceID {
            serverAccounts = users?.accounts ?? []
            serverLogins = users?.logins
            serverUserAutogroups = users?.autogroups ?? [:]
        }
    }

    private func saveWorkspaces() {
        try? WorkspaceStore.save(workspaces)
    }

    /// Replace the whole policy text as one undoable step (Cmd-Z restores it).
    private func replaceText(_ new: String) {
        let old = text
        guard new != old else { return }
        text = new
        reparseNow()
        undoManager?.registerUndo(withTarget: self) { store in
            MainActor.assumeIsolated { store.replaceText(old) }
        }
        undoManager?.setActionName("Policy Change")
    }

    private func scheduleReparse() {
        parseTask?.cancel()
        parseTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 120_000_000)
            guard !Task.isCancelled else { return }
            self?.reparseNow()
        }
    }

    private func reparseNow() {
        parseTask?.cancel()
        parseTask = nil
        // Autosave: the editor text is the current workspace's policy.
        // ponytail: saves on each (debounced) parse; a quit within 120 ms of the
        // last keystroke can lose that keystroke.
        if let i = workspaces.firstIndex(where: { $0.id == currentWorkspaceID }),
           workspaces[i].policy != text {
            workspaces[i].policy = text
            saveWorkspaces()
        }
        do {
            // Emptying the editor means "start from scratch", not a syntax error.
            let source = text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                ? "{}" : text
            let parsed = try HuJSONParser.parse(source)
            tree = parsed
            model = PolicyModel(tree: parsed)
            model.userAutogroups = serverUserAutogroups
            vocabulary = EditorVocabulary(model)
            parseError = nil
            testResults = evaluator.runTests()
            sshTestResults = evaluator.runSSHTests()
            lintIssues = allLint()
            writeLinkedFile()
        } catch let error as HuJSONError {
            parseError = error
            testResults = []
            sshTestResults = []
            lintIssues = [LintIssue(severity: .error, title: "Policy does not parse",
                                    detail: "Line \(error.line): \(error.message)", line: error.line)]
        } catch {
            parseError = HuJSONError(message: "\(error)", line: 0)
            testResults = []
            lintIssues = []
        }
    }

    /// Apply a structural edit to the tree and regenerate the policy text,
    /// preserving comments captured at parse time. Parses immediately so the
    /// UI reflects the edit without the typing debounce.
    func mutate(_ edit: (inout JSON) -> Void) {
        guard var t = tree else { return }
        edit(&t)
        replaceText(HuJSONSerializer.serialize(t))
    }

    /// The editor line a problem points at, if it can be found.
    func line(of issue: LintIssue) -> Int? {
        issue.line ?? issue.path.flatMap { tree?.line(at: $0) }
    }

    func reset() {
        loadPolicy(SamplePolicy.text, reason: "reset")
    }

    // MARK: - Clipboard / files

    func copyToClipboard() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    func importFromFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json, .text, .plainText, .data]
        panel.allowsOtherFileTypes = true
        panel.message = "Choose a Tailscale ACL policy file (HuJSON)"
        if panel.runModal() == .OK, let url = panel.url,
           let contents = try? String(contentsOf: url, encoding: .utf8) {
            loadPolicy(contents, reason: "imported")
        }
    }

    /// Replace the whole policy (import, Headscale pull) and parse immediately.
    /// Snapshots what's being replaced and the result, so both can be restored.
    func loadPolicy(_ contents: String, reason: String = "replaced") {
        snapshot(reason: "before \(reason)")
        defer { snapshot(reason: reason) }
        replaceText(contents)
    }

    /// Save a Markdown access report for the current workspace.
    func exportReport() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "md") ?? .plainText]
        panel.nameFieldStringValue = "\(currentWorkspace.name) access report.md"
        panel.message = "Export an access report (groups, tags, devices, rules, who can reach what)"
        if panel.runModal() == .OK, let url = panel.url {
            // One access-map image per group and tag, in a folder next to the report.
            let folderName = url.deletingPathExtension().lastPathComponent + " images"
            let folder = url.deletingLastPathComponent().appendingPathComponent(folderName, isDirectory: true)
            try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            var images: [(title: String, path: String)] = []
            let entities = model.groupOrder.map { (AccessMapScreen.Kind.group, $0) }
                + model.tagOrder.map { (AccessMapScreen.Kind.tag, $0) }
            for (kind, name) in entities {
                let file = name.replacingOccurrences(of: ":", with: "-") + ".png"
                if let png = renderPNG(AccessMapScreen(focus: kind, name).environmentObject(self)),
                   (try? png.write(to: folder.appendingPathComponent(file))) != nil {
                    images.append((name, "\(folderName)/\(file)"))
                }
            }
            let report = policyReport(workspace: currentWorkspace.name, model: model,
                                      nodes: headscaleNodes, problems: lintIssues, mapImages: images)
            try? report.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    func exportToFile() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = "policy.hujson"
        panel.allowsOtherFileTypes = true
        panel.message = "Export the current ACL policy"
        if panel.runModal() == .OK, let url = panel.url {
            try? text.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    // MARK: - Rule editing (used by the visual builder)

    func addRule(src: String, dstTarget: String, ports: String, proto: String?) {
        mutate { tree in
            var members: [JSON.Member] = [
                .init(comments: [], key: "action", value: .string("accept")),
                .init(comments: [], key: "src", value: stringArrayJSON([src])),
                .init(comments: [], key: "dst",
                      value: stringArrayJSON([DestSpec(target: dstTarget, ports: ports).spec])),
            ]
            if let proto, !proto.isEmpty, proto != "any" {
                members.insert(.init(comments: [], key: "proto", value: .string(proto)), at: 1)
            }
            var acls = tree["acls"]?.elements ?? []
            acls.append(JSON.Element(comments: [], value: .object(members)))
            if tree["acls"] == nil {
                tree["acls"] = .array(acls)
            } else {
                tree["acls"]?.elements = acls
            }
        }
    }

    /// Replace one dst entry of a rule (edit ports/protocol of a connection).
    func updateConnection(ruleIndex: Int, oldDst: String, newPorts: String, proto: String?) {
        mutate { tree in
            guard var acls = tree["acls"]?.elements, acls.indices.contains(ruleIndex) else { return }
            var rule = acls[ruleIndex].value
            var dst = rule["dst"]?.stringArray ?? []
            if let i = dst.firstIndex(of: oldDst) {
                dst[i] = DestSpec(target: DestSpec(oldDst).target, ports: newPorts).spec
            }
            rule["dst"] = stringArrayJSON(dst)
            if let proto, !proto.isEmpty, proto != "any" {
                rule["proto"] = .string(proto)
            } else {
                rule["proto"] = nil
            }
            acls[ruleIndex].value = rule
            tree["acls"]?.elements = acls
        }
    }

    /// Remove one dst entry; removes the whole rule if it was the last dst.
    func removeConnection(ruleIndex: Int, dst dstSpec: String) {
        mutate { tree in
            guard var acls = tree["acls"]?.elements, acls.indices.contains(ruleIndex) else { return }
            var rule = acls[ruleIndex].value
            var dst = rule["dst"]?.stringArray ?? []
            dst.removeAll { $0 == dstSpec }
            if dst.isEmpty {
                acls.remove(at: ruleIndex)
            } else {
                rule["dst"] = stringArrayJSON(dst)
                acls[ruleIndex].value = rule
            }
            tree["acls"]?.elements = acls
        }
    }

    // MARK: - Grant editing (modern syntax)

    /// Build grant `ip` entries from a ports string and protocol
    /// ("22,80" + tcp → ["tcp:22", "tcp:80"]).
    nonisolated static func ipEntries(ports: String, proto: String?) -> [String] {
        let parts = ports == "*"
            ? ["*"]
            : ports.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard let proto, proto != "any", !proto.isEmpty else { return parts }
        return parts.map { "\(proto):\($0)" }
    }

    /// Derive (proto, ports) UI fields from grant `ip` entries.
    nonisolated static func splitIPEntries(_ entries: [String]) -> (proto: String, ports: String) {
        var protos = Set<String>()
        var ports: [String] = []
        for e in entries {
            if let colon = e.firstIndex(of: ":") {
                protos.insert(String(e[..<colon]).lowercased())
                ports.append(String(e[e.index(after: colon)...]))
            } else {
                protos.insert("any")
                ports.append(e)
            }
        }
        let proto = protos.count == 1 ? protos.first! : "any"
        return (["tcp", "udp", "any"].contains(proto) ? proto : "any",
                ports.joined(separator: ","))
    }

    func addGrant(src: String, dstTarget: String, ports: String, proto: String?) {
        let entries = Self.ipEntries(ports: ports, proto: proto)
        mutate { tree in
            let members: [JSON.Member] = [
                .init(comments: [], key: "src", value: stringArrayJSON([src])),
                .init(comments: [], key: "dst", value: stringArrayJSON([dstTarget])),
                .init(comments: [], key: "ip", value: stringArrayJSON(entries)),
            ]
            var grants = tree["grants"]?.elements ?? []
            grants.append(JSON.Element(comments: [], value: .object(members)))
            if tree["grants"] == nil {
                tree["grants"] = .array(grants)
            } else {
                tree["grants"]?.elements = grants
            }
        }
    }

    func updateGrantIP(grantIndex: Int, ports: String, proto: String?) {
        let entries = Self.ipEntries(ports: ports, proto: proto)
        mutate { tree in
            guard var grants = tree["grants"]?.elements,
                  grants.indices.contains(grantIndex) else { return }
            var grant = grants[grantIndex].value
            grant["ip"] = stringArrayJSON(entries)
            grants[grantIndex].value = grant
            tree["grants"]?.elements = grants
        }
    }

    /// Remove one dst from a grant; removes the grant when no dst remains.
    func removeGrantConnection(grantIndex: Int, dst dstName: String) {
        mutate { tree in
            guard var grants = tree["grants"]?.elements,
                  grants.indices.contains(grantIndex) else { return }
            var grant = grants[grantIndex].value
            var dst = grant["dst"]?.stringArray ?? []
            dst.removeAll { $0 == dstName }
            if dst.isEmpty {
                grants.remove(at: grantIndex)
            } else {
                grant["dst"] = stringArrayJSON(dst)
                grants[grantIndex].value = grant
            }
            tree["grants"]?.elements = grants
        }
    }

    // MARK: - SSH rules

    private func sshMembers(action: String, src: [String], dst: [String],
                            users: [String]) -> [JSON.Member] {
        [
            .init(comments: [], key: "action", value: .string(action)),
            .init(comments: [], key: "src", value: stringArrayJSON(src)),
            .init(comments: [], key: "dst", value: stringArrayJSON(dst)),
            .init(comments: [], key: "users", value: stringArrayJSON(users)),
        ]
    }

    func addSSHRule(action: String, src: [String], dst: [String], users: [String]) {
        mutate { tree in
            var rules = tree["ssh"]?.elements ?? []
            rules.append(JSON.Element(
                comments: [],
                value: .object(sshMembers(action: action, src: src, dst: dst, users: users))
            ))
            if tree["ssh"] == nil {
                tree["ssh"] = .array(rules)
            } else {
                tree["ssh"]?.elements = rules
            }
        }
    }

    func updateSSHRule(index: Int, action: String, src: [String], dst: [String],
                       users: [String]) {
        mutate { tree in
            guard var rules = tree["ssh"]?.elements, rules.indices.contains(index) else { return }
            rules[index].value = .object(sshMembers(action: action, src: src, dst: dst, users: users))
            tree["ssh"]?.elements = rules
        }
    }

    /// Create (index nil) or update one rule in "acls", "grants", or "ssh".
    /// Only the given keys change (nil removes a key), so fields the editor
    /// doesn't show — proto, app, via, srcPosture — are kept. `name` is the
    /// rule's first comment line. `expires` sets ("YYYY-MM-DD") or removes
    /// (.some(nil)) the "expires:" comment; leave it nil to keep it as is.
    func saveRule(section: String, index: Int?, name: String, expires: String?? = nil,
                  fields: [(key: String, value: JSON?)]) {
        mutate { tree in
            var list = tree[section]?.elements ?? []
            let existing = index.flatMap { list.indices.contains($0) ? $0 : nil }
            var element = existing.map { list[$0] } ?? JSON.Element(comments: [], value: .object([]))
            for field in fields { element.value[field.key] = field.value }
            var expiry = element.comments.filter { RuleExpiry.date(in: $0) != nil }
            if let expires { expiry = expires.map { [RuleExpiry.comment(for: $0)] } ?? [] }
            element.comments.removeAll { RuleExpiry.date(in: $0) != nil }
            let trimmed = name.trimmingCharacters(in: .whitespaces)
            if element.comments.isEmpty {
                if !trimmed.isEmpty { element.comments = [trimmed] }
            } else if trimmed.isEmpty {
                element.comments.removeFirst()
            } else {
                element.comments[0] = trimmed
            }
            element.comments += expiry
            if let existing { list[existing] = element } else { list.append(element) }
            tree[section] = .array(list)
        }
    }

    func deleteRule(section: String, index: Int) {
        mutate { tree in
            guard var list = tree[section]?.elements, list.indices.contains(index) else { return }
            list.remove(at: index)
            tree[section] = .array(list)
        }
    }

    /// Apply a one-click fix from the Problems screen (undoable).
    func apply(_ action: LintFix.Action) {
        switch action {
        case .addTagOwner(let tag):
            addEntity(kind: .tag, name: tag, address: "")
        case .defineGroup(let group):
            addEntity(kind: .group, name: group, address: "")
        case .deleteEntity(let name):
            deleteEntity(name)
        case .deleteRule(let section, let index):
            deleteRule(section: section, index: index)
        case .removeGroupMember(let group, let member):
            mutate { tree in
                guard var members = tree["groups"]?[group]?.elements else { return }
                members.removeAll { $0.value.stringValue == member }
                tree["groups"]?[group] = .array(members)
            }
        }
    }

    /// Set the approvers for one route (empty removes it); `oldRoute` renames.
    func setRouteApprovers(route: String, approvers: [String], replacing oldRoute: String? = nil) {
        mutate { tree in
            var aa = tree["autoApprovers"] ?? .object([])
            var routes = aa["routes"]?.members ?? []
            if let i = routes.firstIndex(where: { $0.key == (oldRoute ?? route) }) {
                if approvers.isEmpty {
                    routes.remove(at: i)
                } else {
                    routes[i].key = route
                    routes[i].value = stringArrayJSON(approvers)
                }
            } else if !approvers.isEmpty {
                routes.append(JSON.Member(comments: [], key: route, value: stringArrayJSON(approvers)))
            }
            aa["routes"] = routes.isEmpty ? nil : .object(routes)
            tree["autoApprovers"] = (aa.members?.isEmpty ?? true) ? nil : aa
        }
    }

    func setExitNodeApprovers(_ approvers: [String]) {
        mutate { tree in
            var aa = tree["autoApprovers"] ?? .object([])
            aa["exitNode"] = approvers.isEmpty ? nil : stringArrayJSON(approvers)
            tree["autoApprovers"] = (aa.members?.isEmpty ?? true) ? nil : aa
        }
    }

    /// Add generated tests, or replace all existing tests with them.
    func setGeneratedTests(_ tests: [ACLTest], ssh: [SSHTest] = [], replacingExisting: Bool) {
        mutate { tree in
            let existing = replacingExisting ? [] : (tree["tests"]?.elements ?? [])
            let all = existing + testElements(tests)
            tree["tests"] = all.isEmpty ? nil : .array(all)
            if !ssh.isEmpty || replacingExisting {
                let existingSSH = replacingExisting ? [] : (tree["sshTests"]?.elements ?? [])
                let allSSH = existingSSH + sshTestElements(ssh)
                tree["sshTests"] = allSSH.isEmpty ? nil : .array(allSSH)
            }
        }
    }

    func deleteSSHTest(index: Int) {
        deleteRule(section: "sshTests", index: index)
    }

    func deleteSSHRule(index: Int) {
        mutate { tree in
            guard var rules = tree["ssh"]?.elements, rules.indices.contains(index) else { return }
            rules.remove(at: index)
            tree["ssh"]?.elements = rules
        }
    }

    // MARK: - Entity editing

    enum EntityKind: String, CaseIterable, Identifiable {
        case group = "Group"
        case tag = "Tag"
        case host = "Host"
        case ipSet = "IP set"
        var id: String { rawValue }
    }

    func addEntity(kind: EntityKind, name: String, address: String) {
        let fullName: String
        switch kind {
        case .group: fullName = name.hasPrefix("group:") ? name : "group:\(name)"
        case .tag: fullName = name.hasPrefix("tag:") ? name : "tag:\(name)"
        case .ipSet: fullName = name.hasPrefix("ipset:") ? name : "ipset:\(name)"
        case .host: fullName = name
        }
        mutate { tree in
            switch kind {
            case .group:
                appendMember(&tree, section: "groups", key: fullName, value: .array([]))
            case .tag:
                appendMember(&tree, section: "tagOwners", key: fullName, value: .array([]))
            case .host:
                appendMember(&tree, section: "hosts", key: fullName, value: .string(address))
            case .ipSet:
                appendMember(&tree, section: "ipsets", key: fullName,
                             value: .array([JSON.Element(comments: [], value: .string(address))]))
            }
        }
    }

    /// Replace the string list of a groups/tagOwners entry (members / owners).
    func setEntityList(section: String, key: String, values: [String]) {
        mutate { tree in
            guard var members = tree[section]?.members,
                  let i = members.firstIndex(where: { $0.key == key }) else { return }
            members[i].value = stringArrayJSON(values)
            tree[section] = .object(members)
        }
    }

    /// Change a host's IP address or CIDR.
    func setHostAddress(name: String, address: String) {
        mutate { tree in
            guard var members = tree["hosts"]?.members,
                  let i = members.firstIndex(where: { $0.key == name }) else { return }
            members[i].value = .string(address)
            tree["hosts"] = .object(members)
        }
    }

    /// Rename an entity everywhere: section keys, tag owners, src/dst specs, tests.
    func renameEntity(from oldName: String, to newName: String) {
        guard oldName != newName, !newName.isEmpty else { return }
        mutate { tree in
            rewriteNames(&tree, from: oldName, to: newName)
        }
    }

    /// Delete an entity and clean up every rule/test that references it.
    func deleteEntity(_ name: String) {
        mutate { tree in
            for section in ["groups", "tagOwners", "hosts", "ipsets"] {
                if var members = tree[section]?.members {
                    members.removeAll { $0.key == name }
                    tree[section]?.elements = nil
                    tree[section] = .object(members)
                }
            }
            // Drop the entity from tagOwners owner lists and group members.
            for section in ["groups", "tagOwners"] {
                if var members = tree[section]?.members {
                    for i in members.indices {
                        var values = members[i].value.stringArray
                        values.removeAll { $0 == name }
                        members[i].value = stringArrayJSON(values)
                    }
                    tree[section] = .object(members)
                }
            }
            // Clean acls.
            if var acls = tree["acls"]?.elements {
                for i in acls.indices {
                    var rule = acls[i].value
                    var src = rule["src"]?.stringArray ?? []
                    src.removeAll { $0 == name || $0 == "host:\(name)" }
                    var dst = rule["dst"]?.stringArray ?? []
                    dst.removeAll {
                        let t = DestSpec($0).target
                        return t == name || t == "host:\(name)"
                    }
                    rule["src"] = stringArrayJSON(src)
                    rule["dst"] = stringArrayJSON(dst)
                    acls[i].value = rule
                }
                acls.removeAll {
                    ($0.value["src"]?.stringArray.isEmpty ?? true)
                        || ($0.value["dst"]?.stringArray.isEmpty ?? true)
                }
                tree["acls"] = .array(acls)
            }
            // Clean grants (dst entries are bare targets; via lists too).
            if var grants = tree["grants"]?.elements {
                for i in grants.indices {
                    var grant = grants[i].value
                    for key in ["src", "dst", "via"] where grant[key] != nil {
                        var values = grant[key]?.stringArray ?? []
                        values.removeAll { $0 == name || $0 == "host:\(name)" }
                        if key == "via" && values.isEmpty {
                            grant[key] = nil
                        } else {
                            grant[key] = stringArrayJSON(values)
                        }
                    }
                    grants[i].value = grant
                }
                grants.removeAll {
                    ($0.value["src"]?.stringArray.isEmpty ?? true)
                        || ($0.value["dst"]?.stringArray.isEmpty ?? true)
                }
                tree["grants"] = .array(grants)
            }
            // Clean ssh rules.
            if var ssh = tree["ssh"]?.elements {
                for i in ssh.indices {
                    var rule = ssh[i].value
                    for key in ["src", "dst"] where rule[key] != nil {
                        var values = rule[key]?.stringArray ?? []
                        values.removeAll { $0 == name || $0 == "host:\(name)" }
                        rule[key] = stringArrayJSON(values)
                    }
                    ssh[i].value = rule
                }
                ssh.removeAll {
                    ($0.value["src"]?.stringArray.isEmpty ?? true)
                        || ($0.value["dst"]?.stringArray.isEmpty ?? true)
                }
                tree["ssh"] = .array(ssh)
            }
            // Clean tests.
            if var tests = tree["tests"]?.elements {
                for i in tests.indices {
                    var test = tests[i].value
                    for key in ["accept", "deny"] {
                        if test[key] != nil {
                            var entries = test[key]?.stringArray ?? []
                            entries.removeAll { DestSpec($0).target == name }
                            if entries.isEmpty {
                                test[key] = nil
                            } else {
                                test[key] = stringArrayJSON(entries)
                            }
                        }
                    }
                    tests[i].value = test
                }
                tests.removeAll { $0.value["src"]?.stringValue == name }
                tree["tests"] = .array(tests)
            }
        }
    }

    // MARK: - Tests

    func addTest(src: String, accept: [String], deny: [String]) {
        mutate { tree in
            var members: [JSON.Member] = [
                .init(comments: [], key: "src", value: .string(src)),
            ]
            if !accept.isEmpty {
                members.append(.init(comments: [], key: "accept", value: stringArrayJSON(accept)))
            }
            if !deny.isEmpty {
                members.append(.init(comments: [], key: "deny", value: stringArrayJSON(deny)))
            }
            var tests = tree["tests"]?.elements ?? []
            tests.append(JSON.Element(comments: [], value: .object(members)))
            if tree["tests"] == nil {
                tree["tests"] = .array(tests)
            } else {
                tree["tests"]?.elements = tests
            }
        }
    }

    func deleteTest(index: Int) {
        mutate { tree in
            guard var tests = tree["tests"]?.elements, tests.indices.contains(index) else { return }
            tests.remove(at: index)
            tree["tests"]?.elements = tests
        }
    }
}

// MARK: - Tree helpers

func stringArrayJSON(_ strings: [String]) -> JSON {
    .array(strings.map { JSON.Element(comments: [], value: .string($0)) })
}

private func appendMember(_ tree: inout JSON, section: String, key: String, value: JSON) {
    if var members = tree[section]?.members {
        guard !members.contains(where: { $0.key == key }) else { return }
        members.append(JSON.Member(comments: [], key: key, value: value))
        tree[section] = .object(members)
    } else {
        tree[section] = .object([JSON.Member(comments: [], key: key, value: value)])
    }
}

/// Recursively rewrite entity names in keys and string values.
/// Handles bare names ("group:eng") and dst specs with ports ("tag:server:22").
private func rewriteNames(_ tree: inout JSON, from oldName: String, to newName: String) {
    func rewriteString(_ s: String) -> String {
        if s == oldName { return newName }
        if s == "host:\(oldName)" { return "host:\(newName)" }
        let d = DestSpec(s)
        if d.target == oldName && s != d.target {
            return DestSpec(target: newName, ports: d.ports).spec
        }
        if d.target == "host:\(oldName)" && s != d.target {
            return DestSpec(target: "host:\(newName)", ports: d.ports).spec
        }
        return s
    }
    func walk(_ node: inout JSON) {
        switch node {
        case .string(let s):
            node = .string(rewriteString(s))
        case .array(var elements):
            for i in elements.indices { walk(&elements[i].value) }
            node = .array(elements)
        case .object(var members):
            for i in members.indices {
                if members[i].key == oldName { members[i].key = newName }
                walk(&members[i].value)
            }
            node = .object(members)
        default:
            break
        }
    }
    walk(&tree)
}
