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

    /// The server's users (empty when unknown).
    @Published var serverAccounts: [ServerAccount] = []
    /// Why the users couldn't be loaded, if they couldn't.
    @Published var serverUsersError: Error?
    /// Role autogroups of the server's users; re-evaluates the policy when set.
    @Published var serverUserAutogroups: [String: Set<String>] = [:] {
        didSet { if serverUserAutogroups != oldValue { reparseNow() } }
    }

    private func allLint() -> [LintIssue] {
        lintPolicy(model) + lintNodes(model, nodes: headscaleNodes) + lintUsers(model, logins: serverLogins)
    }

    /// Shows the Getting Started checklist (first launch, Help menu).
    @Published var showGettingStarted = false
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
        serverUsersError = nil
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

    func setServerURL(_ url: String) {
        guard let i = workspaces.firstIndex(where: { $0.id == currentWorkspaceID }) else { return }
        workspaces[i].serverURL = url
        saveWorkspaces()
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
        serverUsersError = nil
        traffic = nil
        saveWorkspaces()
    }

    func setTailnet(_ tailnet: String) {
        guard let i = workspaces.firstIndex(where: { $0.id == currentWorkspaceID }) else { return }
        workspaces[i].tailnet = tailnet
        saveWorkspaces()
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

}
