import SwiftUI
import AppKit

/// Talk to the workspace's control server (self-hosted Headscale or the
/// official Tailscale API): pull/push the policy, list devices.
/// Opt-in — nothing touches the network until a server is configured here.
struct HeadscaleScreen: View {
    @EnvironmentObject var store: PolicyStore
    @State private var apiKey = ""
    @State private var status: (ok: Bool, text: String)?
    @State private var busy = false
    @State private var confirmingPull = false
    @State private var review: PushCandidate?
    @State private var history = PushHistory.load()
    @State private var openingRecord: PushRecord?
    @State private var comparing: DiffPresentation?
    @State private var editingTags: HeadscaleNode?
    // Auth key form
    @State private var keyTags: [String] = []
    @State private var keyUser = ""
    @State private var users: [ServerUser] = []
    @State private var keyReusable = false
    @State private var keyEphemeral = false
    @State private var keyPreauthorized = true
    @State private var keyExpiry: TimeInterval = 86_400
    @State private var createdKey: String?
    @State private var keyError: String?

    private var serverURL: Binding<String> {
        Binding(get: { store.currentWorkspace.serverURL }, set: { store.setServerURL($0) })
    }

    private var kind: ServerKind { store.currentWorkspace.kind }

    private var kindBinding: Binding<ServerKind> {
        Binding(get: { kind }, set: { if $0 != kind { store.setServerKind($0); status = nil } })
    }

    private var tailnet: Binding<String> {
        Binding(get: { store.currentWorkspace.tailnet ?? "-" }, set: { store.setTailnet($0) })
    }

    private var serverName: String { kind == .tailscale ? "Tailscale" : "Headscale" }

    private var client: PolicyServer? {
        let ws = store.currentWorkspace
        return makeServer(kind: kind, serverURL: ws.serverURL, tailnet: ws.tailnet ?? "-", credential: apiKey)
    }

    /// Push history for this workspace's server only.
    private var serverHistory: [PushRecord] {
        history.filter { $0.server == store.serverDisplayName }
    }

    private func loadKey() {
        apiKey = HeadscaleKeychain.load(account: store.currentWorkspaceID.uuidString) ?? ""
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Server")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundStyle(Theme.textPrimary)
                    Text("Pull and push the policy for workspace \u{201C}\(store.currentWorkspace.name)\u{201D} on its Headscale server or Tailscale tailnet, and see its devices")
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.textSecondary)
                }

                connectionPanel
                policyPanel
                if client != nil { authKeyPanel }
                if !serverHistory.isEmpty { historyPanel }
                if !store.headscaleNodes.isEmpty { nodesPanel }
            }
            .padding(16)
            .frame(maxWidth: 820, alignment: .topLeading)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .background(Theme.background)
        .onAppear(perform: loadKey)
        .onChange(of: store.currentWorkspaceID) {
            loadKey()
            status = nil
            createdKey = nil
            users = []
            keyUser = ""
        }
        .confirmationDialog("Replace the editor contents with the policy from \(serverName)?",
                            isPresented: $confirmingPull) {
            Button("Pull and replace", role: .destructive) { pull() }
        } message: {
            Text("Unsaved edits in the editor will be lost. Export first if you want to keep them.")
        }
        .sheet(item: $review) { candidate in
            if let client {
                PushReviewSheet(client: client, candidate: candidate) {
                    history = PushHistory.load()
                    store.markSynced(candidate.text)
                    if candidate.isRestore { store.loadPolicy(candidate.text, reason: "restored") }
                    store.snapshot(reason: candidate.isRestore ? "restored on server" : "pushed")
                    status = (true, candidate.isRestore
                              ? "Restored — the server and editor now have the earlier policy."
                              : "Pushed — \(serverName) accepted and applied the policy.")
                }
                .environmentObject(store)
            }
        }
        .sheet(item: $comparing) { DiffSheet(diff: $0) }
        .sheet(item: $editingTags) { DeviceTagsSheet(node: $0) }
        .confirmationDialog("Replace the editor contents with this policy?",
                            isPresented: Binding(get: { openingRecord != nil },
                                                 set: { if !$0 { openingRecord = nil } })) {
            if let record = openingRecord {
                Button("Open the version before this push") { store.loadPolicy(record.before, reason: "opened from push history") }
                Button("Open the version that was pushed") { store.loadPolicy(record.pushed, reason: "opened from push history") }
            }
        } message: {
            Text("Unsaved edits in the editor will be lost.")
        }
    }

    // MARK: - Panels

    private var connectionPanel: some View {
        panel {
            Text("Connection")
                .font(.system(size: 13, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            PillTabs(tabs: [(ServerKind.headscale, "Headscale", "server.rack"),
                            (ServerKind.tailscale, "Tailscale", "cloud")],
                     selection: kindBinding)
            if kind == .headscale {
                field("Server URL", hint: "e.g. https://headscale.example.com") {
                    TextField("https://headscale.example.com", text: serverURL)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 12, design: .monospaced))
                }
                field("API key", hint: "Create one on the server: headscale apikeys create — stored in your Keychain") {
                    SecureField("API key", text: $apiKey)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 12, design: .monospaced))
                }
            } else {
                field("Tailnet", hint: "\"-\" means the tailnet the key belongs to. Otherwise the tailnet ID from the admin console's General settings.") {
                    TextField("-", text: tailnet)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 12, design: .monospaced))
                }
                field("API access token or OAuth client secret",
                      hint: "An OAuth client (tskey-client-…) never expires — give it the policy_file and devices scopes. Access tokens (tskey-api-…) expire after at most 90 days. Create either under Settings ▸ Keys or Trust credentials in the admin console. Stored in your Keychain.") {
                    SecureField("tskey-client-… or tskey-api-…", text: $apiKey)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 12, design: .monospaced))
                }
            }
            HStack(spacing: 10) {
                Button("Save & test") {
                    HeadscaleKeychain.save(apiKey, account: store.currentWorkspaceID.uuidString)
                    refreshNodes(announce: true)
                }
                .disabled(client == nil || busy)
                if busy { ProgressView().controlSize(.small) }
                if let status {
                    Label(status.text, systemImage: status.ok ? "checkmark.circle.fill" : "xmark.octagon.fill")
                        .font(.system(size: 11.5))
                        .foregroundStyle(status.ok ? Theme.green : Theme.red)
                        .lineLimit(3)
                }
            }
        }
    }

    private var policyPanel: some View {
        panel {
            Text("Policy")
                .font(.system(size: 13, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            Text(kind == .headscale
                 ? "Pushing requires the server to store its policy in the database (policy.mode: database in config.yaml). In file mode the server's policy file is the source of truth and push is refused."
                 : "Before each push, Tailscale checks the policy and runs its tests without saving, and the push is refused if the policy changed on Tailscale after the review read it.")
                .font(.system(size: 10.5))
                .foregroundStyle(Theme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) {
                ToolbarButton(label: "Pull from \(serverName)", icon: "arrow.down.circle") {
                    confirmingPull = true
                }
                .disabled(client == nil || busy)
                ToolbarButton(label: "Review & push…", icon: "arrow.up.circle") {
                    review = PushCandidate(text: store.text, isRestore: false)
                }
                .disabled(client == nil || busy || !store.isValid)
                ToolbarButton(label: "Compare with server…", icon: "doc.on.doc") { compareWithServer() }
                    .disabled(client == nil || busy)
            }
        }
    }

    private var authKeyPanel: some View {
        panel {
            Text("Auth keys")
                .font(.system(size: 13, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            Text(kind == .tailscale
                 ? "Create a key for joining new devices. Devices that join with tags get those tags from the start, so the policy applies right away. Keys made with an OAuth client must have tags."
                 : "Create a pre-auth key for joining new devices. Give it tags for tagged devices, or a user for that user's devices.")
                .font(.system(size: 10.5))
                .foregroundStyle(Theme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            StringListEditor(title: "Tags", addPrompt: "e.g. tag:server", suggestions: store.model.tagOrder, items: $keyTags)
            if kind == .headscale {
                HStack(spacing: 8) {
                    Picker("User", selection: $keyUser) {
                        Text("No user (tags only)").tag("")
                        ForEach(users) { Text($0.name).tag($0.id) }
                    }
                    .frame(width: 280)
                    Button("Load users") { loadUsers() }
                        .font(.system(size: 11))
                }
            }
            HStack(spacing: 16) {
                Toggle("Reusable", isOn: $keyReusable)
                Toggle("Ephemeral", isOn: $keyEphemeral)
                    .help("Devices are removed automatically after going offline")
                if kind == .tailscale {
                    Toggle("Pre-approved", isOn: $keyPreauthorized)
                        .help("Devices skip device approval")
                }
                Picker("Expires in", selection: $keyExpiry) {
                    Text("1 hour").tag(3_600.0)
                    Text("1 day").tag(86_400.0)
                    Text("7 days").tag(604_800.0)
                    Text("30 days").tag(2_592_000.0)
                    Text("90 days").tag(7_776_000.0)
                }
                .frame(width: 180)
            }
            .font(.system(size: 11.5))
            HStack(spacing: 10) {
                ToolbarButton(label: "Create key", icon: "key") { createKey() }
                    .disabled(busy || (keyTags.isEmpty && (kind == .tailscale ? false : keyUser.isEmpty))
                              || !keyTags.allSatisfy { $0.hasPrefix("tag:") })
                if let keyError {
                    Label(keyError, systemImage: "xmark.octagon.fill")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if let createdKey {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Copy it now — the server won't show this key again, and the app doesn't save it.")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(Theme.orange)
                    HStack(spacing: 8) {
                        Text(verbatim: createdKey)
                            .font(.system(size: 11.5, design: .monospaced))
                            .foregroundStyle(Theme.textPrimary)
                            .textSelection(.enabled)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Button("Copy") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(createdKey, forType: .string)
                        }
                        Button("Done") { self.createdKey = nil }
                    }
                    .font(.system(size: 11))
                }
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 8).fill(Theme.orange.opacity(0.10)))
            }
        }
    }

    private func loadUsers() {
        guard let client else { return }
        Task {
            do {
                users = try await client.listUsers()
                keyError = nil
            } catch {
                keyError = "Couldn't load users: \(error.localizedDescription)"
            }
        }
    }

    private func createKey() {
        guard let client else { return }
        let request = AuthKeyRequest(tags: keyTags, reusable: keyReusable, ephemeral: keyEphemeral,
                                     preauthorized: keyPreauthorized, expiry: keyExpiry,
                                     user: keyUser.isEmpty ? nil : keyUser)
        busy = true
        keyError = nil
        Task {
            do {
                createdKey = try await client.createAuthKey(request)
            } catch {
                keyError = "The server refused: \(error.localizedDescription)"
            }
            busy = false
        }
    }

    private var historyPanel: some View {
        panel {
            Text("Push history")
                .font(.system(size: 13, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            Text("Before every push the server's previous policy is saved on this Mac. Restoring goes through the same review.")
                .font(.system(size: 10.5))
                .foregroundStyle(Theme.textSecondary)
            ForEach(serverHistory) { record in
                HStack(spacing: 8) {
                    Image(systemName: "clock.arrow.circlepath")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.textSecondary)
                    Text(record.date.formatted(date: .abbreviated, time: .shortened))
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(Theme.textPrimary)
                    Text(verbatim: record.server)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Theme.textSecondary)
                    Spacer()
                    Button("Compare…") {
                        comparing = DiffPresentation(title: "Push on \(record.date.formatted(date: .abbreviated, time: .shortened))",
                                                     oldLabel: "before the push", newLabel: "pushed",
                                                     old: record.before, new: record.pushed)
                    }
                    .font(.system(size: 11))
                    Button("Open in editor…") { openingRecord = record }
                        .font(.system(size: 11))
                    Button("Restore on server…") {
                        review = PushCandidate(text: record.before, isRestore: true)
                    }
                    .font(.system(size: 11))
                    .disabled(client == nil || record.before.isEmpty)
                    .help("Put the policy from before this push back on the server")
                }
            }
        }
    }

    private var nodesPanel: some View {
        panel {
            HStack {
                Text("Nodes (\(store.headscaleNodes.count))")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(Theme.textPrimary)
                Spacer()
                Button {
                    refreshNodes(announce: false)
                } label: {
                    Image(systemName: "arrow.clockwise")
                        .font(.system(size: 11))
                }
                .buttonStyle(.plain)
                .foregroundStyle(Theme.textSecondary)
                .disabled(busy)
                .help("Refresh")
            }
            ForEach(store.headscaleNodes) { node in
                HStack(spacing: 8) {
                    Circle()
                        .fill(node.online == true ? Theme.green : Theme.textSecondary.opacity(0.4))
                        .frame(width: 7, height: 7)
                        .help(node.online == true ? "Online" : "Offline")
                    Text(node.displayName)
                        .font(.system(size: 12, weight: .semibold, design: .monospaced))
                        .foregroundStyle(Theme.textPrimary)
                    if let user = node.user?.name, !user.isEmpty {
                        Chip(text: user, color: Theme.green, icon: "person")
                    }
                    ForEach(node.allTags, id: \.self) { EntityChip(name: $0) }
                    Spacer()
                    Text(node.statusText)
                        .font(.system(size: 10.5))
                        .foregroundStyle(node.online == true ? Theme.green : Theme.textSecondary)
                    Text(verbatim: (node.ipAddresses ?? []).joined(separator: "  "))
                        .font(.system(size: 10.5, design: .monospaced))
                        .foregroundStyle(Theme.textSecondary)
                        .textSelection(.enabled)
                    Button("Tags…") { editingTags = node }
                        .font(.system(size: 11))
                        .disabled(client == nil)
                }
                .padding(.vertical, 2)
            }
        }
    }

    private func panel<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 12, content: content)
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 9).fill(Theme.panel))
            .overlay(RoundedRectangle(cornerRadius: 9).stroke(Theme.panelBorder, lineWidth: 1))
    }

    private func field<Content: View>(_ title: String, hint: String,
                                      @ViewBuilder _ control: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Theme.textSecondary)
            control()
            Text(hint)
                .font(.system(size: 10.5))
                .foregroundStyle(Theme.textSecondary.opacity(0.8))
        }
    }

    // MARK: - Actions

    private func run(_ work: @escaping (PolicyServer) async throws -> String) {
        guard let client else { return }
        busy = true
        Task {
            do {
                status = (true, try await work(client))
            } catch {
                status = (false, error.localizedDescription)
            }
            busy = false
        }
    }

    private func refreshNodes(announce: Bool) {
        run { client in
            let nodes = try await client.listNodes()
            store.headscaleNodes = nodes
            return announce ? "Connected — \(nodes.count) node\(nodes.count == 1 ? "" : "s")" : "Nodes refreshed"
        }
    }

    private func compareWithServer() {
        run { client in
            let server = try await client.getPolicy()
            comparing = DiffPresentation(title: "Editor vs server", oldLabel: "on the server",
                                         newLabel: "in the editor", old: server, new: store.text)
            return server == store.text ? "The editor matches the server." : "Showing differences from the server."
        }
    }

    private func pull() {
        run { client in
            let policy = try await client.getPolicy()
            guard !policy.isEmpty else { return "Server returned an empty policy — editor left unchanged." }
            store.loadPolicy(policy, reason: "pulled")
            store.markSynced(policy)
            store.headscaleNodes = try await client.listNodes()
            return "Pulled policy and \(store.headscaleNodes.count) devices."
        }
    }
}

struct PushCandidate: Identifiable {
    let id = UUID()
    var text: String
    var isRestore: Bool
}

// MARK: - Push review

/// Shows what a push changes for your real devices before it goes live, and
/// saves the server's current policy to history before pushing.
struct PushReviewSheet: View {
    /// Kept in state so the same client (and its Tailscale ETag) is used from
    /// review to push, even if SwiftUI rebuilds this view.
    @State private var client: PolicyServer
    var candidate: PushCandidate
    var onPushed: () -> Void

    init(client: PolicyServer, candidate: PushCandidate, onPushed: @escaping () -> Void) {
        _client = State(initialValue: client)
        self.candidate = candidate
        self.onPushed = onPushed
    }

    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var serverText: String?
    @State private var changes: [AccessChange] = []
    @State private var deviceCount = 0
    @State private var previewNote: String?
    @State private var candidateErrors: [LintIssue] = []
    /// Tailscale's own verdict: nil not checked, "" passed, otherwise the failure.
    @State private var serverVerdict: String?
    @State private var blocker: String?
    @State private var loading = true
    @State private var pushing = false
    /// The server text as of our last pull/push, when the server has changed since.
    @State private var conflictBase: String?
    @State private var noSyncRecord = false
    @State private var comparing: DiffPresentation?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(candidate.isRestore ? "Review restore on \(host)" : "Review push to \(host)")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)

            if loading {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Comparing with the server's current policy…")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.textSecondary)
                }
            } else if let blocker {
                Label(blocker, systemImage: "xmark.octagon.fill")
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.red)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                if let conflictBase, let serverText {
                    VStack(alignment: .leading, spacing: 6) {
                        Label("The server's policy changed since your last pull or push. Pushing overwrites those changes — cancel and pull first to keep them.",
                              systemImage: "exclamationmark.triangle.fill")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(Theme.orange)
                            .fixedSize(horizontal: false, vertical: true)
                        Button("Show what changed on the server…") {
                            comparing = DiffPresentation(title: "Changes made on the server",
                                                         oldLabel: "at your last pull/push", newLabel: "on the server now",
                                                         old: conflictBase, new: serverText)
                        }
                        .font(.system(size: 11.5))
                    }
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Theme.orange.opacity(0.10)))
                } else if noSyncRecord {
                    Text("No record of a pull in this workspace, so changes made on the server by others can't be detected. Pull once to enable that check.")
                        .font(.system(size: 10.5))
                        .foregroundStyle(Theme.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                summary
                if !changes.isEmpty { changeList }
                if let serverText, serverText != candidate.text {
                    Button("Show text changes…") {
                        comparing = DiffPresentation(title: "Text changes", oldLabel: "on the server",
                                                     newLabel: candidate.isRestore ? "restored version" : "to be pushed",
                                                     old: serverText, new: candidate.text)
                    }
                    .font(.system(size: 11.5))
                }
                if let serverVerdict {
                    Label(serverVerdict.isEmpty ? "Tailscale's own check passed (policy and its tests)."
                          : "Tailscale's check failed — it will refuse this push: \(serverVerdict)",
                          systemImage: serverVerdict.isEmpty ? "checkmark.seal" : "xmark.octagon.fill")
                        .font(.system(size: 11.5))
                        .foregroundStyle(serverVerdict.isEmpty ? Theme.green : Theme.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if !candidateErrors.isEmpty {
                    Label("The Problems check reports \(candidateErrors.count) error\(candidateErrors.count == 1 ? "" : "s") in this policy — the server may reject it.",
                          systemImage: "exclamationmark.triangle.fill")
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text("Compares TCP/UDP access between your current devices on every port named in either policy, and SSH logins for root, every account named in either policy, and other non-root users. ICMP isn't compared. The server's current policy is saved to Push history first.")
                    .font(.system(size: 10.5))
                    .foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                if pushing { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(conflictBase != nil ? "Overwrite and push"
                       : candidate.isRestore ? "Restore on server" : "Push to server") { push() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(loading || pushing || blocker != nil)
            }
        }
        .padding(20)
        .frame(width: 560)
        .background(Theme.background)
        .task { await prepare() }
        .sheet(item: $comparing) { DiffSheet(diff: $0) }
    }

    private var host: String { client.displayHost }

    @ViewBuilder
    private var summary: some View {
        if serverText == candidate.text {
            Text("The policy is identical to what's already on the server.")
                .font(.system(size: 12))
                .foregroundStyle(Theme.textSecondary)
        } else if let previewNote {
            Label(previewNote, systemImage: "info.circle")
                .font(.system(size: 12))
                .foregroundStyle(Theme.orange)
                .fixedSize(horizontal: false, vertical: true)
        } else if changes.isEmpty {
            Label("No network access changes between your \(deviceCount) devices.",
                  systemImage: "checkmark.shield")
                .font(.system(size: 12.5, weight: .semibold))
                .foregroundStyle(Theme.green)
        } else {
            Text(changes.count == 1 ? "1 device pair changes access:" : "\(changes.count) device pairs change access:")
                .font(.system(size: 12.5, weight: .semibold))
                .foregroundStyle(Theme.textPrimary)
        }
    }

    private var changeList: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(changes) { change in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(verbatim: "\(change.src) → \(change.dst)")
                            .font(.system(size: 11.5, weight: .semibold, design: .monospaced))
                            .foregroundStyle(Theme.textPrimary)
                        if !change.gained.isEmpty {
                            Text(verbatim: "+ gains \(change.gained.joined(separator: ", "))")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(Theme.green)
                        }
                        if !change.lost.isEmpty {
                            Text(verbatim: "− loses \(change.lost.joined(separator: ", "))")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(Theme.red)
                        }
                        if !change.sshGained.isEmpty {
                            Text(verbatim: "+ gains SSH as \(change.sshGained.joined(separator: ", "))")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(Theme.green)
                        }
                        if !change.sshLost.isEmpty {
                            Text(verbatim: "− loses SSH as \(change.sshLost.joined(separator: ", "))")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(Theme.red)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
                    .background(RoundedRectangle(cornerRadius: 6).fill(Theme.panel))
                }
            }
        }
        .frame(maxHeight: 320)
    }

    private func prepare() async {
        guard let newTree = try? HuJSONParser.parse(candidate.text) else {
            blocker = "This policy doesn't parse, so it can't be pushed."
            loading = false
            return
        }
        let newModel = PolicyModel(tree: newTree)
        candidateErrors = lintPolicy(newModel).filter { $0.severity == .error }
        do {
            let current = try await client.getPolicy()
            serverText = current
            if let report = try? await client.validate(candidate.text) {
                serverVerdict = report.passed ? "" : report.summary
            }
            if let last = store.currentWorkspace.lastSyncedPolicy {
                if last != current { conflictBase = last }
            } else {
                noSyncRecord = !current.isEmpty
            }
            var nodes = store.headscaleNodes
            if nodes.isEmpty {
                nodes = try await client.listNodes()
                store.headscaleNodes = nodes
            }
            deviceCount = nodes.count
            if current.isEmpty {
                previewNote = "The server has no policy yet, so there's nothing to compare against."
            } else if let oldTree = try? HuJSONParser.parse(current) {
                changes = accessChanges(from: PolicyModel(tree: oldTree), to: newModel, nodes: nodes)
            } else {
                previewNote = "The server's current policy couldn't be parsed here, so no access comparison is available."
            }
        } catch {
            blocker = "Couldn't read the server's current policy, so there would be no rollback copy: \(error.localizedDescription)"
        }
        loading = false
    }

    private func push() {
        let record = PushRecord(date: Date(), server: host,
                                before: serverText ?? "", pushed: candidate.text)
        pushing = true
        Task {
            do {
                try PushHistory.append(record)
            } catch {
                blocker = "Couldn't save the rollback copy, so nothing was pushed: \(error.localizedDescription)"
                pushing = false
                return
            }
            do {
                try await client.setPolicy(candidate.text)
                pushing = false
                onPushed()
                dismiss()
            } catch {
                PushHistory.remove(id: record.id)
                blocker = "The server refused the policy: \(error.localizedDescription)"
                pushing = false
            }
        }
    }
}
