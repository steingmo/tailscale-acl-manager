import SwiftUI
import AppKit
import UniformTypeIdentifiers

/// Talk to the workspace's control server (self-hosted Headscale or the
/// official Tailscale API): pull/push the policy, list devices.
/// Opt-in — nothing touches the network until a server is configured here.
struct ServerScreen: View {
    @EnvironmentObject var store: PolicyStore
    @State private var apiKey = ""
    @State private var status: (ok: Bool, text: String)?
    @State private var busy = false
    @State private var confirmingPull = false
    @State private var review: PushCandidate?
    @State private var settingUpGit = false
    @State private var confirmingInsecure = false
    @State private var credential: CredentialInfo?
    @State private var activity: [ActivityEntry] = []
    @State private var history = PushHistory.load()
    @State private var openingRecord: PushRecord?
    @State private var comparing: DiffPresentation?

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

    /// Guarded like `PolicyStore.serverClient()`: changes ask for Touch ID
    /// and are logged. (Uses the key in the field, which may not be saved yet.)
    private var client: PolicyServer? {
        let ws = store.currentWorkspace
        return makeServer(kind: kind, serverURL: ws.serverURL, tailnet: ws.tailnet ?? "-", credential: apiKey)
            .map { GuardedServer($0, workspace: ws.name, requireAuth: SecuritySettings.requireAuth) }
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
                if kind == .tailscale, let client { PolicyChangesPanel(client: client) }
                if client != nil { UsersPanel() }
                if let client { AuthKeysPanel(client: client) }
                if !serverHistory.isEmpty { historyPanel }
                if !activity.isEmpty { activityPanel }
                if !store.headscaleNodes.isEmpty { DevicesPanel(client: client) }
            }
            .padding(16)
            .frame(maxWidth: 820, alignment: .topLeading)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .background(Theme.background)
        .onAppear(perform: loadKey)
        .onAppear { activity = ActivityLog.recent(server: store.serverDisplayName) }
        .onChange(of: store.headscaleNodes.map(\.id)) { activity = ActivityLog.recent(server: store.serverDisplayName) }
        .onReceive(NotificationCenter.default.publisher(for: ActivityLog.changed)) { _ in
            activity = ActivityLog.recent(server: store.serverDisplayName)
        }
        .onChange(of: store.currentWorkspaceID) {
            loadKey()
            status = nil
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
        .sheet(isPresented: $settingUpGit) { GitOpsSetupSheet() }
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
                if isUnencryptedRemote(store.currentWorkspace.serverURL) {
                    Label("Unencrypted: with http://, your API key and policy cross the network in clear text, readable by anyone on the path. Use https:// (e.g. a reverse proxy with a certificate).",
                          systemImage: "lock.open.fill")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(Theme.red)
                        .fixedSize(horizontal: false, vertical: true)
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
                    if kind == .headscale, isUnencryptedRemote(store.currentWorkspace.serverURL) {
                        confirmingInsecure = true
                    } else {
                        saveAndTest()
                    }
                }
                .disabled(client == nil || busy)
                .confirmationDialog("Send the API key over an unencrypted connection?", isPresented: $confirmingInsecure) {
                    Button("Connect anyway", role: .destructive) { saveAndTest() }
                } message: {
                    Text("\(store.currentWorkspace.serverURL) uses http://. Anyone on the network path can read the API key and take over the server's policy. Use https:// if you can.")
                }
                if busy { ProgressView().controlSize(.small) }
                if let status {
                    Label(status.text, systemImage: status.ok ? "checkmark.circle.fill" : "xmark.octagon.fill")
                        .font(.system(size: 11.5))
                        .foregroundStyle(status.ok ? Theme.green : Theme.red)
                        .lineLimit(3)
                }
            }
            if let credential { credentialLine(credential) }
        }
        .task(id: "\(store.currentWorkspaceID)\(kind)") { await loadCredentialInfo() }
    }

    private func saveAndTest() {
        HeadscaleKeychain.save(apiKey, account: store.currentWorkspaceID.uuidString)
        refreshNodes(announce: true)
        Task { await loadCredentialInfo() }
    }

    private func loadCredentialInfo() async {
        credential = nil
        guard let client else { return }
        credential = try? await client.credentialInfo()
    }

    /// What the stored credential is, what it may do, and when it expires.
    private func credentialLine(_ c: CredentialInfo) -> some View {
        let days = c.expires.map { Int(($0.timeIntervalSinceNow / 86_400).rounded(.down)) }
        return VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Image(systemName: "key.fill").font(.system(size: 10.5)).foregroundStyle(Theme.textSecondary)
                Text(verbatim: c.kind).font(.system(size: 11, weight: .semibold)).foregroundStyle(Theme.textPrimary)
                if let days {
                    Text(verbatim: days < 0 ? "expired" : "expires in \(days) day\(days == 1 ? "" : "s")")
                        .font(.system(size: 11, weight: days <= 14 ? .semibold : .regular))
                        .foregroundStyle(days < 0 ? Theme.red : days <= 14 ? Theme.orange : Theme.textSecondary)
                } else if c.kind == "OAuth client" {
                    Text("doesn't expire").font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                }
            }
            if c.isFullAccess {
                Text(kind == .tailscale
                     ? "Full access to the tailnet, with your own admin rights. An OAuth client limited to the scopes you use is safer and doesn't expire."
                     : "Full access to the server. Create keys with a short expiry and rotate them (headscale apikeys create --expiration 90d).")
                    .font(.system(size: 10.5)).foregroundStyle(Theme.orange).fixedSize(horizontal: false, vertical: true)
            } else if let scopes = c.scopes {
                Text(verbatim: "Scopes: " + scopes.joined(separator: ", "))
                    .font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                if !c.missingFeatures.isEmpty {
                    Text(verbatim: "Not available with these scopes: " + c.missingFeatures.joined(separator: ", ") + ".")
                        .font(.system(size: 10.5)).foregroundStyle(Theme.textSecondary).fixedSize(horizontal: false, vertical: true)
                }
            } else if kind == .headscale {
                Text("Headscale API keys have full access. Prefer keys with a short expiry, and rotate them.")
                    .font(.system(size: 10.5)).foregroundStyle(Theme.textSecondary)
            }
        }
        .textSelection(.enabled)
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
            if store.isGitOps, let file = store.linkedFileURL {
                HStack(spacing: 8) {
                    Image(systemName: "arrow.triangle.branch").foregroundStyle(Theme.green)
                    Text(verbatim: "Managed in Git: \(file.lastPathComponent) — changes go out as pull requests, and Tailscale's GitHub Action applies them on merge.")
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.textPrimary)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button("Stop using Git") { store.setGitOps(file: nil) }
                        .font(.system(size: 11))
                        .help("Go back to pushing directly. The file stays linked.")
                }
            }
            HStack(spacing: 8) {
                ToolbarButton(label: "Pull from \(serverName)", icon: "arrow.down.circle") {
                    confirmingPull = true
                }
                .disabled(client == nil || busy)
                ToolbarButton(label: store.isGitOps ? "Review & open pull request…" : "Review & push…",
                              icon: store.isGitOps ? "arrow.triangle.pull" : "arrow.up.circle") {
                    review = PushCandidate(text: store.text, isRestore: false)
                }
                .disabled(client == nil || busy || !store.isValid)
                if kind == .tailscale, !store.isGitOps {
                    ToolbarButton(label: "Set up Git…", icon: "arrow.triangle.branch") { settingUpGit = true }
                        .disabled(client == nil)
                        .help("Manage this tailnet's policy in a GitHub repository with Tailscale's GitOps action")
                }
                ToolbarButton(label: "Compare with server…", icon: "doc.on.doc") { compareWithServer() }
                    .disabled(client == nil || busy)
            }
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

    /// Every change the app made on this server (activity.jsonl).
    private var activityPanel: some View {
        panel {
            HStack {
                Text("Activity on \(store.serverDisplayName)")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(Theme.textPrimary)
                Spacer()
                Button { activity = ActivityLog.recent(server: store.serverDisplayName) } label: {
                    Image(systemName: "arrow.clockwise").font(.system(size: 11))
                }
                .buttonStyle(.plain)
                .foregroundStyle(Theme.textSecondary)
                .help("Refresh")
                Button("Show log file") { NSWorkspace.shared.activateFileViewerSelecting([ActivityLog.fileURL]) }
                    .font(.system(size: 11))
            }
            ForEach(activity) { e in
                HStack(spacing: 8) {
                    Image(systemName: e.error == nil ? "checkmark.circle" : "xmark.circle")
                        .font(.system(size: 10.5))
                        .foregroundStyle(e.error == nil ? Theme.green : Theme.red)
                    Text(e.date, format: .dateTime.day().month().hour().minute())
                        .font(.system(size: 10.5, design: .monospaced))
                        .foregroundStyle(Theme.textSecondary)
                        .frame(width: 110, alignment: .leading)
                    Text(verbatim: e.action).font(.system(size: 11.5, weight: .semibold)).foregroundStyle(Theme.textPrimary)
                    Text(verbatim: e.detail).font(.system(size: 11)).foregroundStyle(Theme.textSecondary).lineLimit(1)
                    Spacer()
                    Text(verbatim: e.error ?? e.user).font(.system(size: 10.5))
                        .foregroundStyle(e.error == nil ? Theme.textSecondary : Theme.red).lineLimit(1)
                        .help(e.error ?? "")
                }
            }
        }
    }

    private func panel<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        ServerPanel(content: content)
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

