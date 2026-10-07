import SwiftUI
import AppKit
import UniformTypeIdentifiers

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
    @State private var settingUpGit = false
    @State private var confirmingInsecure = false
    @State private var credential: CredentialInfo?
    @State private var activity: [ActivityEntry] = []
    @State private var history = PushHistory.load()
    @State private var openingRecord: PushRecord?
    @State private var comparing: DiffPresentation?
    @State private var editingTags: HeadscaleNode?
    @State private var policyChanges: [PolicyChange] = []
    @State private var policyChangesError: String?
    @State private var deviceFilter = DeviceFilter.all
    @State private var nodeAction: NodeAction?
    @State private var renaming: HeadscaleNode?
    @State private var newName = ""

    enum DeviceFilter: String, CaseIterable {
        case all = "All"
        case stale = "Not seen in 30 days"
        case expiring = "Key expiring"

        func includes(_ n: HeadscaleNode) -> Bool {
            switch self {
            case .all: return true
            case .stale: return n.isStale()
            case .expiring: return (n.keyDaysLeft() ?? .max) <= 14
            }
        }
    }

    /// A confirmed change to live devices.
    struct NodeAction: Identifiable {
        enum Kind { case expire, delete }
        let id = UUID()
        var kind: Kind
        var nodes: [HeadscaleNode]
    }
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
                if kind == .tailscale, client != nil { changesPanel }
                if client != nil { UsersPanel() }
                if client != nil { authKeyPanel }
                if !serverHistory.isEmpty { historyPanel }
                if !activity.isEmpty { activityPanel }
                if !store.headscaleNodes.isEmpty { nodesPanel }
            }
            .padding(16)
            .frame(maxWidth: 820, alignment: .topLeading)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .background(Theme.background)
        .onAppear(perform: loadKey)
        .onAppear { activity = ActivityLog.recent(server: store.serverDisplayName) }
        .onChange(of: store.headscaleNodes.map(\.id)) { activity = ActivityLog.recent(server: store.serverDisplayName) }
        .onChange(of: busy) { activity = ActivityLog.recent(server: store.serverDisplayName) }
        .task(id: "\(store.currentWorkspaceID)\(kind)") { await loadPolicyChanges() }
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
        .sheet(isPresented: $settingUpGit) { GitOpsSetupSheet() }
        .confirmationDialog(nodeActionTitle, isPresented: Binding(get: { nodeAction != nil },
                                                                  set: { if !$0 { nodeAction = nil } })) {
            if let action = nodeAction {
                Button(action.kind == .delete ? "Delete from \(serverName)" : "Expire key", role: .destructive) {
                    perform(action)
                }
            }
        } message: {
            Text(nodeAction?.kind == .delete
                 ? "The devices are removed from the tailnet right away and must be set up again to rejoin."
                 : "The device is disconnected right away and must log in again to reconnect.")
        }
        .alert("Rename \(renaming?.displayName ?? "device")", isPresented: Binding(get: { renaming != nil },
                                                                                 set: { if !$0 { renaming = nil } })) {
            TextField("New name", text: $newName)
            Button("Rename") { if let node = renaming { rename(node, to: newName) } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Its MagicDNS name changes too.")
        }
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
                            SecureClipboard.copy(createdKey)
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

    /// Who changed the policy on Tailscale recently (configuration audit log).
    private var changesPanel: some View {
        panel {
            HStack {
                Text("Recent policy changes")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(Theme.textPrimary)
                Spacer()
                Button { Task { await loadPolicyChanges() } } label: {
                    Image(systemName: "arrow.clockwise").font(.system(size: 11))
                }
                .buttonStyle(.plain)
                .foregroundStyle(Theme.textSecondary)
                .help("Refresh")
            }
            if let policyChangesError {
                Text(policyChangesError)
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else if policyChanges.isEmpty {
                Text("No policy changes in the last 30 days.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.textSecondary)
            }
            ForEach(policyChanges.prefix(10)) { c in
                HStack(spacing: 8) {
                    Image(systemName: "person.crop.circle").foregroundStyle(Theme.textSecondary)
                    Text(verbatim: c.who)
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(Theme.textPrimary)
                    if !c.origin.isEmpty {
                        Text(verbatim: "via \(c.origin)").font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                    }
                    Spacer()
                    Text(c.date, format: .dateTime.day().month().year().hour().minute())
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.textSecondary)
                }
            }
        }
    }

    private func loadPolicyChanges() async {
        guard kind == .tailscale, let client else { return }
        do {
            policyChanges = try await client.policyChanges(days: 30) ?? []
            policyChangesError = nil
        } catch let error as ServerError where error.status == 403 {
            policyChangesError = "Your credential can't read the audit log. Give the OAuth client the logs:configuration:read scope to see who changed the policy."
        } catch {
            policyChangesError = "Couldn't load the audit log: \(error.localizedDescription)"
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

    private var nodesPanel: some View {
        let shown = store.headscaleNodes.filter(deviceFilter.includes)
        return panel {
            HStack {
                Text("Devices (\(store.headscaleNodes.count))")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(Theme.textPrimary)
                Picker("", selection: $deviceFilter) {
                    ForEach(DeviceFilter.allCases, id: \.self) { f in
                        Text(f == .all ? f.rawValue : "\(f.rawValue) (\(store.headscaleNodes.filter(f.includes).count))").tag(f)
                    }
                }
                .labelsHidden()
                .frame(width: 190)
                Spacer()
                if deviceFilter == .stale, !shown.isEmpty {
                    Button("Delete \(shown.count) stale…") { nodeAction = NodeAction(kind: .delete, nodes: shown) }
                        .font(.system(size: 11))
                        .disabled(client == nil || busy)
                }
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
            if shown.isEmpty {
                Text("No devices match.").font(.system(size: 11.5)).foregroundStyle(Theme.textSecondary)
            }
            ForEach(shown) { node in
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
                    if let os = node.os, !os.isEmpty {
                        Text(verbatim: ([os] + [node.postureAttributes["node:tsVersion"]].compactMap { $0 }).joined(separator: " "))
                            .font(.system(size: 10.5))
                            .foregroundStyle(Theme.textSecondary)
                    }
                    Spacer()
                    if let days = node.keyDaysLeft(), days <= 14 {
                        Text(days < 0 ? "key expired" : days == 0 ? "key expires today" : "key expires in \(days)d")
                            .font(.system(size: 10.5, weight: .semibold))
                            .foregroundStyle(days < 0 ? Theme.red : Theme.orange)
                    }
                    Text(node.statusText)
                        .font(.system(size: 10.5))
                        .foregroundStyle(node.online == true ? Theme.green : node.isStale() ? Theme.orange : Theme.textSecondary)
                    Text(verbatim: (node.ipAddresses ?? []).joined(separator: "  "))
                        .font(.system(size: 10.5, design: .monospaced))
                        .foregroundStyle(Theme.textSecondary)
                        .textSelection(.enabled)
                    Menu {
                        Button("Tags…") { editingTags = node }
                        Button("Rename…") { newName = node.displayName; renaming = node }
                        Divider()
                        Button("Expire Key…") { nodeAction = NodeAction(kind: .expire, nodes: [node]) }
                        Button("Delete…") { nodeAction = NodeAction(kind: .delete, nodes: [node]) }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                    .menuStyle(.borderlessButton)
                    .fixedSize()
                    .disabled(client == nil || busy)
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

    private var nodeActionTitle: String {
        guard let a = nodeAction else { return "" }
        let what = a.nodes.count == 1 ? a.nodes[0].displayName : "\(a.nodes.count) devices"
        return a.kind == .delete ? "Delete \(what)?" : "Expire the key of \(what)?"
    }

    private func perform(_ action: NodeAction) {
        run { client in
            var done = 0
            defer { Task { try? await store.refreshNodes() } }
            for node in action.nodes {
                do {
                    if action.kind == .delete {
                        try await client.deleteNode(nodeID: node.id)
                    } else {
                        try await client.expireNode(nodeID: node.id)
                    }
                    done += 1
                } catch {
                    throw ServerError(status: 0, message: "\(node.displayName): \(error.localizedDescription)"
                                      + (done > 0 ? " (\(done) done before this)" : ""))
                }
            }
            let what = done == 1 ? action.nodes[0].displayName : "\(done) devices"
            return action.kind == .delete ? "Deleted \(what)." : "Expired the key of \(what)."
        }
    }

    private func rename(_ node: HeadscaleNode, to name: String) {
        let name = name.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty, !name.contains("/"), name != node.displayName else { return }
        run { client in
            try await client.renameNode(nodeID: node.id, name: name)
            try? await store.refreshNodes()
            return "Renamed \(node.displayName) to \(name)."
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
    /// Both policies as parsed for the review, for replaying real traffic.
    @State private var models: (old: PolicyModel, new: PolicyModel)?
    /// Real connections the old policy allowed that this push would block;
    /// nil until checked.
    @State private var blocked: [TrafficConnection]?
    @State private var trafficError: String?
    @State private var prTitle = ""
    @State private var pullRequest: URL?
    @State private var prError: String?

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
                if models != nil, store.currentWorkspace.kind == .tailscale { trafficCheck }
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

            if store.isGitOps, !loading, blocker == nil {
                if let pullRequest {
                    HStack {
                        Label("Pull request opened. Tailscale's action tests it; merging applies it.", systemImage: "checkmark.seal.fill")
                            .font(.system(size: 11.5, weight: .semibold))
                            .foregroundStyle(Theme.green)
                        Button("Open") { NSWorkspace.shared.open(pullRequest) }
                    }
                } else {
                    HStack {
                        Text("Pull request title").font(.system(size: 11.5)).foregroundStyle(Theme.textSecondary)
                        TextField("Update tailnet policy", text: $prTitle).textFieldStyle(.roundedBorder)
                    }
                }
                if let prError {
                    Text(prError).font(.system(size: 11)).foregroundStyle(Theme.red)
                        .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                }
            }
            HStack {
                if !loading, blocker == nil {
                    Button("Copy as Markdown") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(reviewMarkdown, forType: .string)
                    }
                    .help("For a ticket or pull request, so someone can approve the change before it goes live")
                    Button("Export…") { exportReview() }
                }
                if pushing { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                if store.isGitOps {
                    Button(pullRequest == nil ? "Open pull request" : "Done") {
                        if pullRequest == nil { openPullRequest() } else { dismiss() }
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(loading || pushing || blocker != nil)
                } else {
                    Button(conflictBase != nil ? "Overwrite and push"
                           : candidate.isRestore ? "Restore on server" : "Push to server") { push() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(loading || pushing || blocker != nil)
                }
            }
        }
        .padding(20)
        .frame(width: 560)
        .background(Theme.background)
        .task { await prepare() }
        .sheet(item: $comparing) { DiffSheet(diff: $0) }
    }

    private var host: String { client.displayHost }

    /// Replays recent real traffic (flow logs) against the new policy.
    @ViewBuilder
    private var trafficCheck: some View {
        if let blocked {
            let total = store.traffic?.connections.filter(\.isPortTraffic).count ?? 0
            if blocked.isEmpty {
                Label("None of the \(total) kinds of real connections in the loaded traffic would be blocked.",
                      systemImage: "checkmark.shield")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.green)
            } else {
                let byIP = nodesByAddress(store.headscaleNodes)
                VStack(alignment: .leading, spacing: 3) {
                    Label("This push would block \(blocked.count) kind\(blocked.count == 1 ? "" : "s") of connection that happened recently:",
                          systemImage: "exclamationmark.triangle.fill")
                        .font(.system(size: 11.5, weight: .semibold))
                        .foregroundStyle(Theme.red)
                    ForEach(blocked.prefix(8)) { c in
                        Text(verbatim: "\(trafficName(c.client, nodes: byIP)) → \(trafficName(c.server, nodes: byIP)) \(c.protoName) \(c.port) · \(c.connections)×")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(Theme.textPrimary)
                    }
                    if blocked.count > 8 {
                        Text(verbatim: "…and \(blocked.count - 8) more (in the exported review).")
                            .font(.system(size: 10.5)).foregroundStyle(Theme.textSecondary)
                    }
                }
            }
        } else {
            HStack(spacing: 8) {
                Button(store.traffic == nil ? "Check against the last 7 days of traffic" : "Check against loaded traffic") {
                    Task { await checkTraffic() }
                }
                .font(.system(size: 11.5))
                .disabled(store.trafficProgress != nil)
                if let p = store.trafficProgress {
                    ProgressView().controlSize(.small)
                    Text(p).font(.system(size: 10.5)).foregroundStyle(Theme.textSecondary)
                }
                if let trafficError {
                    Text(trafficError).font(.system(size: 10.5)).foregroundStyle(Theme.red).lineLimit(2)
                }
            }
        }
    }

    private func checkTraffic() async {
        guard let models else { return }
        trafficError = nil
        do {
            if store.traffic == nil { try await store.loadTraffic(days: 7) }
            blocked = trafficBlocked(by: models.new, was: models.old, traffic: store.traffic?.connections ?? [],
                                     nodes: store.headscaleNodes)
        } catch {
            trafficError = error.localizedDescription
        }
    }

    /// This review — summary, access changes, checks, and the text diff — as Markdown.
    private var reviewMarkdown: String {
        var model = (try? HuJSONParser.parse(candidate.text)).map(PolicyModel.init(tree:)) ?? PolicyModel()
        model.userAutogroups = store.model.userAutogroups
        let ev = Evaluator(model: model)
        return pushReviewMarkdown(PushReview(
            workspace: store.currentWorkspace.name, host: host, isRestore: candidate.isRestore,
            serverText: serverText, candidate: candidate.text, changes: changes, deviceCount: deviceCount,
            note: previewNote, verdict: serverVerdict, errors: candidateErrors,
            tests: ev.runTests(), sshTests: ev.runSSHTests(), conflict: conflictBase != nil,
            blockedTraffic: blocked.map { list in
                let byIP = nodesByAddress(store.headscaleNodes)
                return list.map { "\(trafficName($0.client, nodes: byIP)) → \(trafficName($0.server, nodes: byIP)) \($0.protoName) \($0.port) (\($0.connections) connections)" }
            }))
    }

    private func exportReview() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "md") ?? .plainText]
        panel.nameFieldStringValue = "\(store.currentWorkspace.name) change review.md"
        if panel.runModal() == .OK, let url = panel.url {
            try? reviewMarkdown.write(to: url, atomically: true, encoding: .utf8)
        }
    }

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
        var newModel = PolicyModel(tree: newTree)
        newModel.userAutogroups = store.model.userAutogroups
        candidateErrors = lintPolicy(newModel).filter { $0.severity == .error }
        do {
            let current = try await client.getPolicy()
            serverText = current
            if let report = try? await client.validate(candidate.text) {
                serverVerdict = report.passed ? "" : report.summary
            }
            if store.isGitOps {
                // Git is the source of truth; drift shows in the banner instead.
            } else if let last = store.currentWorkspace.lastSyncedPolicy {
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
                var oldModel = PolicyModel(tree: oldTree)
                oldModel.userAutogroups = newModel.userAutogroups
                changes = accessChanges(from: oldModel, to: newModel, nodes: nodes)
                models = (oldModel, newModel)
                // Traffic already loaded (Traffic screen): check right away.
                if let traffic = store.traffic {
                    blocked = trafficBlocked(by: newModel, was: oldModel, traffic: traffic.connections, nodes: nodes)
                }
            } else {
                previewNote = "The server's current policy couldn't be parsed here, so no access comparison is available."
            }
        } catch {
            blocker = "Couldn't read the server's current policy, so there would be no rollback copy: \(error.localizedDescription)"
        }
        loading = false
    }

    /// Git mode: the reviewed policy goes to GitHub as a pull request; the
    /// review (access changes, checks, traffic) becomes its description.
    private func openPullRequest() {
        guard let file = store.linkedFileURL else { return }
        pushing = true
        prError = nil
        let title = prTitle.trimmingCharacters(in: .whitespaces).isEmpty
            ? (candidate.isRestore ? "Restore an earlier tailnet policy" : "Update tailnet policy") : prTitle
        Task {
            defer { pushing = false }
            do {
                guard let repo = await GitRepo.containing(file) else {
                    throw GitError(message: "\(file.lastPathComponent) isn't in a Git repository anymore.")
                }
                let url = try await repo.openPullRequest(files: [repo.relativePath(file): candidate.text],
                                                         title: title, body: reviewMarkdown)
                pullRequest = url
                store.snapshot(reason: "pull request opened")
                NSWorkspace.shared.open(url)
            } catch {
                prError = error.localizedDescription
            }
        }
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
