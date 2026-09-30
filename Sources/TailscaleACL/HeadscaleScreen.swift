import SwiftUI

/// Talk to a self-hosted Headscale server: pull/push the policy, list nodes.
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

    private var serverURL: Binding<String> {
        Binding(get: { store.currentWorkspace.serverURL }, set: { store.setServerURL($0) })
    }

    private var client: HeadscaleClient? {
        HeadscaleClient.make(serverURL: store.currentWorkspace.serverURL, apiKey: apiKey)
    }

    /// Push history for this workspace's server only.
    private var serverHistory: [PushRecord] {
        let host = URL(string: store.currentWorkspace.serverURL.trimmingCharacters(in: .whitespaces))?.host
        return history.filter { $0.server == host }
    }

    private func loadKey() {
        apiKey = HeadscaleKeychain.load(account: store.currentWorkspaceID.uuidString) ?? ""
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Headscale")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundStyle(Theme.textPrimary)
                    Text("Pull and push the policy for workspace \u{201C}\(store.currentWorkspace.name)\u{201D} on its Headscale server, and see its nodes")
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.textSecondary)
                }

                connectionPanel
                policyPanel
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
        }
        .confirmationDialog("Replace the editor contents with the policy from Headscale?",
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
                    if candidate.isRestore { store.loadPolicy(candidate.text) }
                    status = (true, candidate.isRestore
                              ? "Restored — the server and editor now have the earlier policy."
                              : "Pushed — Headscale accepted and applied the policy.")
                }
                .environmentObject(store)
            }
        }
        .sheet(item: $comparing) { DiffSheet(diff: $0) }
        .confirmationDialog("Replace the editor contents with this policy?",
                            isPresented: Binding(get: { openingRecord != nil },
                                                 set: { if !$0 { openingRecord = nil } })) {
            if let record = openingRecord {
                Button("Open the version before this push") { store.loadPolicy(record.before) }
                Button("Open the version that was pushed") { store.loadPolicy(record.pushed) }
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
            Text("Pushing requires the server to store its policy in the database (policy.mode: database in config.yaml). In file mode the server's policy file is the source of truth and push is refused.")
                .font(.system(size: 10.5))
                .foregroundStyle(Theme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) {
                ToolbarButton(label: "Pull from Headscale", icon: "arrow.down.circle") {
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

    private func run(_ work: @escaping (HeadscaleClient) async throws -> String) {
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
            store.loadPolicy(policy)
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
    var client: HeadscaleClient
    var candidate: PushCandidate
    var onPushed: () -> Void

    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var serverText: String?
    @State private var changes: [AccessChange] = []
    @State private var deviceCount = 0
    @State private var previewNote: String?
    @State private var candidateErrors: [LintIssue] = []
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
                if !candidateErrors.isEmpty {
                    Label("The Problems check reports \(candidateErrors.count) error\(candidateErrors.count == 1 ? "" : "s") in this policy — Headscale may reject it.",
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
                       : candidate.isRestore ? "Restore on server" : "Push to Headscale") { push() }
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

    private var host: String { client.baseURL.host ?? "server" }

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
                blocker = "Headscale refused the policy: \(error.localizedDescription)"
                pushing = false
            }
        }
    }
}
