import SwiftUI

/// Talk to a self-hosted Headscale server: pull/push the policy, list nodes.
/// Opt-in — nothing touches the network until a server is configured here.
struct HeadscaleScreen: View {
    @EnvironmentObject var store: PolicyStore
    @AppStorage("headscaleURL") private var serverURL = ""
    @State private var apiKey = HeadscaleKeychain.load() ?? ""
    @State private var status: (ok: Bool, text: String)?
    @State private var busy = false
    @State private var confirmingPull = false
    @State private var confirmingPush = false

    private var client: HeadscaleClient? {
        let trimmed = serverURL.trimmingCharacters(in: .whitespaces)
        guard let url = URL(string: trimmed), url.scheme != nil, url.host != nil,
              !apiKey.isEmpty else { return nil }
        return HeadscaleClient(baseURL: url, apiKey: apiKey)
    }

    private var lintErrors: [LintIssue] { store.lintIssues.filter { $0.severity == .error } }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Headscale")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundStyle(Theme.textPrimary)
                    Text("Pull and push the policy on your self-hosted Headscale server, and see its nodes")
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.textSecondary)
                }

                connectionPanel
                policyPanel
                if !store.headscaleNodes.isEmpty { nodesPanel }
            }
            .padding(16)
            .frame(maxWidth: 820, alignment: .topLeading)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .background(Theme.background)
        .confirmationDialog("Replace the editor contents with the policy from Headscale?",
                            isPresented: $confirmingPull) {
            Button("Pull and replace", role: .destructive) { pull() }
        } message: {
            Text("Unsaved edits in the editor will be lost. Export first if you want to keep them.")
        }
        .confirmationDialog("Push this policy to \(client?.baseURL.host ?? "the server")?",
                            isPresented: $confirmingPush) {
            Button("Push to Headscale", role: .destructive) { push() }
        } message: {
            Text(lintErrors.isEmpty
                 ? "Headscale applies it immediately to every node."
                 : "Headscale applies it immediately to every node. The Problems screen reports \(lintErrors.count) error\(lintErrors.count == 1 ? "" : "s") — Headscale may reject it.")
        }
    }

    // MARK: - Panels

    private var connectionPanel: some View {
        panel {
            Text("Connection")
                .font(.system(size: 13, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            field("Server URL", hint: "e.g. https://headscale.example.com") {
                TextField("https://headscale.example.com", text: $serverURL)
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
                    HeadscaleKeychain.save(apiKey)
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
                ToolbarButton(label: "Push to Headscale", icon: "arrow.up.circle") {
                    confirmingPush = true
                }
                .disabled(client == nil || busy || !store.isValid)
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

    private func pull() {
        run { client in
            let policy = try await client.getPolicy()
            guard !policy.isEmpty else { return "Server returned an empty policy — editor left unchanged." }
            store.loadPolicy(policy)
            return "Pulled policy into the editor."
        }
    }

    private func push() {
        let text = store.text
        run { client in
            try await client.setPolicy(text)
            return "Pushed — Headscale accepted and applied the policy."
        }
    }
}
