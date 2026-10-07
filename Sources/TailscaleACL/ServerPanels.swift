import SwiftUI

/// The rounded box every Server screen section sits in.
struct ServerPanel<Content: View>: View {
    let content: Content

    init(@ViewBuilder content: () -> Content) { self.content = content() }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) { content }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 9).fill(Theme.panel))
            .overlay(RoundedRectangle(cornerRadius: 9).stroke(Theme.panelBorder, lineWidth: 1))
    }
}

// MARK: - Auth keys

/// Create a pre-auth key for joining devices; the key is shown once.
struct AuthKeysPanel: View {
    var client: PolicyServer
    @EnvironmentObject var store: PolicyStore
    @State private var busy = false
    @State private var keyTags: [String] = []
    @State private var keyUser = ""
    @State private var users: [ServerUser] = []
    @State private var keyReusable = false
    @State private var keyEphemeral = false
    @State private var keyPreauthorized = true
    @State private var keyExpiry: TimeInterval = 86_400
    @State private var createdKey: String?
    @State private var keyError: String?


    private var kind: ServerKind { store.currentWorkspace.kind }

    private func panel<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        ServerPanel(content: content)
    }

    var body: some View {
        authKeyPanel
            .onChange(of: store.currentWorkspaceID) {
                createdKey = nil
                users = []
                keyUser = ""
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

}

// MARK: - Recent policy changes

/// Who changed the policy on Tailscale recently (configuration audit log).
struct PolicyChangesPanel: View {
    var client: PolicyServer
    @EnvironmentObject var store: PolicyStore
    @State private var policyChanges: [PolicyChange] = []
    @State private var policyChangesError: String?

    private func panel<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        ServerPanel(content: content)
    }

    var body: some View {
        changesPanel
            .task(id: store.currentWorkspaceID) { await loadPolicyChanges() }
    }

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
        do {
            policyChanges = try await client.policyChanges(days: 30) ?? []
            policyChangesError = nil
        } catch let error as ServerError where error.status == 403 {
            policyChangesError = "Your credential can't read the audit log. Give the OAuth client the logs:configuration:read scope to see who changed the policy."
        } catch {
            policyChangesError = "Couldn't load the audit log: \(error.localizedDescription)"
        }
    }

}

// MARK: - Devices

/// The server's devices: filters for stale devices and expiring keys, and
/// tags, rename, key expiry, and delete.
struct DevicesPanel: View {
    var client: PolicyServer?
    @EnvironmentObject var store: PolicyStore
    @State private var busy = false
    @State private var status: (ok: Bool, text: String)?
    @State private var editingTags: HeadscaleNode?
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

    private var serverName: String { store.currentWorkspace.kind == .tailscale ? "Tailscale" : "Headscale" }

    private func panel<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        ServerPanel(content: content)
    }

    var body: some View {
        nodesPanel
            .sheet(item: $editingTags) { DeviceTagsSheet(node: $0) }
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

}
