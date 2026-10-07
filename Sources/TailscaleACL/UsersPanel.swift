import SwiftUI
import AppKit

/// The Server screen's users: invite or add people (and put them in groups),
/// change roles, approve, suspend, and offboard — removing them from the
/// policy's groups in the same step.
struct UsersPanel: View {
    @EnvironmentObject var store: PolicyStore
    @State private var invites: [PendingInvite] = []
    @State private var status: (ok: Bool, text: String)?
    @State private var busy = false
    @State private var adding = false
    @State private var offboarding: ServerAccount?
    @State private var addingToGroups: ServerAccount?

    private var kind: ServerKind { store.currentWorkspace.kind }
    static let roles = ["member", "admin", "it-admin", "network-admin", "billing-admin", "auditor"]

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(verbatim: "Users (\(store.serverAccounts.count))")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(Theme.textPrimary)
                Spacer()
                if busy { ProgressView().controlSize(.small) }
                Button { Task { await reload() } } label: {
                    Image(systemName: "arrow.clockwise").font(.system(size: 11))
                }
                .buttonStyle(.plain)
                .foregroundStyle(Theme.textSecondary)
                .help("Refresh")
                Button(kind == .tailscale ? "Invite…" : "Add user…") { adding = true }
                    .font(.system(size: 11))
            }
            if let status {
                Label(status.text, systemImage: status.ok ? "checkmark.circle" : "xmark.octagon.fill")
                    .font(.system(size: 11))
                    .foregroundStyle(status.ok ? Theme.green : Theme.red)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
            if store.serverAccounts.isEmpty {
                Text(kind == .tailscale
                     ? "No users loaded. Listing users needs the users:read scope; changing them needs users."
                     : "No users loaded.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.textSecondary)
            }
            if !invites.isEmpty {
                Text("Pending invites")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
                ForEach(invites) { inviteRow($0) }
                Divider().overlay(Theme.panelBorder)
            }
            ForEach(store.serverAccounts) { userRow($0) }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 9).fill(Theme.panel))
        .overlay(RoundedRectangle(cornerRadius: 9).stroke(Theme.panelBorder, lineWidth: 1))
        .task(id: store.currentWorkspaceID) { await loadInvites() }
        .sheet(isPresented: $adding) {
            AddUserSheet { message in
                status = (true, message)
                Task { await reload() }
            }
        }
        .sheet(item: $addingToGroups) { account in
            GroupPickerSheet(login: account.login, current: store.groups(containing: account.policyNames)) { picked in
                store.addUser(account.login, toGroups: picked)
                status = (true, "Added \(account.login) to \(picked.joined(separator: ", ")) in the editor — review and push to apply.")
            }
        }
        .sheet(item: $offboarding) { account in
            OffboardSheet(account: account) { message in
                status = (true, message)
                Task { await reload() }
            }
        }
    }

    // MARK: Rows

    private func inviteRow(_ invite: PendingInvite) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "envelope").foregroundStyle(Theme.textSecondary)
            Text(verbatim: invite.email.isEmpty ? "link invite" : invite.email)
                .font(.system(size: 12, weight: .semibold, design: .monospaced))
                .foregroundStyle(Theme.textPrimary)
            Chip(text: invite.role, color: Theme.purple)
            Spacer()
            if let url = invite.inviteURL {
                Button("Copy link") {
                    SecureClipboard.copy(url)
                    status = (true, SecuritySettings.clearCopiedSecrets ? "Invite link copied — cleared from the clipboard in a minute." : "Invite link copied.")
                }
            }
            if !invite.email.isEmpty {
                Button("Resend") { run("Invite to \(invite.email) sent again.") { try await $0.resendInvite(id: invite.id) } }
            }
            Button("Cancel invite") { run("Invite cancelled.") { try await $0.cancelInvite(id: invite.id) } }
        }
        .font(.system(size: 11))
        .buttonStyle(.borderless)
        .disabled(busy)
    }

    private func userRow(_ a: ServerAccount) -> some View {
        let groups = store.groups(containing: a.policyNames)
        return HStack(spacing: 8) {
            Circle().fill(statusColor(a.status)).frame(width: 7, height: 7)
                .help(a.status ?? "")
            VStack(alignment: .leading, spacing: 1) {
                Text(verbatim: a.displayName)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Theme.textPrimary)
                Text(verbatim: a.login)
                    .font(.system(size: 10.5, design: .monospaced))
                    .foregroundStyle(Theme.textSecondary)
                    .textSelection(.enabled)
            }
            if let role = a.role, role != "member" { Chip(text: role, color: Theme.purple) }
            if a.isShared { Chip(text: "shared", color: Theme.textSecondary) }
            if let s = a.status, s != "active", s != "idle" {
                Text(verbatim: s).font(.system(size: 10.5, weight: .semibold)).foregroundStyle(statusColor(s))
            }
            ForEach(groups.prefix(3), id: \.self) { EntityChip(name: $0) }
            if groups.count > 3 {
                Text(verbatim: "+\(groups.count - 3)").font(.system(size: 10.5)).foregroundStyle(Theme.textSecondary)
                    .help(groups.dropFirst(3).joined(separator: ", "))
            }
            Spacer()
            if let n = a.deviceCount {
                Text(verbatim: "\(n) device\(n == 1 ? "" : "s")").font(.system(size: 10.5)).foregroundStyle(Theme.textSecondary)
            }
            Menu {
                if kind == .tailscale {
                    Menu("Role") {
                        ForEach(Self.roles, id: \.self) { role in
                            Button(role == a.role ? "✓ \(role)" : role) {
                                run("\(a.login) is now \(role).") { try await $0.setRole(userID: a.id, role: role) }
                            }
                            .disabled(role == a.role || a.role == "owner")
                        }
                    }
                    if a.status == "needs-approval" {
                        Button("Approve") { run("\(a.login) approved.") { try await $0.approveUser(id: a.id) } }
                    }
                    if a.status == "suspended" {
                        Button("Restore") { run("\(a.login) restored.") { try await $0.restoreUser(id: a.id) } }
                    }
                }
                Button("Add to groups…") { addingToGroups = a }
                Divider()
                Button("Offboard…") { offboarding = a }
                    .disabled(a.role == "owner")
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .disabled(busy)
        }
        .padding(.vertical, 2)
    }

    private func statusColor(_ s: String?) -> Color {
        switch s {
        case "active": return Theme.green
        case "suspended", "over-billing-limit": return Theme.red
        case "needs-approval": return Theme.orange
        default: return Theme.textSecondary.opacity(0.5)
        }
    }

    // MARK: Actions

    private func run(_ success: String, _ work: @escaping (PolicyServer) async throws -> Void) {
        guard let client = store.serverClient() else { return }
        busy = true
        Task {
            do {
                try await work(client)
                status = (true, success)
            } catch {
                status = (false, Self.explain(error, kind: kind))
            }
            await reload()
        }
    }

    private func reload() async {
        busy = true
        try? await store.refreshNodes()
        await loadInvites()
        busy = false
    }

    private func loadInvites() async {
        guard kind == .tailscale, let client = store.serverClient() else { invites = []; return }
        invites = (try? await client.listInvites()) ?? []
    }

    /// Server errors with the likely fix for missing permissions.
    static func explain(_ error: Error, kind: ServerKind) -> String {
        let text = error.localizedDescription
        guard kind == .tailscale, let e = error as? ServerError, e.status == 403 || e.status == 401 else { return text }
        return text + " — managing users needs an OAuth client with the users scope; invites need a personal API access token."
    }
}

// MARK: - Add or invite

/// Tailscale: invite by email with a role. Headscale: create the user, and
/// optionally a pre-auth key for their first device. Either way, the policy's
/// groups can be filled in at once.
struct AddUserSheet: View {
    var onDone: (String) -> Void

    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var email = ""
    @State private var name = ""
    @State private var displayName = ""
    @State private var role = "member"
    @State private var groups: Set<String> = []
    @State private var makeKey = true
    @State private var working = false
    @State private var error: String?
    /// Shown once: an invite link or a pre-auth key.
    @State private var secret: (label: String, value: String)?

    private var kind: ServerKind { store.currentWorkspace.kind }

    private var login: String {
        kind == .tailscale || !email.isEmpty ? email.trimmingCharacters(in: .whitespaces)
            : name.trimmingCharacters(in: .whitespaces) + "@"
    }

    private var valid: Bool {
        kind == .tailscale ? email.contains("@") : !name.trimmingCharacters(in: .whitespaces).isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(kind == .tailscale ? "Invite a user" : "Add a user")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            if let secret {
                Text(secret.label)
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                Text(verbatim: secret.value)
                    .font(.system(size: 11.5, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 6).fill(Theme.panel))
                HStack {
                    Button("Copy") {
                        SecureClipboard.copy(secret.value)
                    }
                    Spacer()
                    Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
                }
            } else {
                form
            }
        }
        .padding(20)
        .frame(width: 460)
        .background(Theme.background)
    }

    @ViewBuilder
    private var form: some View {
        if kind == .tailscale {
            TextField("Email", text: $email).textFieldStyle(.roundedBorder)
            Picker("Role", selection: $role) {
                ForEach(UsersPanel.roles, id: \.self) { Text($0).tag($0) }
            }
            .frame(width: 240)
            Text("Tailscale emails an invite link. Only a personal API access token can send invites, not an OAuth client.")
                .font(.system(size: 10.5))
                .foregroundStyle(Theme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
        } else {
            TextField("User name (e.g. amy)", text: $name).textFieldStyle(.roundedBorder)
            TextField("Display name (optional)", text: $displayName).textFieldStyle(.roundedBorder)
            TextField("Email (optional)", text: $email).textFieldStyle(.roundedBorder)
            Toggle("Create a pre-auth key for their first device", isOn: $makeKey)
                .font(.system(size: 11.5))
        }
        if !store.model.groupOrder.isEmpty {
            Text(verbatim: "Add \(login.isEmpty ? "them" : login) to groups in the policy")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Theme.textSecondary)
            GroupToggles(selected: $groups)
        }
        if let error {
            Text(error).font(.system(size: 11)).foregroundStyle(Theme.red).fixedSize(horizontal: false, vertical: true)
        }
        HStack {
            if working { ProgressView().controlSize(.small) }
            Spacer()
            Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
            Button(kind == .tailscale ? "Send invite" : "Add user", action: submit)
                .keyboardShortcut(.defaultAction)
                .disabled(!valid || working)
        }
    }

    private func submit() {
        guard let client = store.serverClient() else { return }
        working = true
        error = nil
        Task {
            defer { working = false }
            do {
                var done: String
                if kind == .tailscale {
                    let invite = try await client.invite(email: login, role: role)
                    done = "Invited \(login) as \(role)."
                    if let url = invite.inviteURL {
                        secret = ("Invite sent. The link, if you want to send it yourself:", url)
                    }
                } else {
                    let account = try await client.createUser(name: name.trimmingCharacters(in: .whitespaces),
                                                              displayName: displayName, email: email.trimmingCharacters(in: .whitespaces))
                    done = "Added user \(account.login)."
                    if makeKey {
                        let key = try await client.createAuthKey(AuthKeyRequest(tags: [], user: account.id))
                        secret = ("Pre-auth key for \(account.login)'s first device — shown only once, valid 24 hours:", key)
                    }
                }
                if !groups.isEmpty {
                    let ordered = store.model.groupOrder.filter(groups.contains)
                    store.addUser(login, toGroups: ordered)
                    done += " Added to \(ordered.joined(separator: ", ")) in the editor — review and push the policy to apply."
                }
                onDone(done)
                if secret == nil { dismiss() }
            } catch {
                self.error = UsersPanel.explain(error, kind: kind)
            }
        }
    }
}

/// Checkboxes for the policy's groups.
struct GroupToggles: View {
    @Binding var selected: Set<String>
    @EnvironmentObject var store: PolicyStore

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(store.model.groupOrder, id: \.self) { g in
                    Toggle(isOn: Binding(get: { selected.contains(g) },
                                         set: { if $0 { selected.insert(g) } else { selected.remove(g) } })) {
                        let n = store.model.groups[g]?.count ?? 0
                        Text(verbatim: "\(g)  ·  \(n) member\(n == 1 ? "" : "s")")
                            .font(.system(size: 11.5, design: .monospaced))
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxHeight: 180)
    }
}

/// Add an existing user to more groups.
struct GroupPickerSheet: View {
    var login: String
    var current: [String]
    var onPick: ([String]) -> Void

    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var selected: Set<String> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(verbatim: "Add \(login) to groups")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            GroupToggles(selected: $selected)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Add") {
                    onPick(store.model.groupOrder.filter { selected.contains($0) && !current.contains($0) })
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(selected.subtracting(current).isEmpty)
            }
        }
        .padding(20)
        .frame(width: 420)
        .background(Theme.background)
        .onAppear { selected = Set(current) }
    }
}

// MARK: - Offboard

/// Suspend (Tailscale) or delete a user on the server, and remove them from
/// the policy's groups and tag owners in the same step.
struct OffboardSheet: View {
    var account: ServerAccount
    var onDone: (String) -> Void

    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var delete = false
    @State private var removeFromPolicy = true
    @State private var working = false
    @State private var error: String?

    private var kind: ServerKind { store.currentWorkspace.kind }

    var body: some View {
        let groups = store.groups(containing: account.policyNames)
        VStack(alignment: .leading, spacing: 12) {
            Text(verbatim: "Offboard \(account.displayName)")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            if kind == .tailscale {
                Picker("", selection: $delete) {
                    Text("Suspend — can be restored later").tag(false)
                    Text("Delete — removes the user and their devices").tag(true)
                }
                .pickerStyle(.radioGroup)
                .labelsHidden()
            } else {
                Text("Deletes the user on Headscale. Headscale may refuse while they still have devices — delete those first on the Devices list.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Toggle(groups.isEmpty ? "Not in any group in the policy"
                   : "Remove from \(groups.joined(separator: ", ")) in the policy",
                   isOn: $removeFromPolicy)
                .disabled(groups.isEmpty)
                .font(.system(size: 11.5))
            Text("The policy change is made in the editor (undoable); push it to apply.")
                .font(.system(size: 10.5))
                .foregroundStyle(Theme.textSecondary)
            if let error {
                Text(error).font(.system(size: 11)).foregroundStyle(Theme.red).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                if working { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(kind == .tailscale && !delete ? "Suspend" : "Delete", role: .destructive) { offboard(groups) }
                    .disabled(working)
            }
        }
        .padding(20)
        .frame(width: 460)
        .background(Theme.background)
        .onAppear { delete = kind == .headscale }
    }

    private func offboard(_ groups: [String]) {
        guard let client = store.serverClient() else { return }
        working = true
        error = nil
        Task {
            defer { working = false }
            do {
                if delete || kind == .headscale {
                    try await client.deleteUser(id: account.id)
                } else {
                    try await client.suspendUser(id: account.id)
                }
                var done = "\(account.login) \(delete || kind == .headscale ? "deleted" : "suspended")."
                if removeFromPolicy, !groups.isEmpty {
                    store.removeUserEverywhere(account.policyNames)
                    done += " Removed from \(groups.joined(separator: ", ")) in the editor — review and push the policy to apply."
                }
                onDone(done)
                dismiss()
            } catch {
                self.error = UsersPanel.explain(error, kind: kind)
            }
        }
    }
}
