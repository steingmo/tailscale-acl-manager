import SwiftUI

/// Create or edit one ACL, grant, or SSH rule: name (its comment), sources,
/// destinations, and ports/users. Fields the sheet doesn't show are kept.
struct RuleSheet: View {
    /// The rule being edited, or nil to create one.
    var existing: RuleSummary?
    /// Source filled in for a new rule (e.g. the focused map entity).
    var prefillSource: String?
    /// Destination filled in for a new rule.
    var prefillDestination: String?

    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var kind: RuleSummary.Kind = .grant
    @State private var name = ""
    @State private var src: [String] = []
    @State private var dst: [String] = []
    @State private var ip: [String] = []
    @State private var users: [String] = []
    @State private var action = "accept"
    @State private var hasApp = false
    @State private var expires = false
    @State private var expiryDate = Date().addingTimeInterval(7 * 86_400)
    @State private var confirmingDelete = false
    @State private var copying = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(existing == nil ? "Add rule" : "Edit rule")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)

            if existing == nil {
                Picker("", selection: $kind) {
                    Text("Grant").tag(RuleSummary.Kind.grant)
                    Text("ACL (legacy)").tag(RuleSummary.Kind.acl)
                    Text("SSH").tag(RuleSummary.Kind.ssh)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 300)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("Name")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
                TextField("e.g. Admins reach the NAS", text: $name)
                    .textFieldStyle(.roundedBorder)
                Text("Saved as the comment above the rule.")
                    .font(.system(size: 10.5))
                    .foregroundStyle(Theme.textSecondary.opacity(0.8))
            }

            if kind == .ssh {
                Picker("", selection: $action) {
                    Text("accept").tag("accept")
                    Text("check").tag("check")
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 180)
            }

            StringListEditor(title: "Sources", addPrompt: "e.g. group:ops, tag:ci, or an email",
                             suggestions: sourceSuggestions, items: $src)
            StringListEditor(title: kind == .acl ? "Destinations with ports" : "Destinations",
                             addPrompt: kind == .acl ? "e.g. tag:server:22,443 or *:*" : "e.g. tag:server or ipset:RDS",
                             suggestions: destSuggestions, items: $dst)
            if kind == .grant {
                StringListEditor(title: "Protocols and ports (ip)", addPrompt: "e.g. tcp:443, udp:53, or *",
                                 suggestions: ["*", "tcp:22", "tcp:80", "tcp:443", "udp:53", "tcp:3389", "icmp:*"],
                                 items: $ip)
            }
            if kind == .ssh {
                StringListEditor(title: "SSH users", addPrompt: "e.g. root or autogroup:nonroot",
                                 suggestions: ["root", "autogroup:nonroot"], items: $users)
            }

            HStack(spacing: 8) {
                Toggle("Temporary access, expires", isOn: $expires)
                    .font(.system(size: 11.5))
                if expires {
                    DatePicker("", selection: $expiryDate, displayedComponents: .date)
                        .labelsHidden()
                }
            }
            .help("Saved as an \u{201C}expires:\u{201D} comment. Tailscale doesn't remove the rule by itself: Problems warns a week before and offers to delete it once it has expired.")

            HStack {
                if existing != nil {
                    Button("Delete rule", role: .destructive) { confirmingDelete = true }
                    if store.workspaces.count > 1 {
                        Button("Copy to workspaces…") { copying = true }
                            .help("Copies the saved rule; save your edits first")
                    }
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(existing == nil ? "Add rule" : "Save", action: save)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!valid)
            }
        }
        .padding(20)
        .frame(width: 480)
        .background(Theme.background)
        .onAppear(perform: load)
        .sheet(isPresented: $copying) {
            if let existing { CopyToWorkspacesSheet(payload: .rule(existing)) }
        }
        .confirmationDialog("Delete this rule?", isPresented: $confirmingDelete) {
            Button("Delete", role: .destructive) {
                if let existing { store.deleteRule(section: existing.section, index: existing.index) }
                dismiss()
            }
        } message: {
            Text("You can undo this with ⌘Z.")
        }
    }

    private var sourceSuggestions: [String] {
        ["*", "autogroup:member"] + store.model.groupOrder + store.model.tagOrder
    }

    private var destSuggestions: [String] {
        let m = store.model
        var targets = ["*"] + m.tagOrder + m.hostOrder + m.ipsetOrder + m.groupOrder
        targets += kind == .ssh ? ["autogroup:self"] : ["autogroup:internet"]
        return kind == .acl ? targets.map { "\($0):*" } : targets
    }

    private var valid: Bool {
        guard !src.isEmpty, !dst.isEmpty else { return false }
        switch kind {
        case .grant: return !ip.isEmpty || hasApp
        case .ssh: return !users.isEmpty
        case .acl: return true
        }
    }

    private func load() {
        guard let existing else {
            if let prefillSource { src = [prefillSource] }
            if let prefillDestination { dst = [prefillDestination] }
            return
        }
        kind = existing.kind
        let m = store.model
        var date: String?
        switch existing.kind {
        case .acl:
            guard let r = m.rules.first(where: { $0.index == existing.index }) else { return }
            (name, src, dst, date) = (r.comments.first ?? "", r.src, r.dst, r.expires)
        case .grant:
            guard let g = m.grants.first(where: { $0.index == existing.index }) else { return }
            (name, src, dst, ip, hasApp, date) = (g.comments.first ?? "", g.src, g.dst, g.ip, g.hasApp, g.expires)
        case .ssh:
            guard let s = m.sshRules.first(where: { $0.index == existing.index }) else { return }
            (name, src, dst, users, action, date) = (s.comments.first ?? "", s.src, s.dst, s.users, s.action, s.expires)
        }
        if let parsed = date.flatMap(RuleExpiry.formatter.date(from:)) {
            (expires, expiryDate) = (true, parsed)
        }
    }

    private func save() {
        var fields: [(key: String, value: JSON?)] = []
        switch kind {
        case .acl:
            if existing == nil { fields.append(("action", .string("accept"))) }
            fields += [("src", stringArrayJSON(src)), ("dst", stringArrayJSON(dst))]
        case .grant:
            fields += [("src", stringArrayJSON(src)), ("dst", stringArrayJSON(dst)),
                       ("ip", ip.isEmpty ? nil : stringArrayJSON(ip))]
        case .ssh:
            fields += [("action", .string(action)), ("src", stringArrayJSON(src)),
                       ("dst", stringArrayJSON(dst)), ("users", stringArrayJSON(users))]
        }
        let section = existing?.section ?? RuleSummary(kind: kind, index: 0, name: "", badge: "",
                                                       sources: [], destinations: []).section
        store.saveRule(section: section, index: existing?.index, name: name,
                       expires: .some(expires ? RuleExpiry.formatter.string(from: expiryDate) : nil), fields: fields)
        dismiss()
    }
}
