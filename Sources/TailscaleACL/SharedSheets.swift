import SwiftUI

// Shared sheets and controls used by the visual builder, access matrix, and SSH screens.

struct QuickPort: Identifiable {
    var label: String
    var port: Int
    var id: Int { port }
}

let quickPorts: [QuickPort] = [
    .init(label: "SSH", port: 22),
    .init(label: "DNS", port: 53),
    .init(label: "HTTP", port: 80),
    .init(label: "HTTPS", port: 443),
    .init(label: "RDP", port: 3389),
    .init(label: "MySQL", port: 3306),
    .init(label: "PostgreSQL", port: 5432),
    .init(label: "Redis", port: 6379),
]


struct ConnectionSheet: View {
    var title: String
    var src: String
    var dstTarget: String
    var initialPorts: String
    var initialProto: String
    var showRemove: Bool
    var allowTypeChoice: Bool
    var initialIsGrant: Bool
    var onSave: (String, String, Bool) -> Void
    var onRemove: () -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var ports = ""
    @State private var proto = "any"
    @State private var isGrant = true

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(title)
                .font(.system(size: 17, weight: .bold))
                .foregroundStyle(Theme.textPrimary)

            HStack(spacing: 8) {
                EntityChip(name: src)
                Image(systemName: "arrow.right")
                    .foregroundStyle(Theme.textSecondary)
                EntityChip(name: dstTarget)
            }

            if allowTypeChoice {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Rule syntax")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(Theme.textSecondary)
                    Picker("", selection: $isGrant) {
                        Text("Grant (modern)").tag(true)
                        Text("ACL (legacy)").tag(false)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .frame(width: 260)
                }
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("Protocol")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
                Picker("", selection: $proto) {
                    Text("Any").tag("any")
                    Text("TCP").tag("tcp")
                    Text("UDP").tag("udp")
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 220)
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("Ports")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
                let columns = [GridItem(.adaptive(minimum: 100), spacing: 6)]
                LazyVGrid(columns: columns, alignment: .leading, spacing: 6) {
                    ForEach(quickPorts) { qp in
                        let active = portSet.contains(String(qp.port))
                        Button {
                            togglePort(qp.port)
                        } label: {
                            // verbatim: port numbers must never get locale
                            // grouping separators (3389, not 3.389)
                            Text(verbatim: "\(qp.label) \(qp.port)")
                                .font(.system(size: 11.5, weight: .medium))
                                .padding(.horizontal, 8)
                                .padding(.vertical, 5)
                                .frame(maxWidth: .infinity)
                                .background(
                                    RoundedRectangle(cornerRadius: 6)
                                        .fill(active ? Theme.green.opacity(0.2) : Color.white.opacity(0.06))
                                )
                                .overlay(
                                    RoundedRectangle(cornerRadius: 6)
                                        .stroke(active ? Theme.green : Theme.panelBorder, lineWidth: 1)
                                )
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(active ? Theme.green : Theme.textPrimary)
                    }
                }
                TextField("Custom, e.g. 22,80,8000-8100 or * for all", text: $ports)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12.5, design: .monospaced))
            }

            HStack {
                if showRemove {
                    Button(role: .destructive) {
                        onRemove()
                        dismiss()
                    } label: {
                        Text("Remove access")
                    }
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(showRemove ? "Save" : "Grant access") {
                    onSave(ports.trimmingCharacters(in: .whitespaces), proto, isGrant)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(ports.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 460)
        .background(Theme.background)
        .onAppear {
            ports = initialPorts
            proto = initialProto
            isGrant = initialIsGrant
        }
    }

    private var portSet: Set<String> {
        Set(ports.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) })
    }

    private func togglePort(_ port: Int) {
        var parts = ports.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && $0 != "*" }
        if let i = parts.firstIndex(of: String(port)) {
            parts.remove(at: i)
        } else {
            parts.append(String(port))
        }
        ports = parts.joined(separator: ",")
    }
}

/// Editable list of strings with add/remove rows and optional suggestions menu.
struct StringListEditor: View {
    var title: String
    var addPrompt: String
    var suggestions: [String]
    @Binding var items: [String]

    @State private var newItem = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Theme.textSecondary)

            ForEach(items.indices, id: \.self) { i in
                HStack(spacing: 6) {
                    TextField("", text: Binding(
                        get: { i < items.count ? items[i] : "" },
                        set: { if i < items.count { items[i] = $0 } }
                    ))
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12, design: .monospaced))
                    Button {
                        items.remove(at: i)
                    } label: {
                        Image(systemName: "minus.circle")
                            .font(.system(size: 11))
                            .foregroundStyle(Theme.textSecondary)
                    }
                    .buttonStyle(.plain)
                    .help("Remove")
                }
            }

            HStack(spacing: 6) {
                TextField(addPrompt, text: $newItem)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12, design: .monospaced))
                    .onSubmit { addItem() }
                if !suggestions.isEmpty {
                    Menu {
                        ForEach(suggestions.filter { !items.contains($0) }, id: \.self) { s in
                            Button(s) { items.append(s) }
                        }
                    } label: {
                        Image(systemName: "chevron.down.circle")
                            .font(.system(size: 11))
                    }
                    .menuStyle(.borderlessButton)
                    .frame(width: 24)
                    .help("Add a known entity")
                }
                Button {
                    addItem()
                } label: {
                    Image(systemName: "plus.circle")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.blue)
                }
                .buttonStyle(.plain)
                .disabled(newItem.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
    }

    private func addItem() {
        let trimmed = newItem.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !items.contains(trimmed) else { return }
        items.append(trimmed)
        newItem = ""
    }
}

// MARK: - Text comparison

struct DiffPresentation: Identifiable {
    let id = UUID()
    var title: String
    var oldLabel: String
    var newLabel: String
    var old: String
    var new: String
}

/// Line-by-line comparison of two policy texts (unchanged runs collapsed).
struct DiffSheet: View {
    var diff: DiffPresentation
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        let lines = lineDiff(old: diff.old, new: diff.new)
        let changed = lines.contains { $0.kind == .added || $0.kind == .removed }
        VStack(alignment: .leading, spacing: 12) {
            Text(diff.title)
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            HStack(spacing: 14) {
                Text(verbatim: "− \(diff.oldLabel)").foregroundStyle(Theme.red)
                Text(verbatim: "+ \(diff.newLabel)").foregroundStyle(Theme.green)
            }
            .font(.system(size: 11.5, design: .monospaced))

            if changed {
                ScrollView([.vertical, .horizontal]) {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(lines) { line in row(line) }
                    }
                    .padding(8)
                }
                .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: Theme.editorBackground)))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.panelBorder, lineWidth: 1))
            } else {
                Label("No differences.", systemImage: "checkmark.circle")
                    .font(.system(size: 12.5))
                    .foregroundStyle(Theme.green)
            }

            HStack {
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 720, height: changed ? 560 : nil)
        .background(Theme.background)
    }

    @ViewBuilder
    private func row(_ line: DiffLine) -> some View {
        switch line.kind {
        case .skipped:
            Text(verbatim: "⋯ \(line.text) unchanged line\(line.text == "1" ? "" : "s")")
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(Theme.textSecondary)
                .padding(.vertical, 3)
        default:
            let (prefix, color): (String, Color) = line.kind == .added ? ("+ ", Theme.green)
                : line.kind == .removed ? ("− ", Theme.red) : ("  ", Theme.textPrimary.opacity(0.75))
            Text(verbatim: prefix + line.text)
                .font(.system(size: 11.5, design: .monospaced))
                .foregroundStyle(color)
                .fixedSize()
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(line.kind == .same ? Color.clear : color.opacity(0.10))
        }
    }
}

// MARK: - Whole-rule editor

/// Create or edit one ACL, grant, or SSH rule: name (its comment), sources,
/// destinations, and ports/users. Fields the sheet doesn't show are kept.
struct RuleSheet: View {
    /// The rule being edited, or nil to create one.
    var existing: RuleSummary?
    /// Source filled in for a new rule (e.g. the focused map entity).
    var prefillSource: String?

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
    @State private var confirmingDelete = false

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

            HStack {
                if existing != nil {
                    Button("Delete rule", role: .destructive) { confirmingDelete = true }
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
            return
        }
        kind = existing.kind
        let m = store.model
        switch existing.kind {
        case .acl:
            guard let r = m.rules.first(where: { $0.index == existing.index }) else { return }
            (name, src, dst) = (r.comments.first ?? "", r.src, r.dst)
        case .grant:
            guard let g = m.grants.first(where: { $0.index == existing.index }) else { return }
            (name, src, dst, ip, hasApp) = (g.comments.first ?? "", g.src, g.dst, g.ip, g.hasApp)
        case .ssh:
            guard let s = m.sshRules.first(where: { $0.index == existing.index }) else { return }
            (name, src, dst, users, action) = (s.comments.first ?? "", s.src, s.dst, s.users, s.action)
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
        store.saveRule(section: section, index: existing?.index, name: name, fields: fields)
        dismiss()
    }
}
