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

// MARK: - Device tags

/// Replace a device's tags on the Headscale server.
struct DeviceTagsSheet: View {
    var node: HeadscaleNode

    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var tags: [String] = []
    @State private var confirming = false
    @State private var saving = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(verbatim: "Tags for \(node.displayName)")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            Text(node.allTags.isEmpty
                 ? "This device belongs to \(node.user?.name ?? "a user"). Tagging it makes it a tagged device: it then matches the policy only as its tags and loses its user's access, and it can't be turned back into a user device from here."
                 : "A tagged device must keep at least one tag. The server applies the change immediately.")
                .font(.system(size: 11))
                .foregroundStyle(node.allTags.isEmpty ? Theme.orange : Theme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            StringListEditor(title: "Tags", addPrompt: "e.g. tag:server",
                             suggestions: store.model.tagOrder, items: $tags)
            let undeclared = tags.filter { store.model.tagOwners[$0] == nil }
            if !undeclared.isEmpty {
                Label("Not in tagOwners: \(undeclared.joined(separator: ", ")) — the server may reject it.",
                      systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.orange)
            }
            if let error {
                Label(error, systemImage: "xmark.octagon.fill")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                if saving { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Apply to server…") { confirming = true }
                    .keyboardShortcut(.defaultAction)
                    .disabled(tags.isEmpty || tags == node.allTags || saving
                              || !tags.allSatisfy { $0.hasPrefix("tag:") })
            }
        }
        .padding(20)
        .frame(width: 460)
        .background(Theme.background)
        .onAppear { tags = node.allTags }
        .confirmationDialog("Set tags on \(node.displayName) to \(tags.joined(separator: ", "))?",
                            isPresented: $confirming) {
            Button("Apply to server", role: .destructive, action: apply)
        } message: {
            Text("This changes the device on \(store.serverDisplayName) right away.")
        }
    }

    private func apply() {
        guard let client = store.serverClient() else { return }
        saving = true
        error = nil
        Task {
            do {
                try await client.setTags(nodeID: node.id, tags: tags)
                try? await store.refreshNodes()
                dismiss()
            } catch {
                self.error = "The server refused: \(error.localizedDescription)"
            }
            saving = false
        }
    }
}

// MARK: - Quick search

enum SearchResult {
    case entity(String)   // focus the Access Map ("node:<id>" for devices)
    case rule(RuleSummary)
}

/// ⌘K: find any group, tag, user, host, IP set, device, or rule.
struct QuickSearchSheet: View {
    var onPick: (SearchResult) -> Void

    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var query = ""
    @State private var highlighted = 0
    @FocusState private var focused: Bool

    private struct Item: Identifiable {
        var id: String
        var title: String
        var subtitle: String
        var icon: String
        var color: Color
        var result: SearchResult
    }

    private var allItems: [Item] {
        let m = store.model
        var items: [Item] = []
        func entity(_ name: String, _ subtitle: String) {
            items.append(Item(id: "e:" + name, title: name, subtitle: subtitle, icon: Theme.entityIcon(name),
                              color: Theme.entityColor(name), result: .entity(name)))
        }
        m.groupOrder.forEach { g in
            let n = m.groups[g]?.count ?? 0
            entity(g, "group · \(n) member\(n == 1 ? "" : "s")")
        }
        m.tagOrder.forEach { entity($0, "tag") }
        m.allUsers.forEach { entity($0, "user") }
        m.hostOrder.forEach { entity($0, "host · \(m.hosts[$0] ?? "")") }
        m.ipsetOrder.forEach { entity($0, "IP set") }
        for n in store.headscaleNodes {
            items.append(Item(id: "n:" + n.id, title: n.displayName,
                              subtitle: "device · \(([n.policyName] + [n.ipAddresses?.first]).compactMap { $0 }.joined(separator: " · "))",
                              icon: "desktopcomputer", color: Theme.textPrimary, result: .entity("node:\(n.id)")))
        }
        for r in ruleSummaries(m, sourceIDs: nil) {
            let kind = r.kind == .grant ? "grant" : r.kind == .ssh ? "SSH rule" : "ACL rule"
            items.append(Item(id: "r:" + r.id, title: r.name,
                              subtitle: "\(kind) · \(r.sources.joined(separator: ", ")) → \(r.destinations.joined(separator: ", "))",
                              icon: "line.3.horizontal.decrease", color: Theme.lineGreen, result: .rule(r)))
        }
        return items
    }

    private var results: [Item] {
        let q = query.trimmingCharacters(in: .whitespaces)
        let all = allItems
        guard !q.isEmpty else { return Array(all.prefix(60)) }
        return all.filter { $0.title.localizedCaseInsensitiveContains(q) || $0.subtitle.localizedCaseInsensitiveContains(q) }
    }

    var body: some View {
        let results = self.results
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(Theme.textSecondary)
                TextField("Search groups, tags, users, devices, rules…", text: $query)
                    .textFieldStyle(.plain)
                    .font(.system(size: 14))
                    .focused($focused)
                    .onSubmit { pick(results) }
            }
            .padding(14)
            Divider().overlay(Theme.panelBorder)
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(spacing: 1) {
                        ForEach(Array(results.enumerated()), id: \.element.id) { i, item in
                            Button { onPick(item.result) } label: {
                                HStack(spacing: 10) {
                                    Image(systemName: item.icon)
                                        .font(.system(size: 11))
                                        .foregroundStyle(item.color)
                                        .frame(width: 18)
                                    VStack(alignment: .leading, spacing: 1) {
                                        Text(verbatim: item.title)
                                            .font(.system(size: 12.5, weight: .medium))
                                            .foregroundStyle(Theme.textPrimary)
                                            .lineLimit(1)
                                        Text(verbatim: item.subtitle)
                                            .font(.system(size: 10.5))
                                            .foregroundStyle(Theme.textSecondary)
                                            .lineLimit(1)
                                    }
                                    Spacer()
                                }
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                                .background(RoundedRectangle(cornerRadius: 6)
                                    .fill(i == highlighted ? Color.white.opacity(0.09) : .clear))
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .id(i)
                        }
                        if results.isEmpty {
                            Text("No matches.")
                                .font(.system(size: 12))
                                .foregroundStyle(Theme.textSecondary)
                                .padding(20)
                        }
                    }
                    .padding(6)
                }
                .onChange(of: highlighted) { proxy.scrollTo(highlighted) }
            }
        }
        .frame(width: 520, height: 420)
        .background(Theme.background)
        .onAppear { focused = true }
        .onChange(of: query) { highlighted = 0 }
        .onKeyPress(.downArrow) {
            highlighted = min(highlighted + 1, max(results.count - 1, 0))
            return .handled
        }
        .onKeyPress(.upArrow) {
            highlighted = max(highlighted - 1, 0)
            return .handled
        }
        .onKeyPress(.escape) {
            dismiss()
            return .handled
        }
    }

    private func pick(_ results: [Item]) {
        guard results.indices.contains(highlighted) else { return }
        onPick(results[highlighted].result)
    }
}

// MARK: - Templates

/// Pick a ready-made pattern, fill in its fields, and add it to the policy.
struct TemplatesSheet: View {
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var selected = policyTemplates[0].id
    @State private var values: [String: String] = [:]
    @State private var copyingTemplate = false

    private var template: PolicyTemplate { policyTemplates.first { $0.id == selected } ?? policyTemplates[0] }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Add from a template")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            HStack(alignment: .top, spacing: 14) {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(policyTemplates) { t in
                        Button { selected = t.id } label: {
                            Text(t.title)
                                .font(.system(size: 12, weight: t.id == selected ? .semibold : .regular))
                                .foregroundStyle(Theme.textPrimary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                                .background(RoundedRectangle(cornerRadius: 6)
                                    .fill(t.id == selected ? Color.white.opacity(0.09) : .clear))
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
                .frame(width: 210)
                VStack(alignment: .leading, spacing: 10) {
                    Text(template.detail)
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                    ForEach(template.fields, id: \.key) { field in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(field.label)
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundStyle(Theme.textSecondary)
                            TextField(field.defaultValue, text: Binding(
                                get: { values[field.key] ?? field.defaultValue },
                                set: { values[field.key] = $0 }))
                                .textFieldStyle(.roundedBorder)
                                .font(.system(size: 12, design: .monospaced))
                        }
                    }
                    Text("Existing groups and tags are kept. Undo with ⌘Z.")
                        .font(.system(size: 10.5))
                        .foregroundStyle(Theme.textSecondary.opacity(0.8))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                if store.workspaces.count > 1 {
                    Button("Add to other workspaces…") { copyingTemplate = true }
                }
                Button("Add to policy") {
                    store.applyTemplate(template, values: filledValues)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!store.isValid)
            }
        }
        .padding(20)
        .frame(width: 620)
        .background(Theme.background)
        .onChange(of: selected) { values = [:] }
        .sheet(isPresented: $copyingTemplate) {
            CopyToWorkspacesSheet(payload: .template(template, filledValues))
        }
    }

    private var filledValues: [String: String] {
        var v = Dictionary(uniqueKeysWithValues: template.fields.map { ($0.key, $0.defaultValue) })
        for (k, value) in values where template.fields.contains(where: { $0.key == k }) {
            v[k] = value.trimmingCharacters(in: .whitespaces)
        }
        return v
    }
}

// MARK: - Version history

/// Snapshots of this workspace's policy: compare any with the editor, or restore.
struct HistorySheet: View {
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var snapshots: [Snapshot] = []
    @State private var comparing: DiffPresentation?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Version history")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundStyle(Theme.textPrimary)
                    Text("Saved when the workspace opens, and before and after pulls, imports, pushes, and restores. The newest 100 are kept.")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                Button("Save snapshot now") {
                    store.snapshot(reason: "saved by hand")
                    snapshots = SnapshotStore.load(store.currentWorkspaceID)
                }
            }
            ScrollView {
                VStack(spacing: 1) {
                    ForEach(snapshots) { snap in
                        HStack(spacing: 10) {
                            Image(systemName: snap.text == store.text ? "checkmark.circle.fill" : "clock")
                                .font(.system(size: 11))
                                .foregroundStyle(snap.text == store.text ? Theme.green : Theme.textSecondary)
                                .help(snap.text == store.text ? "Same as the editor" : "")
                            Text(snap.date.formatted(date: .abbreviated, time: .shortened))
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundStyle(Theme.textPrimary)
                            Text(snap.reason)
                                .font(.system(size: 11))
                                .foregroundStyle(Theme.textSecondary)
                            Spacer()
                            Button("Compare…") {
                                comparing = DiffPresentation(title: "Snapshot vs editor",
                                                             oldLabel: "snapshot (\(snap.reason))", newLabel: "in the editor",
                                                             old: snap.text, new: store.text)
                            }
                            .disabled(snap.text == store.text)
                            Button("Restore") {
                                store.loadPolicy(snap.text, reason: "restored snapshot")
                                dismiss()
                            }
                            .disabled(snap.text == store.text)
                            .help("Replace the editor with this version (undo with ⌘Z)")
                        }
                        .font(.system(size: 11))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(RoundedRectangle(cornerRadius: 6).fill(Theme.panel))
                    }
                    if snapshots.isEmpty {
                        Text("No snapshots yet.").font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                    }
                }
            }
            .frame(height: 360)
            HStack {
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 620)
        .background(Theme.background)
        .onAppear { snapshots = SnapshotStore.load(store.currentWorkspaceID) }
        .sheet(item: $comparing) { DiffSheet(diff: $0) }
    }
}

// MARK: - Copy to other workspaces

enum CopyPayload {
    case rule(RuleSummary)
    case entities([String])
    case template(PolicyTemplate, [String: String])

    var title: String {
        switch self {
        case .rule(let r): return "Copy \u{201C}\(r.name)\u{201D} to other workspaces"
        case .entities(let names): return "Copy \(names.joined(separator: ", ")) to other workspaces"
        case .template(let t, _): return "Add \u{201C}\(t.title)\u{201D} to other workspaces"
        }
    }
}

/// Pick target workspaces and copy a rule, definitions, or template into them.
/// Groups, tags, hosts, and IP sets a rule needs come along when missing;
/// existing definitions in the target are never overwritten.
struct CopyToWorkspacesSheet: View {
    var payload: CopyPayload
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var selected: Set<UUID> = []
    @State private var results: [(name: String, outcome: CopyOutcome)]?

    private var others: [Workspace] { store.workspaces.filter { $0.id != store.currentWorkspaceID } }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(payload.title)
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
            Text("Missing groups, tags, hosts, and IP sets come along; existing ones in the target are kept as they are. Each target saves a version before and after in its History.")
                .font(.system(size: 11))
                .foregroundStyle(Theme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            if let results {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(results.indices, id: \.self) { i in
                        let r = results[i]
                        Label("\(r.name): \(describe(r.outcome))",
                              systemImage: r.outcome == .copied ? "checkmark.circle.fill"
                                : r.outcome == .alreadyThere ? "equal.circle" : "xmark.octagon.fill")
                            .font(.system(size: 12))
                            .foregroundStyle(r.outcome == .copied ? Theme.green
                                             : r.outcome == .alreadyThere ? Theme.textSecondary : Theme.red)
                    }
                }
            } else {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(others) { ws in
                        Toggle(ws.name, isOn: Binding(
                            get: { selected.contains(ws.id) },
                            set: { if $0 { selected.insert(ws.id) } else { selected.remove(ws.id) } }))
                            .font(.system(size: 12.5))
                    }
                }
            }
            HStack {
                Spacer()
                if results == nil {
                    Button("Cancel") { dismiss() }
                        .keyboardShortcut(.cancelAction)
                    Button("Copy") { copy() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(selected.isEmpty || store.tree == nil)
                } else {
                    Button("Done") { dismiss() }
                        .keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(20)
        .frame(width: 440)
        .background(Theme.background)
    }

    private func describe(_ outcome: CopyOutcome) -> String {
        switch outcome {
        case .copied: return "copied"
        case .alreadyThere: return "already there"
        case .failed(let why): return "not copied — \(why)"
        }
    }

    private func copy() {
        guard let source = store.tree else { return }
        let reason = "copied from \(store.currentWorkspace.name)"
        let targets = others.map(\.id).filter(selected.contains)
        switch payload {
        case .rule(let r):
            results = store.modifyWorkspaces(targets, reason: reason) {
                copyRule(section: r.section, index: r.index, from: source, into: $0)
            }
        case .entities(let names):
            results = store.modifyWorkspaces(targets, reason: reason) {
                copyEntities(names, from: source, into: $0)
            }
        case .template(let t, let values):
            results = store.modifyWorkspaces(targets, reason: "template \(t.title)") {
                applyTemplate(t, values: values, to: $0)
            }
        }
    }
}


// MARK: - Convert ACLs to grants

/// Preview of rewriting the ACLs as grants, with proof that access is unchanged.
struct ConvertToGrantsSheet: View {
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var showingDiff = false

    private struct Preview {
        var text: String
        var aclCount: Int
        var grantCount: Int
        var differences: [String]
        var deviceChanges: [AccessChange]
    }

    private var preview: Preview? {
        guard var tree = store.tree else { return nil }
        let before = store.model
        let converted = convertACLsToGrants(&tree)
        guard converted > 0 else { return nil }
        let after = PolicyModel(tree: tree)
        return Preview(text: HuJSONSerializer.serialize(tree), aclCount: converted,
                       grantCount: after.grants.count - before.grants.count,
                       differences: entityAccessDifferences(before, after),
                       deviceChanges: accessChanges(from: before, to: after, nodes: store.headscaleNodes))
    }

    var body: some View {
        let p = preview
        VStack(alignment: .leading, spacing: 14) {
            Text("Convert ACLs to grants")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            if let p {
                Text(verbatim: "\(p.aclCount) ACL rule\(p.aclCount == 1 ? "" : "s") become\(p.aclCount == 1 ? "s" : "") \(p.grantCount) grant\(p.grantCount == 1 ? "" : "s"). An ACL whose destinations use different ports is split into one grant per port list. Comments, expiry dates, and posture requirements carry over.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                let same = p.differences.isEmpty && p.deviceChanges.isEmpty
                Label(same ? "Access is unchanged: every user, group, tag, host, and autogroup reaches exactly the same destinations and ports\(store.headscaleNodes.isEmpty ? "" : ", and so does every device")."
                      : "Access would change — this shouldn't happen; please report it:",
                      systemImage: same ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundStyle(same ? Theme.green : Theme.red)
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(p.differences, id: \.self) { d in
                    Text(verbatim: d).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Theme.textSecondary)
                }
                ForEach(p.deviceChanges) { c in
                    Text(verbatim: "\(c.src) → \(c.dst): +\(c.gained.joined(separator: ",")) −\(c.lost.joined(separator: ","))")
                        .font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Theme.textSecondary)
                }
                if store.currentWorkspace.kind == .headscale {
                    Label("Headscale supports grants from version 0.29.0. Older servers reject the converted policy on push.",
                          systemImage: "info.circle")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                HStack {
                    Button("Show text changes") { showingDiff = true }
                    Spacer()
                    Button("Cancel") { dismiss() }
                        .keyboardShortcut(.cancelAction)
                    Button(same ? "Convert" : "Convert anyway") {
                        store.convertToGrants()
                        dismiss()
                    }
                    .keyboardShortcut(.defaultAction)
                }
                .sheet(isPresented: $showingDiff) {
                    DiffSheet(diff: DiffPresentation(title: "ACLs → grants", oldLabel: "now", newLabel: "converted",
                                                     old: store.text, new: p.text))
                }
            } else {
                Text("There are no ACL rules to convert.")
                    .foregroundStyle(Theme.textSecondary)
                Button("Close") { dismiss() }
            }
        }
        .padding(20)
        .frame(width: 520)
        .background(Theme.background)
    }
}
