import SwiftUI

/// Create or edit one ACL, grant, or SSH rule: name (its comment), sources,
/// destinations, ports/users, and the options — via (routers and exit
/// nodes), device postures, the ACL protocol, the SSH check period, expiry.
/// Before saving it shows what the rule would add to Problems and how access
/// changes. Fields the sheet doesn't show are kept.
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
    @State private var via: [String] = []
    @State private var postures: [String] = []
    @State private var proto = ""
    @State private var checkPeriod = ""
    @State private var expires = false
    @State private var expiryDate = Date().addingTimeInterval(7 * 86_400)
    @State private var showOptions = false
    @State private var preview: (problems: [String], changes: [String])?
    @State private var confirmingDelete = false
    @State private var copying = false

    /// Common services, as grant ip entries.
    private static let services: [(name: String, ip: [String])] = [
        ("All", ["*"]), ("SSH", ["tcp:22"]), ("HTTPS", ["tcp:443"]), ("HTTP", ["tcp:80"]),
        ("RDP", ["tcp:3389", "udp:3389"]), ("DNS", ["tcp:53", "udp:53"]), ("SMB", ["tcp:445"]),
        ("SQL Server", ["tcp:1433"]), ("PostgreSQL", ["tcp:5432"]), ("MySQL", ["tcp:3306"]),
        ("LDAP", ["tcp:389", "udp:389", "tcp:636"]), ("Kerberos", ["tcp:88", "udp:88"]), ("Ping", ["icmp:*"]),
    ]

    var body: some View {
        ScrollView {
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
                                 addPrompt: kind == .acl ? "e.g. tag:server:22,443 or *:*" : "e.g. tag:server, ipset:RDS, or 10.0.0.0/24",
                                 suggestions: destSuggestions, items: $dst)
                if kind == .grant {
                    StringListEditor(title: "Protocols and ports (ip)", addPrompt: "e.g. tcp:443, udp:53, 8000-8100, or *",
                                     suggestions: ["*", "tcp:22", "tcp:80", "tcp:443", "udp:53", "tcp:3389", "icmp:*"],
                                     items: $ip)
                    servicePresets
                }
                if kind == .ssh {
                    StringListEditor(title: "SSH users", addPrompt: "e.g. root or autogroup:nonroot",
                                     suggestions: ["root", "autogroup:nonroot"], items: $users)
                }

                DisclosureGroup(isExpanded: $showOptions) {
                    options.padding(.top, 8)
                } label: {
                    Text(optionsLabel)
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(Theme.textPrimary)
                }

                checkPanel

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
        }
        .frame(width: 540)
        .frame(minHeight: 420, idealHeight: 640, maxHeight: 820)
        .background(Theme.background)
        .onAppear(perform: load)
        .task(id: draftKey) {
            // Re-checked shortly after edits stop, off the main thread.
            try? await Task.sleep(nanoseconds: 300_000_000)
            guard valid, let tree = store.tree else { preview = nil; return }
            let (section, index, name, expiry, fields) = (sectionName, existing?.index, self.name, expiryValue, draftFields)
            let current = store.model
            let currentIssues = Set(store.lintIssues.map(\.id))
            preview = await Task.detached {
                var candidate = tree
                applyRuleEdit(&candidate, section: section, index: index, name: name, expires: expiry, fields: fields)
                var m = PolicyModel(tree: candidate)
                m.userAutogroups = current.userAutogroups
                let problems = lintPolicy(m).filter { !currentIssues.contains($0.id) }.map { "\($0.title): \($0.detail)" }
                return (Array(problems.prefix(6)), entityAccessDifferences(current, m, limit: 8))
            }.value
        }
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

    // MARK: Parts

    private var servicePresets: some View {
        FlowLayout(spacing: 5) {
            ForEach(Self.services, id: \.name) { service in
                let on = service.ip.allSatisfy(ip.contains)
                Button {
                    if service.ip == ["*"] {
                        ip = on ? [] : ["*"]
                    } else if on {
                        ip.removeAll { service.ip.contains($0) }
                    } else {
                        ip = (ip.filter { $0 != "*" } + service.ip).uniqued()
                    }
                } label: {
                    Text(service.name)
                        .font(.system(size: 10.5, weight: .semibold))
                        .padding(.horizontal, 7).padding(.vertical, 3)
                        .background(RoundedRectangle(cornerRadius: 5).fill(on ? Theme.green.opacity(0.25) : Theme.panel))
                        .foregroundStyle(on ? Theme.green : Theme.textSecondary)
                }
                .buttonStyle(.plain)
                .help(service.ip.joined(separator: ", "))
            }
        }
    }

    @ViewBuilder
    private var options: some View {
        VStack(alignment: .leading, spacing: 12) {
            if kind == .grant {
                StringListEditor(title: "Route through (via)", addPrompt: "e.g. tag:client-vpn",
                                 suggestions: viaSuggestions, items: $via)
                Text("Only through subnet routers or exit nodes with these tags — for reaching subnets or the internet.")
                    .font(.system(size: 10.5)).foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if kind == .acl {
                HStack {
                    Text("Protocol").font(.system(size: 11, weight: .semibold)).foregroundStyle(Theme.textSecondary)
                    Picker("", selection: $proto) {
                        Text("Any (TCP and UDP)").tag("")
                        Text("TCP").tag("tcp")
                        Text("UDP").tag("udp")
                        Text("ICMP").tag("icmp")
                    }
                    .labelsHidden()
                    .frame(width: 180)
                }
            }
            if kind != .ssh {
                StringListEditor(title: "Device posture (any of)", addPrompt: "e.g. posture:huntress-protected",
                                 suggestions: store.model.postureOrder, items: $postures)
                if postures.isEmpty, !store.model.defaultSrcPosture.isEmpty {
                    Text(verbatim: "Without one, defaultSrcPosture applies: \(store.model.defaultSrcPosture.joined(separator: ", ")).")
                        .font(.system(size: 10.5)).foregroundStyle(Theme.textSecondary)
                }
            }
            if kind == .ssh, action == "check" {
                HStack {
                    Text("Re-check every").font(.system(size: 11, weight: .semibold)).foregroundStyle(Theme.textSecondary)
                    TextField("12h (default), 1h, or always", text: $checkPeriod)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 200)
                }
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
        }
    }

    private var optionsLabel: String {
        var set: [String] = []
        if !via.isEmpty { set.append("via \(via.joined(separator: ", "))") }
        if !postures.isEmpty { set.append("posture") }
        if !proto.isEmpty { set.append(proto.uppercased()) }
        if expires { set.append("expires") }
        let title = kind == .grant ? "Routing, posture, and expiry" : kind == .acl ? "Protocol, posture, and expiry" : "Check period and expiry"
        return set.isEmpty ? title : "\(title) — \(set.joined(separator: " · "))"
    }

    @ViewBuilder
    private var checkPanel: some View {
        if let preview, valid {
            VStack(alignment: .leading, spacing: 5) {
                if preview.problems.isEmpty {
                    Label("No new problems", systemImage: "checkmark.shield").foregroundStyle(Theme.green)
                } else {
                    ForEach(preview.problems, id: \.self) {
                        Label($0, systemImage: "exclamationmark.triangle.fill").foregroundStyle(Theme.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                if preview.changes.isEmpty {
                    Text(existing == nil ? "Adds no access anyone doesn't already have." : "Access doesn't change.")
                        .foregroundStyle(Theme.textSecondary)
                } else {
                    Text("Access changes:").font(.system(size: 11, weight: .semibold)).foregroundStyle(Theme.textPrimary)
                    ForEach(preview.changes, id: \.self) {
                        Text($0).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Theme.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .font(.system(size: 11))
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 7).fill(Theme.panel))
        }
    }

    // MARK: Suggestions

    private var sourceSuggestions: [String] {
        var out = ["*", "autogroup:member", "autogroup:tagged"] + store.model.groupOrder + store.model.tagOrder
        out += Evaluator.roleAutogroups.sorted()
        out += store.serverAccounts.map(\.login).sorted()
        return out.uniqued()
    }

    private var destSuggestions: [String] {
        let m = store.model
        var targets = ["*"] + m.tagOrder + m.hostOrder + m.ipsetOrder + m.groupOrder
        targets += kind == .ssh ? ["autogroup:self"] : ["autogroup:internet", "autogroup:self"]
        return kind == .acl ? targets.map { "\($0):*" } : targets
    }

    /// Tags on devices with approved routes first: those are the routers and exit nodes.
    private var viaSuggestions: [String] {
        let routers = store.headscaleNodes.filter { !($0.approvedRoutes ?? []).isEmpty }.flatMap(\.allTags)
        return (routers + store.model.tagOrder).uniqued()
    }

    // MARK: Load and save

    private var valid: Bool {
        guard !src.isEmpty, !dst.isEmpty else { return false }
        switch kind {
        case .grant: return !ip.isEmpty || hasApp
        case .ssh: return !users.isEmpty
        case .acl: return true
        }
    }

    private var sectionName: String {
        existing?.section ?? RuleSummary(kind: kind, index: 0, name: "", badge: "", sources: [], destinations: []).section
    }

    private var expiryValue: String?? { .some(expires ? RuleExpiry.formatter.string(from: expiryDate) : nil) }

    /// Changes whenever the draft does, for the live check.
    private var draftKey: String {
        // Built in steps: one long expression times out CI's type checker.
        let kindCode: String = kind == .grant ? "g" : kind == .acl ? "a" : "s"
        let scalars: [String] = [kindCode, name, action, proto, checkPeriod, "\(expires)\(expiryDate)"]
        let lists: [[String]] = [src, dst, ip, users, via, postures]
        let joined: [String] = lists.map { $0.joined(separator: ",") }
        return scalars.joined(separator: "|") + "|" + joined.joined(separator: "|")
    }

    private var draftFields: [(key: String, value: JSON?)] {
        func list(_ items: [String]) -> JSON? { items.isEmpty ? nil : stringArrayJSON(items) }
        switch kind {
        case .acl:
            var fields: [(key: String, value: JSON?)] = existing == nil ? [("action", JSON.string("accept"))] : []
            fields.append(("src", stringArrayJSON(src)))
            fields.append(("dst", stringArrayJSON(dst)))
            fields.append(("proto", proto.isEmpty ? nil : JSON.string(proto)))
            fields.append(("srcPosture", list(postures)))
            return fields
        case .grant:
            return [("src", stringArrayJSON(src)), ("dst", stringArrayJSON(dst)), ("ip", list(ip)),
                    ("via", list(via)), ("srcPosture", list(postures))]
        case .ssh:
            let period = checkPeriod.trimmingCharacters(in: .whitespaces)
            return [("action", .string(action)), ("src", stringArrayJSON(src)), ("dst", stringArrayJSON(dst)),
                    ("users", stringArrayJSON(users)),
                    ("checkPeriod", action == "check" && !period.isEmpty ? .string(period) : nil)]
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
            (proto, postures) = (r.proto ?? "", r.srcPosture)
        case .grant:
            guard let g = m.grants.first(where: { $0.index == existing.index }) else { return }
            (name, src, dst, ip, hasApp, date) = (g.comments.first ?? "", g.src, g.dst, g.ip, g.hasApp, g.expires)
            (via, postures) = (g.via, g.srcPosture)
        case .ssh:
            guard let s = m.sshRules.first(where: { $0.index == existing.index }) else { return }
            (name, src, dst, users, action, date) = (s.comments.first ?? "", s.src, s.dst, s.users, s.action, s.expires)
            checkPeriod = store.tree?["ssh"]?.elements?[safe: existing.index]?.value["checkPeriod"]?.stringValue ?? ""
        }
        if let parsed = date.flatMap(RuleExpiry.formatter.date(from:)) {
            (expires, expiryDate) = (true, parsed)
        }
        showOptions = !via.isEmpty || !postures.isEmpty || !proto.isEmpty || !checkPeriod.isEmpty || expires
    }

    private func save() {
        store.saveRule(section: sectionName, index: existing?.index, name: name, expires: expiryValue, fields: draftFields)
        dismiss()
    }
}

extension Array {
    subscript(safe index: Int) -> Element? { indices.contains(index) ? self[index] : nil }
}
