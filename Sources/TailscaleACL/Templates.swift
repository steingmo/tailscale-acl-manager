import Foundation

/// Limit a grant's or ACL's ports to those real traffic used: a grant's
/// `ip` becomes the specs ("tcp:443", "udp:88"); an ACL's destinations keep
/// their targets with the used port numbers. Returns false if not found.
@discardableResult
func narrowRulePorts(_ tree: inout JSON, section: String, index: Int, to specs: [String]) -> Bool {
    guard !specs.isEmpty, var list = tree[section]?.elements, list.indices.contains(index) else { return false }
    let parsed = specs.compactMap { spec -> (proto: String, port: Int)? in
        let parts = spec.split(separator: ":")
        guard parts.count == 2, let port = Int(parts[1]) else { return nil }
        return (String(parts[0]), port)
    }.sorted { ($0.port, $0.proto) < ($1.port, $1.proto) }
    if section == "grants" {
        list[index].value["ip"] = stringArrayJSON(parsed.map { "\($0.proto):\($0.port)" })
    } else {
        let ports = parsed.map(\.port).uniqued().map(String.init).joined(separator: ",")
        let dst = (list[index].value["dst"]?.stringArray ?? []).map { DestSpec(target: DestSpec($0).target, ports: ports).spec }
        list[index].value["dst"] = stringArrayJSON(dst.uniqued())
    }
    tree[section] = .array(list)
    return true
}

/// Rewrite "acls" as equivalent "grants", Tailscale's recommended syntax.
/// An ACL becomes one grant per distinct port list among its destinations
/// ("tag:a:22", "tag:b:443" → two grants); "proto" moves into "ip"
/// ("tcp:22"), and comments, expiry, and srcPosture carry over. Entries
/// that aren't plain accept rules stay ACLs. Returns how many converted.
@discardableResult
func convertACLsToGrants(_ tree: inout JSON) -> Int {
    guard let acls = tree["acls"]?.elements else { return 0 }
    var grants = tree["grants"]?.elements ?? []
    var kept: [JSON.Element] = []
    var converted = 0
    for e in acls {
        guard case .object = e.value, (e.value["action"]?.stringValue ?? "accept") == "accept",
              let src = e.value["src"], let dst = e.value["dst"]?.stringArray, !dst.isEmpty else {
            kept.append(e)
            continue
        }
        let proto = e.value["proto"]?.scalarText
        var byPorts: [(ports: String, targets: [String])] = []
        for d in dst.map(DestSpec.init) {
            let target = d.target.hasPrefix("host:") ? String(d.target.dropFirst(5)) : d.target
            if let i = byPorts.firstIndex(where: { $0.ports == d.ports }) {
                byPorts[i].targets.append(target)
            } else {
                byPorts.append((d.ports, [target]))
            }
        }
        for (n, group) in byPorts.enumerated() {
            let ip = group.ports.split(separator: ",").map { p in
                let port = p.trimmingCharacters(in: .whitespaces)
                return proto.map { "\($0):\(port)" } ?? port
            }
            var members: [JSON.Member] = [
                .init(comments: [], key: "src", value: src),
                .init(comments: [], key: "dst", value: stringArrayJSON(group.targets.uniqued())),
                .init(comments: [], key: "ip", value: stringArrayJSON(ip)),
            ]
            if let posture = e.value["srcPosture"] {
                members.append(.init(comments: [], key: "srcPosture", value: posture))
            }
            // Split grants keep the expiry; the name stays on the first.
            let comments = n == 0 ? e.comments : e.comments.filter { RuleExpiry.date(in: $0) != nil }
            grants.append(JSON.Element(comments: comments, value: .object(members)))
        }
        converted += 1
    }
    guard converted > 0, var members = tree.members, let ai = members.firstIndex(where: { $0.key == "acls" }) else { return 0 }
    if let gi = members.firstIndex(where: { $0.key == "grants" }) {
        members[gi].value = .array(grants)
        if kept.isEmpty { members.remove(at: ai) } else { members[ai].value = .array(kept) }
    } else if kept.isEmpty {
        // Grants take the ACLs' place, comments above "acls" included.
        members[ai].key = "grants"
        members[ai].value = .array(grants)
    } else {
        members[ai].value = .array(kept)
        members.insert(.init(comments: [], key: "grants", value: .array(grants)), at: ai + 1)
    }
    tree.members = members
    return converted
}

/// A ready-made policy pattern added to the current policy in one undoable
/// step. Existing groups and tags are kept; new ones are created as needed.
struct PolicyTemplate: Identifiable {
    struct Field {
        var key: String
        var label: String
        var defaultValue: String
    }

    var id: String
    var title: String
    var detail: String
    var fields: [Field]
    var apply: (inout JSON, [String: String]) -> Void
}

/// Comma-separated field value → list.
private func list(_ value: String?) -> [String] {
    (value ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
}

/// Add `key` to a section object unless it's already there.
private func ensure(_ tree: inout JSON, _ section: String, _ key: String, _ value: JSON) {
    var members = tree[section]?.members ?? []
    guard !members.contains(where: { $0.key == key }) else { return }
    members.append(JSON.Member(comments: [], key: key, value: value))
    tree[section] = .object(members)
}

/// Append a commented rule object to a section array.
private func appendRule(_ tree: inout JSON, _ section: String, _ comment: String, _ fields: [(String, JSON)]) {
    var rules = tree[section]?.elements ?? []
    rules.append(JSON.Element(comments: [comment],
                              value: .object(fields.map { JSON.Member(comments: [], key: $0.0, value: $0.1) })))
    tree[section] = .array(rules)
}

/// Add an approver to autoApprovers.routes[route], or to exitNode when route is nil.
private func addApprover(_ tree: inout JSON, route: String?, _ approver: String) {
    var aa = tree["autoApprovers"] ?? .object([])
    if let route {
        var routes = aa["routes"]?.members ?? []
        if let i = routes.firstIndex(where: { $0.key == route }) {
            let current = routes[i].value.stringArray
            if !current.contains(approver) { routes[i].value = stringArrayJSON(current + [approver]) }
        } else {
            routes.append(JSON.Member(comments: [], key: route, value: stringArrayJSON([approver])))
        }
        aa["routes"] = .object(routes)
    } else {
        let current = aa["exitNode"]?.stringArray ?? []
        if !current.contains(approver) { aa["exitNode"] = stringArrayJSON(current + [approver]) }
    }
    tree["autoApprovers"] = aa
}

private func strings(_ s: [String]) -> JSON { stringArrayJSON(s) }

let policyTemplates: [PolicyTemplate] = [
    PolicyTemplate(
        id: "admins", title: "Admins reach everything",
        detail: "A group with full access to every device and port.",
        fields: [.init(key: "group", label: "Admin group", defaultValue: "group:admins"),
                 .init(key: "members", label: "Members (comma-separated emails)", defaultValue: "")]
    ) { tree, v in
        let group = v["group"] ?? "group:admins"
        ensure(&tree, "groups", group, strings(list(v["members"])))
        appendRule(&tree, "grants", "Admins reach everything", [
            ("src", strings([group])), ("dst", strings(["*"])), ("ip", strings(["*"])),
        ])
    },
    PolicyTemplate(
        id: "self", title: "Everyone reaches their own devices",
        detail: "Each user can reach all of their own devices on any port.",
        fields: []
    ) { tree, _ in
        appendRule(&tree, "grants", "Everyone reaches their own devices", [
            ("src", strings(["autogroup:member"])), ("dst", strings(["autogroup:self"])), ("ip", strings(["*"])),
        ])
    },
    PolicyTemplate(
        id: "subnet", title: "Subnet router",
        detail: "Tag a router, auto-approve the route it advertises, and let users reach that network.",
        fields: [.init(key: "tag", label: "Router tag", defaultValue: "tag:router"),
                 .init(key: "route", label: "Route", defaultValue: "192.168.1.0/24"),
                 .init(key: "users", label: "Who can use it (comma-separated)", defaultValue: "autogroup:member")]
    ) { tree, v in
        let tag = v["tag"] ?? "tag:router"
        let route = v["route"] ?? "192.168.1.0/24"
        ensure(&tree, "tagOwners", tag, strings([]))
        addApprover(&tree, route: route, tag)
        appendRule(&tree, "grants", "Subnet router: \(route)", [
            ("src", strings(list(v["users"]))), ("dst", strings([route])), ("ip", strings(["*"])),
        ])
    },
    PolicyTemplate(
        id: "exit", title: "Exit node",
        detail: "Tag exit nodes, auto-approve them, and let users send internet traffic through them.",
        fields: [.init(key: "tag", label: "Exit node tag", defaultValue: "tag:exit"),
                 .init(key: "users", label: "Who can use it (comma-separated)", defaultValue: "autogroup:member")]
    ) { tree, v in
        let tag = v["tag"] ?? "tag:exit"
        ensure(&tree, "tagOwners", tag, strings([]))
        addApprover(&tree, route: nil, tag)
        appendRule(&tree, "grants", "Internet through exit nodes", [
            ("src", strings(list(v["users"]))), ("dst", strings(["autogroup:internet"])), ("ip", strings(["*"])),
        ])
    },
    PolicyTemplate(
        id: "ssh", title: "SSH to tagged servers",
        detail: "Let a group SSH into tagged servers as a given account (network access on port 22 plus an SSH rule).",
        fields: [.init(key: "tag", label: "Server tag", defaultValue: "tag:server"),
                 .init(key: "group", label: "Group", defaultValue: "group:admins"),
                 .init(key: "login", label: "Login account", defaultValue: "root")]
    ) { tree, v in
        let tag = v["tag"] ?? "tag:server"
        let group = v["group"] ?? "group:admins"
        ensure(&tree, "tagOwners", tag, strings([]))
        ensure(&tree, "groups", group, strings([]))
        appendRule(&tree, "grants", "SSH network access to \(tag)", [
            ("src", strings([group])), ("dst", strings([tag])), ("ip", strings(["tcp:22"])),
        ])
        appendRule(&tree, "ssh", "\(group) may SSH to \(tag)", [
            ("action", .string("accept")), ("src", strings([group])), ("dst", strings([tag])),
            ("users", strings([v["login"] ?? "root"])),
        ])
    },
    PolicyTemplate(
        id: "huntress", title: "Require Huntress protection",
        detail: "A posture: the device is in Huntress, its firewall is on, and Defender protects it (Macs and Linux report Defender as Incompatible and still pass). Grants from the given sources then require it. Check the push review to see who would lose access.",
        fields: [.init(key: "posture", label: "Posture name", defaultValue: "posture:huntress-protected"),
                 .init(key: "sources", label: "Require it for grants from (comma-separated, e.g. group:mgmt-vpn)", defaultValue: "")]
    ) { tree, v in
        let posture = v["posture"].flatMap { $0.isEmpty ? nil : $0 } ?? "posture:huntress-protected"
        ensure(&tree, "postures", posture, strings([
            "huntress:firewallStatus == 'Enabled'",
            "huntress:defenderStatus IN ['Protected', 'Incompatible']",
        ]))
        // Grants that already require a posture keep theirs: srcPosture is any-of,
        // so adding one would loosen them.
        let sources = Set(list(v["sources"]))
        guard !sources.isEmpty, var grants = tree["grants"]?.elements else { return }
        for i in grants.indices where grants[i].value["srcPosture"] == nil
            && !sources.isDisjoint(with: grants[i].value["src"]?.stringArray ?? []) {
            grants[i].value["srcPosture"] = strings([posture])
        }
        tree["grants"] = .array(grants)
    },
]
