import Foundation

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
]
