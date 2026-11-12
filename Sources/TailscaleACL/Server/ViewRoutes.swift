import Foundation
import Hummingbird

// Read-only API behind the search, SSH, Tests, Routes, and Visual Builder
// views. Each is what the Mac screen of the same name shows, from the engine.

/// Everything ⌘K can find; the browser filters it as you type.
struct SearchIndexReply: ResponseEncodable {
    struct Item: Encodable {
        /// "entity", "device", or "rule".
        var kind: String
        var title: String
        var subtitle: String
        /// What to open: a policy name or node:<id> for the map, else a policy line.
        var focus: String?
        var line: Int?
    }
    var items: [Item]
}

struct IPLookupReply: ResponseEncodable {
    struct Hit: Encodable { var title: String; var detail: String; var line: Int?; var device: String? }
    var hits: [Hit]
}

struct SSHReply: ResponseEncodable {
    struct Rule: Encodable {
        var index: Int
        var name: String
        var action: String
        var src: [String]
        var dst: [String]
        var users: [String]
        var expires: String?
        var explanation: String?
        var line: Int?
    }
    var rules: [Rule]
}

struct TestsReply: ResponseEncodable {
    struct Assertion: Encodable {
        var kind: String       // accept, deny (network); accept, check, deny (SSH)
        var dst: String
        var login: String?
        var actual: String?    // SSH: what happens instead
        var passed: Bool
        /// For a failing network assertion: why.
        var why: String?
    }
    struct Test: Encodable { var index: Int; var src: String; var passed: Bool; var line: Int?; var assertions: [Assertion] }
    var tests: [Test]
    var sshTests: [Test]
}

struct RoutesReply: ResponseEncodable {
    struct Approver: Encodable { var route: String; var approvers: [String] }
    struct Via: Encodable { var src: [String]; var dst: [String]; var via: [String]; var routers: [String]; var line: Int? }
    struct Attr: Encodable { var target: [String]; var attr: [String]; var app: Bool; var line: Int? }
    struct Device: Encodable {
        struct Route: Encodable { var route: String; var state: String }  // approved, autoApproved (pending), manual
        var id: String
        var name: String
        var tags: [String]
        var routes: [Route]
    }
    var routeApprovers: [Approver]
    var exitNodeApprovers: [String]
    var via: [Via]
    var nodeAttrs: [Attr]
    var devices: [Device]
}

/// The Visual Builder: one line per (rule, source, destination).
struct ConnectionsReply: ResponseEncodable {
    struct Connection: Encodable { var rule: String; var src: String; var dst: String; var ports: String }
    struct Rule: Encodable { var id: String; var kind: String; var name: String; var badge: String; var explanation: String?; var line: Int? }
    var connections: [Connection]
    var rules: [Rule]
    /// Policy order of every source and destination name, defined or not:
    /// the starting order for the boxes, and the unused ones on "Show".
    var sourceOrder: [String]
    var destOrder: [String]
}

func addViewRoutes(to api: RouterGroup<AppContext>, state: ServerState) {
    api.get("sources/:source/search-index") { _, context -> SearchIndexReply in
        let s = try await state.snapshot(context)
        let m = try requireModel(s)
        var items: [SearchIndexReply.Item] = []
        func entity(_ name: String, _ subtitle: String) { items.append(.init(kind: "entity", title: name, subtitle: subtitle, focus: name)) }
        m.groupOrder.forEach { g in
            let n = m.groups[g]?.count ?? 0
            entity(g, "group · \(n) member\(n == 1 ? "" : "s")")
        }
        m.tagOrder.forEach { entity($0, "tag") }
        m.allUsers.forEach { entity($0, "user") }
        m.hostOrder.forEach { entity($0, "host · \(m.hosts[$0] ?? "")") }
        m.ipsetOrder.forEach { entity($0, "IP set") }
        for n in s.nodes {
            let detail = ([n.policyName] + [n.ipAddresses?.first]).compactMap { $0 }.joined(separator: " · ")
            items.append(.init(kind: "device", title: n.displayName, subtitle: "device · \(detail)", focus: "node:\(n.id)"))
        }
        for r in ruleSummaries(m, sourceIDs: nil) {
            let kind = r.kind == .grant ? "grant" : r.kind == .ssh ? "SSH rule" : "ACL rule"
            items.append(.init(kind: "rule", title: r.name,
                               subtitle: "\(kind) · \(r.sources.joined(separator: ", ")) → \(r.destinations.joined(separator: ", "))",
                               line: s.tree?.line(at: "\(r.section)[\(r.index)]")))
        }
        return SearchIndexReply(items: items)
    }

    // ?ip=100.64.0.1 — everything in the policy that covers an address.
    api.get("sources/:source/ip-lookup") { request, context -> IPLookupReply in
        let s = try await state.snapshot(context)
        let m = try requireModel(s)
        guard let ip = request.uri.queryParameters.get("ip"), ip.count <= 64, isAddressLike(ip) else { return IPLookupReply(hits: []) }
        return IPLookupReply(hits: ipLookup(ip, m, nodes: s.nodes).map { hit in
            .init(title: hit.title, detail: hit.detail, line: hit.path.flatMap { s.tree?.line(at: $0) }, device: hit.deviceID)
        })
    }

    api.get("sources/:source/ssh") { _, context -> SSHReply in
        let s = try await state.snapshot(context)
        let m = try requireModel(s)
        return SSHReply(rules: m.sshRules.map { r in
            .init(index: r.index, name: r.comments.first ?? "SSH rule #\(r.index + 1)", action: r.action, src: r.src, dst: r.dst,
                  users: r.users, expires: r.expires, explanation: ruleExplanation(m, kind: .ssh, index: r.index),
                  line: s.tree?.line(at: "ssh[\(r.index)]"))
        })
    }

    api.get("sources/:source/tests") { _, context -> TestsReply in
        let s = try await state.snapshot(context)
        let m = try requireModel(s)
        let ev = Evaluator(model: m)
        let network = ev.runTests().map { t in
            TestsReply.Test(index: t.testIndex, src: t.src, passed: t.passed, line: s.tree?.line(at: "tests[\(t.testIndex)]"),
                            assertions: t.assertions.map { a in
                .init(kind: a.kind == .accept ? "accept" : "deny", dst: a.dst, passed: a.passed,
                      why: a.passed ? nil : explainFailure(m, src: t.src, entry: a.dst, expectAllowed: a.kind == .accept).summary)
            })
        }
        let ssh = ev.runSSHTests().map { t in
            TestsReply.Test(index: t.testIndex, src: t.src, passed: t.passed, line: s.tree?.line(at: "sshTests[\(t.testIndex)]"),
                            assertions: t.assertions.map { a in
                .init(kind: a.expected.rawValue, dst: a.dst, login: a.login, actual: a.actual.rawValue, passed: a.passed)
            })
        }
        return TestsReply(tests: network, sshTests: ssh)
    }

    api.get("sources/:source/routes") { _, context -> RoutesReply in
        let s = try await state.snapshot(context)
        let m = try requireModel(s)
        let ev = Evaluator(model: m)
        let isExit = { (r: String) in r == "0.0.0.0/0" || r == "::/0" }
        return RoutesReply(
            routeApprovers: m.routeApprovers.map { .init(route: $0.route, approvers: $0.approvers) },
            exitNodeApprovers: m.exitNodeApprovers,
            via: m.grants.filter { !$0.via.isEmpty }.map { g in
                .init(src: g.src, dst: g.dst, via: g.via,
                      routers: s.nodes.filter { !Set($0.allTags).isDisjoint(with: g.via) }.map(\.displayName),
                      line: s.tree?.line(at: "grants[\(g.index)]"))
            },
            nodeAttrs: m.nodeAttrs.map { .init(target: $0.target, attr: $0.attr, app: $0.hasApp, line: s.tree?.line(at: "nodeAttrs[\($0.index)]")) },
            devices: s.nodes.filter { !($0.availableRoutes ?? []).isEmpty }.map { n in
                let approved = Set(n.approvedRoutes ?? [])
                // An exit node is one pair; show it once.
                var routes = (n.availableRoutes ?? []).filter { !isExit($0) }
                if (n.availableRoutes ?? []).contains(where: isExit) { routes.insert("0.0.0.0/0", at: 0) }
                return .init(id: n.id, name: n.displayName, tags: n.allTags, routes: routes.map { r in
                    .init(route: isExit(r) ? "exit node" : r,
                          state: approved.contains(r) ? "approved" : ev.autoApproves(route: r, node: n) ? "autoApproved" : "manual")
                })
            })
    }

    api.get("sources/:source/connections") { _, context -> ConnectionsReply in
        let s = try await state.snapshot(context)
        let m = try requireModel(s)
        func strip(_ t: String) -> String { t.hasPrefix("host:") ? String(t.dropFirst(5)) : t }
        var connections: [ConnectionsReply.Connection] = []
        for r in m.rules where r.action == "accept" {
            for src in r.src { for dst in r.dst {
                let d = DestSpec(dst)
                connections.append(.init(rule: "acl\(r.index)", src: src, dst: strip(d.target), ports: d.ports))
            } }
        }
        for g in m.grants {
            let ports = g.ip.isEmpty ? "app" : g.ip.joined(separator: ", ")
            for src in g.src { for dst in g.dst { connections.append(.init(rule: "grant\(g.index)", src: src, dst: strip(dst), ports: ports)) } }
        }
        let rules = ruleSummaries(m, sourceIDs: nil).filter { $0.kind != .ssh }.map { r in
            ConnectionsReply.Rule(id: r.id, kind: r.kind == .grant ? "grant" : "acl", name: r.name, badge: r.badge,
                                  explanation: ruleExplanation(m, kind: r.kind, index: r.index),
                                  line: s.tree?.line(at: "\(r.section)[\(r.index)]"))
        }
        return ConnectionsReply(connections: connections, rules: rules,
                                sourceOrder: (["*", "autogroup:member"] + m.sourceSpecs).uniqued(),
                                destOrder: (["*"] + m.destTargets.map(strip)).uniqued())
    }
}
