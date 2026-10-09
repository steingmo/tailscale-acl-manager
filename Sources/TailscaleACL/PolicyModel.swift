import Foundation

struct ACLRule: Identifiable {
    var index: Int
    var comments: [String]
    var action: String
    var src: [String]
    var dst: [String]
    var proto: String?
    var srcPosture: [String] = []
    /// From a "// expires: YYYY-MM-DD" comment (kept out of `comments`).
    var expires: String?

    var id: Int { index }
}

/// Modern grants syntax: dst entries are bare targets; protocols and ports
/// live in the `ip` field ("*", "443", "80-443", "tcp:22", "icmp:*", …).
struct GrantRule: Identifiable {
    var index: Int
    var comments: [String]
    var src: [String]
    var dst: [String]
    var ip: [String]
    var hasApp: Bool
    var via: [String]
    var srcPosture: [String]
    var expires: String?

    var id: Int { index }
}

/// One entry of "nodeAttrs": node attributes for the matching devices.
struct NodeAttrRule: Identifiable {
    var index: Int
    var comments: [String]
    var target: [String]
    var attr: [String]
    var hasApp: Bool

    var id: Int { index }
}

struct SSHRule: Identifiable {
    var index: Int
    var comments: [String]
    var action: String   // "accept" or "check"
    var src: [String]
    var dst: [String]
    var users: [String]
    var expires: String?

    var id: Int { index }
}

struct ACLTest: Identifiable {
    var index: Int
    var src: String
    var accept: [String]
    var deny: [String]
    /// Posture attributes the test device has (Tailscale's srcPostureAttrs).
    var srcPostureAttrs: [String: String]?

    var id: Int { index }
}

/// One "sshTests" entry: for every dst, each listed login must be allowed
/// (accept), allowed only after a check (check), or not allowed (deny).
struct SSHTest: Identifiable {
    var index: Int
    var src: String
    var dst: [String]
    var accept: [String] = []
    var check: [String] = []
    var deny: [String] = []
    var srcPostureAttrs: [String: String]?

    var id: Int { index }
}

struct PolicyModel {
    var groups: [String: [String]] = [:]
    var groupOrder: [String] = []
    var tagOwners: [String: [String]] = [:]
    var tagOrder: [String] = []
    var hosts: [String: String] = [:]
    var hostOrder: [String] = []
    var ipsets: [String: [String]] = [:]
    var ipsetOrder: [String] = []
    /// "posture:name" → conditions, all of which must hold.
    var postures: [String: [String]] = [:]
    var postureOrder: [String] = []
    /// Postures required by rules that don't set their own srcPosture.
    var defaultSrcPosture: [String] = []
    var rules: [ACLRule] = []
    var grants: [GrantRule] = []
    var sshRules: [SSHRule] = []
    var routeApprovers: [(route: String, approvers: [String])] = []
    var exitNodeApprovers: [String] = []
    var nodeAttrs: [NodeAttrRule] = []
    var tests: [ACLTest] = []
    var sshTests: [SSHTest] = []
    /// Custom relay servers ("derpMap").
    var derpRegions: [DERPRegion] = []
    /// Not from the policy: role autogroups of real users (lowercased login →
    /// e.g. ["autogroup:admin"]), filled in from the server's user list.
    var userAutogroups: [String: Set<String>] = [:]

    init() {}

    /// Some rule (or defaultSrcPosture) requires a device posture.
    var usesPostures: Bool {
        !defaultSrcPosture.isEmpty || rules.contains { !$0.srcPosture.isEmpty } || grants.contains { !$0.srcPosture.isEmpty }
    }

    init(tree: JSON) {
        derpRegions = parseDERPMap(tree)
        if let members = tree["groups"]?.members {
            for m in members {
                groups[m.key] = m.value.stringArray
                groupOrder.append(m.key)
            }
        }
        if let members = tree["tagOwners"]?.members {
            for m in members {
                tagOwners[m.key] = m.value.stringArray
                tagOrder.append(m.key)
            }
        }
        if let members = tree["hosts"]?.members {
            for m in members {
                hosts[m.key] = m.value.stringValue ?? ""
                hostOrder.append(m.key)
            }
        }
        if let members = tree["ipsets"]?.members {
            for m in members {
                ipsets[m.key] = m.value.stringArray
                ipsetOrder.append(m.key)
            }
        }
        if let members = tree["postures"]?.members {
            for m in members {
                postures[m.key] = m.value.stringArray
                postureOrder.append(m.key)
            }
        }
        defaultSrcPosture = tree["defaultSrcPosture"]?.stringArray ?? []
        // A rule's comments split into its name lines and its expiry date.
        func split(_ comments: [String]) -> (comments: [String], expires: String?) {
            (comments.filter { RuleExpiry.date(in: $0) == nil }, comments.lazy.compactMap(RuleExpiry.date(in:)).first)
        }
        if let elements = tree["acls"]?.elements {
            for (i, e) in elements.enumerated() {
                guard case .object = e.value else { continue }
                let c = split(e.comments)
                rules.append(ACLRule(
                    index: i,
                    comments: c.comments,
                    action: e.value["action"]?.stringValue ?? "accept",
                    src: e.value["src"]?.stringArray ?? [],
                    dst: e.value["dst"]?.stringArray ?? [],
                    proto: e.value["proto"]?.scalarText,  // a name or an IANA number
                    srcPosture: e.value["srcPosture"]?.stringArray ?? [],
                    expires: c.expires
                ))
            }
        }
        if let elements = tree["grants"]?.elements {
            for (i, e) in elements.enumerated() {
                guard case .object = e.value else { continue }
                let c = split(e.comments)
                grants.append(GrantRule(
                    index: i,
                    comments: c.comments,
                    src: e.value["src"]?.stringArray ?? [],
                    dst: e.value["dst"]?.stringArray ?? [],
                    ip: e.value["ip"]?.stringArray ?? [],
                    hasApp: e.value["app"] != nil,
                    via: e.value["via"]?.stringArray ?? [],
                    srcPosture: e.value["srcPosture"]?.stringArray ?? [],
                    expires: c.expires
                ))
            }
        }
        if let aa = tree["autoApprovers"] {
            routeApprovers = (aa["routes"]?.members ?? []).map { ($0.key, $0.value.stringArray) }
            exitNodeApprovers = aa["exitNode"]?.stringArray ?? []
        }
        if let elements = tree["nodeAttrs"]?.elements {
            for (i, e) in elements.enumerated() {
                guard case .object = e.value else { continue }
                nodeAttrs.append(NodeAttrRule(index: i, comments: e.comments,
                                              target: e.value["target"]?.stringArray ?? [],
                                              attr: e.value["attr"]?.stringArray ?? [],
                                              hasApp: e.value["app"] != nil))
            }
        }
        if let elements = tree["ssh"]?.elements {
            for (i, e) in elements.enumerated() {
                guard case .object = e.value else { continue }
                let c = split(e.comments)
                sshRules.append(SSHRule(
                    index: i,
                    comments: c.comments,
                    action: e.value["action"]?.stringValue ?? "accept",
                    src: e.value["src"]?.stringArray ?? [],
                    dst: e.value["dst"]?.stringArray ?? [],
                    users: e.value["users"]?.stringArray ?? [],
                    expires: c.expires
                ))
            }
        }
        if let elements = tree["sshTests"]?.elements {
            for (i, e) in elements.enumerated() {
                guard case .object = e.value else { continue }
                sshTests.append(SSHTest(
                    index: i,
                    src: e.value["src"]?.stringValue ?? "",
                    dst: e.value["dst"]?.stringArray ?? [],
                    accept: e.value["accept"]?.stringArray ?? [],
                    check: e.value["check"]?.stringArray ?? [],
                    deny: e.value["deny"]?.stringArray ?? [],
                    srcPostureAttrs: e.value["srcPostureAttrs"]?.members.map { members in
                        Dictionary(members.compactMap { m in m.value.scalarText.map { (m.key, $0) } },
                                   uniquingKeysWith: { a, _ in a })
                    }
                ))
            }
        }
        if let elements = tree["tests"]?.elements {
            for (i, e) in elements.enumerated() {
                guard case .object = e.value else { continue }
                tests.append(ACLTest(
                    index: i,
                    src: e.value["src"]?.stringValue ?? "",
                    accept: e.value["accept"]?.stringArray ?? [],
                    deny: e.value["deny"]?.stringArray ?? [],
                    srcPostureAttrs: e.value["srcPostureAttrs"]?.members.map { members in
                        Dictionary(members.compactMap { m in m.value.scalarText.map { (m.key, $0) } },
                                   uniquingKeysWith: { a, _ in a })
                    }
                ))
            }
        }
    }

    /// Every user email mentioned in groups, sorted.
    var allUsers: [String] {
        var users = Set<String>()
        for members in groups.values {
            for m in members where m.contains("@") { users.insert(m) }
        }
        return users.sorted()
    }

    /// Source-side entities for pickers and the visual builder.
    var sourceSpecs: [String] {
        var specs: [String] = []
        let used = Set(rules.flatMap(\.src) + grants.flatMap(\.src))
        if used.contains("*") { specs.append("*") }
        for s in used where s.hasPrefix("autogroup:") { specs.append(s) }
        specs.append(contentsOf: groupOrder)
        specs.append(contentsOf: tagOrder)
        return specs.uniqued()
    }

    /// Destination-side entities (targets, without ports; "host:x" → "x").
    var destTargets: [String] {
        var targets: [String] = []
        let used = Set(
            (rules.flatMap(\.dst).map { DestSpec($0).target } + grants.flatMap(\.dst))
                .map { $0.hasPrefix("host:") ? String($0.dropFirst(5)) : $0 }
        )
        if used.contains("*") { targets.append("*") }
        targets.append(contentsOf: hostOrder)
        targets.append(contentsOf: tagOrder)
        targets.append(contentsOf: ipsetOrder)
        // Anything referenced only in rules: autogroups, groups-as-dst, raw IPs.
        for t in used.sorted() where !targets.contains(t) {
            targets.append(t)
        }
        return targets.uniqued()
    }
}

/// A destination spec like "tag:server:22,80,443" split into target + ports.
/// Ports are everything after the last colon, if it looks like a port set.
struct DestSpec {
    var target: String
    var ports: String

    init(_ spec: String) {
        // IPv6 with ports is bracketed: "[fd7a:115c:a1e0::1]:22".
        if spec.hasPrefix("["), let close = spec.range(of: "]:") {
            target = String(spec[spec.index(after: spec.startIndex)..<close.lowerBound])
            ports = String(spec[close.upperBound...])
            return
        }
        if spec.contains("::") || spec.filter({ $0 == ":" }).count > 2, isAddressLike(spec) {
            target = spec  // a bare IPv6 address or prefix
            ports = "*"
            return
        }
        if let lastColon = spec.lastIndex(of: ":") {
            let suffix = String(spec[spec.index(after: lastColon)...])
            let portChars = CharacterSet(charactersIn: "0123456789,-*")
            if !suffix.isEmpty && suffix.unicodeScalars.allSatisfy({ portChars.contains($0) }) {
                target = String(spec[..<lastColon])
                ports = suffix
                return
            }
        }
        target = spec
        ports = "*"
    }

    init(target: String, ports: String) {
        self.target = target
        self.ports = ports
    }

    var spec: String {
        target.contains(":") && isAddressLike(target) ? "[\(target)]:\(ports)" : "\(target):\(ports)"
    }
}

extension Array where Element: Hashable {
    func uniqued() -> [Element] {
        var seen = Set<Element>()
        return filter { seen.insert($0).inserted }
    }
}
