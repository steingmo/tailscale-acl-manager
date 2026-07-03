import Foundation

struct ACLRule: Identifiable {
    var index: Int
    var comments: [String]
    var action: String
    var src: [String]
    var dst: [String]
    var proto: String?

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

    var id: Int { index }
}

struct ACLTest: Identifiable {
    var index: Int
    var src: String
    var accept: [String]
    var deny: [String]

    var id: Int { index }
}

struct PolicyModel {
    var groups: [String: [String]] = [:]
    var groupOrder: [String] = []
    var tagOwners: [String: [String]] = [:]
    var tagOrder: [String] = []
    var hosts: [String: String] = [:]
    var hostOrder: [String] = []
    var rules: [ACLRule] = []
    var grants: [GrantRule] = []
    var tests: [ACLTest] = []

    init() {}

    init(tree: JSON) {
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
        if let elements = tree["acls"]?.elements {
            for (i, e) in elements.enumerated() {
                guard case .object = e.value else { continue }
                rules.append(ACLRule(
                    index: i,
                    comments: e.comments,
                    action: e.value["action"]?.stringValue ?? "accept",
                    src: e.value["src"]?.stringArray ?? [],
                    dst: e.value["dst"]?.stringArray ?? [],
                    proto: e.value["proto"]?.stringValue
                ))
            }
        }
        if let elements = tree["grants"]?.elements {
            for (i, e) in elements.enumerated() {
                guard case .object = e.value else { continue }
                grants.append(GrantRule(
                    index: i,
                    comments: e.comments,
                    src: e.value["src"]?.stringArray ?? [],
                    dst: e.value["dst"]?.stringArray ?? [],
                    ip: e.value["ip"]?.stringArray ?? [],
                    hasApp: e.value["app"] != nil,
                    via: e.value["via"]?.stringArray ?? [],
                    srcPosture: e.value["srcPosture"]?.stringArray ?? []
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
                    deny: e.value["deny"]?.stringArray ?? []
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

    /// Destination-side entities (targets, without ports).
    var destTargets: [String] {
        var targets: [String] = []
        let used = Set(rules.flatMap(\.dst).map { DestSpec($0).target }
                       + grants.flatMap(\.dst))
        if used.contains("*") { targets.append("*") }
        targets.append(contentsOf: hostOrder)
        targets.append(contentsOf: tagOrder)
        for t in used where !targets.contains(t) && t.hasPrefix("autogroup:") {
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

    var spec: String { "\(target):\(ports)" }
}

extension Array where Element: Hashable {
    func uniqued() -> [Element] {
        var seen = Set<Element>()
        return filter { seen.insert($0).inserted }
    }
}
