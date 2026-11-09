import Foundation

// One plain sentence per rule: who can reach what, on which services, and
// under which conditions.

/// "a", "a and b", "a, b and c".
private func listed(_ items: [String], _ word: String = "and") -> String {
    let items = items.uniqued()
    guard items.count > 1 else { return items.first ?? "" }
    return items.dropLast().joined(separator: ", ") + " \(word) " + items[items.count - 1]
}

private let serviceNames: [Int: String] = [
    22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 88: "Kerberos", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    636: "LDAPS", 1433: "SQL Server", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5985: "WinRM",
    5986: "WinRM", 6379: "Redis", 27017: "MongoDB",
]

private func afterPrefix(_ s: String, _ prefix: String) -> String { String(s.dropFirst(prefix.count)) }

/// A source, as the subject of a sentence.
private func who(_ src: String, _ m: PolicyModel) -> String {
    switch src {
    case "*": return "everyone"
    case "autogroup:member": return "every member of the tailnet"
    case "autogroup:tagged": return "all tagged devices"
    case "autogroup:shared": return "people the tailnet is shared with"
    case "autogroup:danger-all": return "anyone, including devices outside the tailnet"
    default: break
    }
    if src.hasPrefix("autogroup:") { return "users with the \(afterPrefix(src, "autogroup:")) role" }
    if src.hasPrefix("group:") { return "everyone in \(afterPrefix(src, "group:"))" }
    if src.hasPrefix("tag:") { return "devices tagged \(afterPrefix(src, "tag:"))" }
    return place(src, m)
}

/// A destination, as the object of "can reach".
private func place(_ dst: String, _ m: PolicyModel) -> String {
    switch dst {
    case "*": return "anything"
    case "autogroup:internet": return "the internet through exit nodes"
    case "autogroup:self": return "their own devices"
    case "autogroup:member": return "members' devices"
    case "autogroup:tagged": return "all tagged devices"
    default: break
    }
    if dst.hasPrefix("tag:") { return "devices tagged \(afterPrefix(dst, "tag:"))" }
    if dst.hasPrefix("group:") { return "the devices of people in \(afterPrefix(dst, "group:"))" }
    if dst.hasPrefix("ipset:") { return "the addresses in \(afterPrefix(dst, "ipset:"))" }
    let name = dst.hasPrefix("host:") ? afterPrefix(dst, "host:") : dst
    if let address = m.hosts[name] { return "\(name) (\(address))" }
    return name
}

/// Port specs ("22,443", "8000-8100", "tcp:22", "icmp:*", "*") as services;
/// nil means everything.
private func services(_ specs: [String]) -> String? {
    var names: [String] = []
    for spec in specs.flatMap({ $0.split(separator: ",").map(String.init) }) {
        let parts = spec.split(separator: ":", maxSplits: 1).map(String.init)
        let proto = parts.count == 2 ? parts[0].lowercased() : nil
        let ports = parts.last ?? spec
        if ports == "*" {
            guard let proto else { return nil }
            names.append(proto == "icmp" ? "ping" : "any \(proto.uppercased()) port")
        } else if let port = Int(ports) {
            names.append(serviceNames[port] ?? "\(proto.map { $0.uppercased() + " " } ?? "")port \(port)")
        } else {
            names.append("\(proto.map { $0.uppercased() + " " } ?? "")ports \(ports)")
        }
    }
    return names.isEmpty ? nil : listed(names)
}

private func conditions(posture: [String], via: [String], expires: String?, _ m: PolicyModel) -> String {
    var out = ""
    let required = posture.isEmpty ? m.defaultSrcPosture : posture
    if !required.isEmpty {
        let names = required.map { $0.hasPrefix("posture:") ? afterPrefix($0, "posture:") : $0 }
        out += ", only from devices that pass the \(listed(names, "or")) posture check"
    }
    if !via.isEmpty { out += ", routed through \(listed(via.map { who($0, m) }, "or"))" }
    out += "."
    if let expires, let days = RuleExpiry.daysLeft(expires) {
        out += days < 0 ? " Expired on \(expires)." : " Expires on \(expires)."
    }
    return out
}

private func sentence(_ s: String) -> String { s.prefix(1).uppercased() + s.dropFirst() }

/// One sentence for the rule at `index` in "acls", "grants", or "ssh"; nil if
/// there's no such rule.
func ruleExplanation(_ m: PolicyModel, kind: RuleSummary.Kind, index: Int) -> String? {
    switch kind {
    case .acl:
        guard let r = m.rules.first(where: { $0.index == index }) else { return nil }
        // Destinations grouped by their ports: "X and Y on SSH, and Z on HTTPS".
        var groups: [(ports: String, targets: [String])] = []
        for d in r.dst.map(DestSpec.init) {
            if let i = groups.firstIndex(where: { $0.ports == d.ports }) { groups[i].targets.append(d.target) }
            else { groups.append((d.ports, [d.target])) }
        }
        let proto = r.proto.map { " over \($0)" } ?? ""
        let reach = groups.map { g in
            listed(g.targets.map { place($0, m) }) + (services([g.ports]).map { " on \($0)" } ?? " on any port") + proto
        }
        return sentence("\(listed(r.src.map { who($0, m) })) can reach \(listed(reach))"
                        + conditions(posture: r.srcPosture, via: [], expires: r.expires, m))
    case .grant:
        guard let g = m.grants.first(where: { $0.index == index }) else { return nil }
        let subject = listed(g.src.map { who($0, m) }), object = listed(g.dst.map { place($0, m) })
        let tail = conditions(posture: g.srcPosture, via: g.via, expires: g.expires, m)
        if g.ip.isEmpty {
            return sentence("\(subject) get app capabilities on \(object) — no network access by itself\(tail)")
        }
        return sentence("\(subject) can reach \(object)" + (services(g.ip).map { " on \($0)" } ?? " on any port")
                        + (g.hasApp ? ", with app capabilities" : "") + tail)
    case .ssh:
        guard let s = m.sshRules.first(where: { $0.index == index }) else { return nil }
        let users = s.users.map { $0 == "autogroup:nonroot" ? "any user except root" : $0 == "*" ? "any user" : $0 }
        return sentence("\(listed(s.src.map { who($0, m) })) can SSH into \(listed(s.dst.map { place($0, m) })) as \(listed(users, "or"))"
                        + (s.action == "check" ? ", after signing in again" : "")
                        + conditions(posture: [], via: [], expires: s.expires, m))
    }
}
