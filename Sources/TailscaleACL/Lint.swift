import Foundation

struct LintIssue: Identifiable {
    enum Severity { case error, warning }

    var severity: Severity
    var title: String
    var detail: String

    var id: String { "\(severity)-\(title)-\(detail)" }
}

/// Offline structure checks: undefined references, ownerless tags, unused
/// entities, empty groups, invalid addresses/port specs, shadowed rules.
func lintPolicy(_ m: PolicyModel) -> [LintIssue] {
    var issues: [LintIssue] = []

    func isSelfEvident(_ name: String) -> Bool {
        name == "*" || name.contains("@") || name.hasPrefix("autogroup:")
            || name.hasPrefix("posture:") || isAddressLike(name)
    }

    // --- Undefined references -------------------------------------------
    var references: [(name: String, where_: String)] = []
    for r in m.rules {
        for s in r.src { references.append((s, "acls[\(r.index)].src")) }
        for d in r.dst { references.append((DestSpec(d).target, "acls[\(r.index)].dst")) }
    }
    for g in m.grants {
        for s in g.src { references.append((s, "grants[\(g.index)].src")) }
        for d in g.dst { references.append((d, "grants[\(g.index)].dst")) }
        for v in g.via { references.append((v, "grants[\(g.index)].via")) }
    }
    for s in m.sshRules {
        for x in s.src { references.append((x, "ssh[\(s.index)].src")) }
        for x in s.dst where x != "autogroup:self" {
            references.append((x, "ssh[\(s.index)].dst"))
        }
    }
    for t in m.tests {
        references.append((t.src, "tests[\(t.index)].src"))
        for e in t.accept + t.deny {
            references.append((DestSpec(e).target, "tests[\(t.index)]"))
        }
    }
    for (tag, owners) in m.tagOwners {
        for o in owners { references.append((o, "tagOwners[\(tag)]")) }
    }

    for (raw, where_) in references {
        let name = raw.hasPrefix("host:") ? String(raw.dropFirst(5)) : raw
        if isSelfEvident(name) { continue }
        if name.hasPrefix("group:") {
            if m.groups[name] == nil {
                issues.append(.init(severity: .error, title: "Undefined group",
                                    detail: "\(name) is referenced in \(where_) but not defined in \"groups\"."))
            }
        } else if name.hasPrefix("tag:") {
            if m.tagOwners[name] == nil {
                issues.append(.init(severity: .error, title: "Tag without owner",
                                    detail: "\(name) is referenced in \(where_) but has no entry in \"tagOwners\"."))
            }
        } else if name.hasPrefix("ipset:") {
            if m.ipsets[name] == nil {
                issues.append(.init(severity: .error, title: "Undefined IP set",
                                    detail: "\(name) is referenced in \(where_) but not defined in \"ipsets\"."))
            }
        } else if m.hosts[name] == nil {
            issues.append(.init(severity: .error, title: "Unknown host",
                                detail: "\"\(name)\" in \(where_) is not a host alias, tag, group, IP set, IP, or user."))
        }
    }

    // --- Unused entities --------------------------------------------------
    let referenced = Set(references.map {
        $0.name.hasPrefix("host:") ? String($0.name.dropFirst(5)) : $0.name
    })
    for g in m.groupOrder where !referenced.contains(g) {
        issues.append(.init(severity: .warning, title: "Unused group",
                            detail: "\(g) is defined but never used in any rule, grant, SSH rule, tag owner, or test."))
    }
    for t in m.tagOrder where !referenced.contains(t) {
        issues.append(.init(severity: .warning, title: "Unused tag",
                            detail: "\(t) has owners but is never used in any rule, grant, SSH rule, or test."))
    }
    for h in m.hostOrder where !referenced.contains(h) {
        issues.append(.init(severity: .warning, title: "Unused host",
                            detail: "Host \"\(h)\" is defined but never referenced."))
    }
    for s in m.ipsetOrder where !referenced.contains(s) {
        issues.append(.init(severity: .warning, title: "Unused IP set",
                            detail: "\(s) is defined but never referenced."))
    }

    // --- Empty groups ------------------------------------------------------
    for (name, members) in m.groups where members.isEmpty {
        issues.append(.init(severity: .warning, title: "Empty group",
                            detail: "\(name) has no members, so rules using it match nobody."))
    }

    // --- Invalid addresses and port specs -----------------------------------
    for (name, addr) in m.hosts where !isAddressLike(addr) {
        issues.append(.init(severity: .warning, title: "Invalid host address",
                            detail: "Host \"\(name)\" has value \"\(addr)\", which is not an IPv4 address or CIDR."))
    }
    for (name, entries) in m.ipsets {
        for e in entries where !isAddressLike(e) {
            issues.append(.init(severity: .warning, title: "Invalid IP set entry",
                                detail: "\(name) contains \"\(e)\", which is not an IPv4 address or CIDR."))
        }
    }
    for g in m.grants {
        for spec in g.ip where !isValidIPSpec(spec) {
            issues.append(.init(severity: .error, title: "Invalid grant ip entry",
                                detail: "grants[\(g.index)] has ip \"\(spec)\" — expected \"*\", a port, a range, or proto:port."))
        }
        if g.ip.isEmpty && !g.hasApp {
            issues.append(.init(severity: .error, title: "Grant grants nothing",
                                detail: "grants[\(g.index)] has neither \"ip\" nor \"app\", so it grants no access."))
        }
    }
    for r in m.rules {
        for d in r.dst {
            let ports = DestSpec(d).ports
            if !(ports == "*" || ports.split(separator: ",").allSatisfy { isValidPortToken(String($0)) }) {
                issues.append(.init(severity: .error, title: "Invalid ACL ports",
                                    detail: "acls[\(r.index)] dst \"\(d)\" has an invalid port list."))
            }
        }
    }

    // --- Duplicate / shadowed rules ------------------------------------------
    // ponytail: same-kind pairwise cover check only; no cross acl/grant analysis.
    func srcCovered(_ a: [String], by b: [String]) -> Bool {
        a.allSatisfy { x in
            b.contains { y in
                y == "*" || y == x
                    || ((y == "autogroup:members" || y == "autogroup:member")
                        && (x.contains("@") || x.hasPrefix("group:")))
            }
        }
    }
    for a in m.grants {
        for b in m.grants where b.index != a.index {
            guard srcCovered(a.src, by: b.src) else { continue }
            let dstCovered = a.dst.allSatisfy { x in
                b.dst.contains { $0 == "*" || $0 == x }
            }
            let ipCovered = b.ip.contains("*")
                || a.ip.allSatisfy { b.ip.contains($0) }
            if dstCovered && ipCovered && (b.index < a.index || !srcCovered(b.src, by: a.src)) {
                issues.append(.init(severity: .warning, title: "Shadowed grant",
                                    detail: "grants[\(a.index)] (\(a.src.joined(separator: ", ")) → \(a.dst.joined(separator: ", "))) is already fully covered by grants[\(b.index)]."))
            }
        }
    }
    for a in m.rules {
        for b in m.rules where b.index != a.index {
            guard srcCovered(a.src, by: b.src) else { continue }
            let covered = a.dst.allSatisfy { x in
                let xd = DestSpec(x)
                return b.dst.contains { y in
                    let yd = DestSpec(y)
                    return (yd.target == "*" || yd.target == xd.target)
                        && (yd.ports == "*" || yd.ports == xd.ports)
                }
            }
            if covered && (b.index < a.index || !srcCovered(b.src, by: a.src)) {
                issues.append(.init(severity: .warning, title: "Shadowed rule",
                                    detail: "acls[\(a.index)] is already fully covered by acls[\(b.index)]."))
            }
        }
    }

    return issues.sorted { a, b in
        if a.severity != b.severity { return a.severity == .error }
        return a.title < b.title
    }
}

// MARK: - Token validation

/// IPv4 address or CIDR ("10.0.0.1", "10.0.0.0/16").
func isAddressLike(_ s: String) -> Bool {
    let parts = s.split(separator: "/")
    guard parts.count <= 2, !parts.isEmpty else { return false }
    if parts.count == 2 {
        guard let bits = Int(parts[1]), (0...32).contains(bits) else { return false }
    }
    let octets = parts[0].split(separator: ".")
    return octets.count == 4 && octets.allSatisfy { Int($0).map { (0...255).contains($0) } ?? false }
}

private func isValidPortToken(_ s: String) -> Bool {
    let t = s.trimmingCharacters(in: .whitespaces)
    if let dash = t.firstIndex(of: "-") {
        return Int(t[..<dash]) != nil && Int(t[t.index(after: dash)...]) != nil
    }
    return Int(t) != nil
}

private let knownProtos: Set<String> = [
    "tcp", "udp", "icmp", "gre", "esp", "ah", "sctp", "igmp",
]

private func isValidIPSpec(_ spec: String) -> Bool {
    if spec == "*" { return true }
    if let colon = spec.firstIndex(of: ":") {
        let proto = String(spec[..<colon]).lowercased()
        guard knownProtos.contains(proto) || Int(proto).map({ (1...255).contains($0) }) == true else {
            return false
        }
        let rest = String(spec[spec.index(after: colon)...])
        return rest == "*" || isValidPortToken(rest)
    }
    return isValidPortToken(spec)
}
