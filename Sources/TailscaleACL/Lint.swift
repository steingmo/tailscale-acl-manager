import Foundation

struct LintIssue: Identifiable {
    enum Severity { case error, warning }

    var severity: Severity
    var title: String
    var detail: String
    /// One-click fixes, when the right fix is unambiguous.
    var fixes: [LintFix] = []
    /// Where in the policy, e.g. "grants[3].src" or "groups[group:eng]" (see JSON.line(at:)).
    var path: String?
    /// A line given directly (parse errors), when there is no path.
    var line: Int?

    var id: String { "\(severity)-\(title)-\(detail)" }
}

struct LintFix: Identifiable {
    enum Action {
        case addTagOwner(String)          // tagOwners[tag] = []
        case defineGroup(String)          // groups[group] = []
        case deleteEntity(String)         // definition + every reference
        case deleteRule(section: String, index: Int)
    }

    var label: String
    var action: Action
    var id: String { label }
}

/// Offline structure checks: undefined references, ownerless tags, unused
/// entities, empty groups, invalid addresses/port specs, shadowed rules,
/// postures, expiring rules, wide-open rules.
func lintPolicy(_ m: PolicyModel, now: Date = Date()) -> [LintIssue] {
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
    for (route, approvers) in m.routeApprovers {
        for a in approvers { references.append((a, "autoApprovers.routes[\(route)]")) }
    }
    for a in m.exitNodeApprovers { references.append((a, "autoApprovers.exitNode")) }
    for (name, entries) in m.ipsets {
        for e in entries.compactMap(IPSetEntry.init)
        where e.target.hasPrefix("host:") || e.target.hasPrefix("ipset:") {
            references.append((e.target, "ipsets[\(name)]"))
        }
    }
    for n in m.nodeAttrs {
        for t in n.target { references.append((t, "nodeAttrs[\(n.index)].target")) }
    }

    let knownAutogroups = Set(EditorVocabulary.autogroups.map(\.0) + ["autogroup:members"])
    for (raw, where_) in references {
        let name = raw.hasPrefix("host:") ? String(raw.dropFirst(5)) : raw
        if name.hasPrefix("autogroup:") {
            let side = where_.hasSuffix(".src") ? "src" : where_.hasSuffix(".dst") ? "dst" : nil
            if !knownAutogroups.contains(name) {
                issues.append(.init(severity: .error, title: "Unknown autogroup",
                                    detail: "\(name) in \(where_) is not a Tailscale autogroup.", path: where_))
            } else if name == "autogroup:nonroot" && side != nil {
                issues.append(.init(severity: .error, title: "Misplaced autogroup",
                                    detail: "autogroup:nonroot in \(where_) only works in an SSH rule's \"users\".", path: where_))
            } else if side == "src" && ["autogroup:self", "autogroup:internet"].contains(name) {
                issues.append(.init(severity: .error, title: "Misplaced autogroup",
                                    detail: "\(name) in \(where_) can only be a destination.", path: where_))
            } else if side == "dst" && ["autogroup:shared", "autogroup:danger-all"].contains(name) {
                issues.append(.init(severity: .error, title: "Misplaced autogroup",
                                    detail: "\(name) in \(where_) can only be a source.", path: where_))
            }
            continue
        }
        if isSelfEvident(name) { continue }
        if name.hasPrefix("group:") {
            if m.groups[name] == nil {
                issues.append(.init(severity: .error, title: "Undefined group",
                                    detail: "\(name) is referenced in \(where_) but not defined in \"groups\".",
                                    fixes: [.init(label: "Define empty group", action: .defineGroup(name)),
                                            .init(label: "Remove from rules", action: .deleteEntity(name))], path: where_))
            }
        } else if name.hasPrefix("tag:") {
            if m.tagOwners[name] == nil {
                issues.append(.init(severity: .error, title: "Tag without owner",
                                    detail: "\(name) is referenced in \(where_) but has no entry in \"tagOwners\".",
                                    fixes: [.init(label: "Add to tagOwners", action: .addTagOwner(name))], path: where_))
            }
        } else if name.hasPrefix("ipset:") {
            if m.ipsets[name] == nil {
                issues.append(.init(severity: .error, title: "Undefined IP set",
                                    detail: "\(name) is referenced in \(where_) but not defined in \"ipsets\".",
                                    fixes: [.init(label: "Remove from rules", action: .deleteEntity(name))], path: where_))
            }
        } else if m.hosts[name] == nil {
            issues.append(.init(severity: .error, title: "Unknown host",
                                detail: "\"\(name)\" in \(where_) is not a host alias, tag, group, IP set, IP, or user.", path: where_))
        }
    }

    // --- Unused entities --------------------------------------------------
    let referenced = Set(references.map {
        $0.name.hasPrefix("host:") ? String($0.name.dropFirst(5)) : $0.name
    })
    for g in m.groupOrder where !referenced.contains(g) {
        issues.append(.init(severity: .warning, title: "Unused group",
                            detail: "\(g) is defined but never used in any rule, grant, SSH rule, tag owner, or test.",
                            fixes: [.init(label: "Delete \(g)", action: .deleteEntity(g))], path: "groups[\(g)]"))
    }
    for t in m.tagOrder where !referenced.contains(t) {
        issues.append(.init(severity: .warning, title: "Unused tag",
                            detail: "\(t) has owners but is never used in any rule, grant, SSH rule, or test.",
                            fixes: [.init(label: "Delete \(t)", action: .deleteEntity(t))], path: "tagOwners[\(t)]"))
    }
    for h in m.hostOrder where !referenced.contains(h) {
        issues.append(.init(severity: .warning, title: "Unused host",
                            detail: "Host \"\(h)\" is defined but never referenced.",
                            fixes: [.init(label: "Delete \(h)", action: .deleteEntity(h))], path: "hosts[\(h)]"))
    }
    for s in m.ipsetOrder where !referenced.contains(s) {
        issues.append(.init(severity: .warning, title: "Unused IP set",
                            detail: "\(s) is defined but never referenced.",
                            fixes: [.init(label: "Delete \(s)", action: .deleteEntity(s))], path: "ipsets[\(s)]"))
    }

    // --- Empty groups ------------------------------------------------------
    for (name, members) in m.groups where members.isEmpty {
        issues.append(.init(severity: .warning, title: "Empty group",
                            detail: "\(name) has no members, so rules using it match nobody.", path: "groups[\(name)]"))
    }

    // --- Invalid addresses and port specs -----------------------------------
    for (name, addr) in m.hosts where !isAddressLike(addr) {
        issues.append(.init(severity: .warning, title: "Invalid host address",
                            detail: "Host \"\(name)\" has value \"\(addr)\", which is not an IP address or CIDR.", path: "hosts[\(name)]"))
    }
    for (name, entries) in m.ipsets {
        for e in entries where IPSetEntry(e) == nil {
            issues.append(.init(severity: .warning, title: "Invalid IP set entry",
                                detail: "\(name) contains \"\(e)\", which is not valid — expected an IP, CIDR, range (a-b), host:, ipset:, or autogroup:internet, optionally after add or remove.", path: "ipsets[\(name)]"))
        }
    }
    for g in m.grants {
        for spec in g.ip where !isValidIPSpec(spec) {
            issues.append(.init(severity: .error, title: "Invalid grant ip entry",
                                detail: "grants[\(g.index)] has ip \"\(spec)\" — expected \"*\", a port, a range, or proto:port.", path: "grants[\(g.index)].ip"))
        }
        if g.ip.isEmpty && !g.hasApp {
            issues.append(.init(severity: .error, title: "Grant grants nothing",
                                detail: "grants[\(g.index)] has neither \"ip\" nor \"app\", so it grants no access.", path: "grants[\(g.index)]"))
        }
    }
    for r in m.rules {
        for d in r.dst {
            let ports = DestSpec(d).ports
            if !(ports == "*" || ports.split(separator: ",").allSatisfy { isValidPortToken(String($0)) }) {
                issues.append(.init(severity: .error, title: "Invalid ACL ports",
                                    detail: "acls[\(r.index)] dst \"\(d)\" has an invalid port list.", path: "acls[\(r.index)].dst"))
            }
        }
    }

    // --- SSH rules -------------------------------------------------------------
    for r in m.sshRules where r.action == "check" && r.src.contains(where: { $0.hasPrefix("tag:") }) {
        issues.append(.init(severity: .error, title: "Check mode from tagged source",
                            detail: "ssh[\(r.index)] uses action \"check\" with a tagged source; Tailscale doesn't allow check mode from tagged devices.", path: "ssh[\(r.index)]"))
    }

    // --- Postures -------------------------------------------------------------
    var postureRefs: [(name: String, where_: String)] = m.defaultSrcPosture.map { ($0, "defaultSrcPosture") }
    for r in m.rules { postureRefs += r.srcPosture.map { ($0, "acls[\(r.index)].srcPosture") } }
    for g in m.grants { postureRefs += g.srcPosture.map { ($0, "grants[\(g.index)].srcPosture") } }
    for (name, where_) in postureRefs where m.postures[name] == nil {
        issues.append(.init(severity: .error, title: "Undefined posture",
                            detail: "\(name) is required in \(where_) but not defined in \"postures\", so no device can meet it.", path: where_))
    }
    for name in m.postureOrder {
        if !name.hasPrefix("posture:") {
            issues.append(.init(severity: .error, title: "Invalid posture name",
                                detail: "\"\(name)\" in \"postures\" must start with \"posture:\".", path: "postures[\(name)]"))
        }
        for c in m.postures[name] ?? [] where PostureCondition(c) == nil {
            issues.append(.init(severity: .error, title: "Invalid posture condition",
                                detail: "\(name) has \"\(c)\" — expected e.g. node:os == 'macos', node:tsVersion >= '1.60', or node:os IN ['macos', 'ios'].", path: "postures[\(name)]"))
        }
        if !postureRefs.contains(where: { $0.name == name }) {
            issues.append(.init(severity: .warning, title: "Unused posture",
                                detail: "\(name) is defined but no rule or defaultSrcPosture requires it.", path: "postures[\(name)]"))
        }
    }
    for g in m.grants {
        for v in g.via where !v.hasPrefix("tag:") {
            issues.append(.init(severity: .error, title: "Invalid via",
                                detail: "grants[\(g.index)] routes via \"\(v)\"; via only takes tags (of subnet routers, exit nodes, or app connectors).", path: "grants[\(g.index)].via"))
        }
    }

    // --- Expiring rules ----------------------------------------------------------
    let dated = m.rules.map { ("acls", $0.index, $0.expires) } + m.grants.map { ("grants", $0.index, $0.expires) }
        + m.sshRules.map { ("ssh", $0.index, $0.expires) }
    for (section, index, expires) in dated {
        guard let expires else { continue }
        guard let days = RuleExpiry.daysLeft(expires, now: now) else {
            issues.append(.init(severity: .warning, title: "Invalid expiry date",
                                detail: "\(section)[\(index)] has \"expires: \(expires)\", which is not a real date.", path: "\(section)[\(index)]"))
            continue
        }
        if days < 0 {
            issues.append(.init(severity: .warning, title: "Expired rule",
                                detail: "\(section)[\(index)] expired on \(expires) but still grants access.",
                                fixes: [.init(label: "Delete \(section)[\(index)]", action: .deleteRule(section: section, index: index))], path: "\(section)[\(index)]"))
        } else if days <= 7 {
            issues.append(.init(severity: .warning, title: "Rule expires soon",
                                detail: "\(section)[\(index)] expires on \(expires) (\(days == 0 ? "today" : "in \(days) day\(days == 1 ? "" : "s")")).", path: "\(section)[\(index)]"))
        }
    }

    // --- Wide-open rules ---------------------------------------------------------
    for r in m.rules where r.action == "accept" && r.src.contains("*") && r.dst.contains("*:*") {
        issues.append(.init(severity: .warning, title: "Allows everything",
                            detail: "acls[\(r.index)] lets every device reach every device on every port. Narrow it to the groups, tags, and ports that need access.", path: "acls[\(r.index)]"))
    }
    for g in m.grants where g.src.contains("*") && g.dst.contains("*") && g.ip.contains("*") {
        issues.append(.init(severity: .warning, title: "Allows everything",
                            detail: "grants[\(g.index)] lets every device reach every device on every port. Narrow it to the groups, tags, and ports that need access.", path: "grants[\(g.index)]"))
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
        // A posture-gated, routed, or expiring rule doesn't make another one redundant.
        for b in m.grants where b.index != a.index && b.srcPosture == a.srcPosture
            && b.via == a.via && (b.expires == nil || b.expires == a.expires) {
            guard srcCovered(a.src, by: b.src) else { continue }
            let dstCovered = a.dst.allSatisfy { x in
                b.dst.contains { $0 == "*" || $0 == x }
            }
            let ipCovered = b.ip.contains("*")
                || a.ip.allSatisfy { b.ip.contains($0) }
            if dstCovered && ipCovered && (b.index < a.index || !srcCovered(b.src, by: a.src)) {
                issues.append(.init(severity: .warning, title: "Shadowed grant",
                                    detail: "grants[\(a.index)] (\(a.src.joined(separator: ", ")) → \(a.dst.joined(separator: ", "))) is already fully covered by grants[\(b.index)].",
                                    fixes: [.init(label: "Delete grants[\(a.index)]", action: .deleteRule(section: "grants", index: a.index))], path: "grants[\(a.index)]"))
            }
        }
    }
    for a in m.rules {
        for b in m.rules where b.index != a.index && b.srcPosture == a.srcPosture
            && (b.expires == nil || b.expires == a.expires) {
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
                                    detail: "acls[\(a.index)] is already fully covered by acls[\(b.index)].",
                                    fixes: [.init(label: "Delete acls[\(a.index)]", action: .deleteRule(section: "acls", index: a.index))], path: "acls[\(a.index)]"))
            }
        }
    }

    return issues.sorted { a, b in
        if a.severity != b.severity { return a.severity == .error }
        return a.title < b.title
    }
}

// MARK: - Token validation

/// IPv4 or IPv6 address or CIDR ("10.0.0.1", "10.0.0.0/16", "fd7a:115c:a1e0::/48").
func isAddressLike(_ s: String) -> Bool { parseCIDR(s) != nil }

/// An address's bytes (4 or 16) and prefix length (full length if none given).
func parseCIDR(_ s: String) -> (bytes: [UInt8], bits: Int)? {
    let parts = s.split(separator: "/", omittingEmptySubsequences: false)
    guard parts.count <= 2, let bytes = ipBytes(String(parts[0])) else { return nil }
    guard parts.count == 2 else { return (bytes, bytes.count * 8) }
    guard let bits = Int(parts[1]), (0...bytes.count * 8).contains(bits) else { return nil }
    return (bytes, bits)
}

func ipBytes(_ s: String) -> [UInt8]? {
    var v4 = in_addr()
    if inet_pton(AF_INET, s, &v4) == 1 { return withUnsafeBytes(of: &v4) { Array($0) } }
    var v6 = in6_addr()
    if inet_pton(AF_INET6, s, &v6) == 1 { return withUnsafeBytes(of: &v6) { Array($0) } }
    return nil
}

/// Does `cidr` (an address or prefix) contain `ip` (an address, or a prefix's base)?
func cidrContains(cidr: String, ip: String) -> Bool {
    guard let net = parseCIDR(cidr), let addr = parseCIDR(ip), net.bytes.count == addr.bytes.count else { return false }
    for i in 0..<net.bytes.count {
        let bits = min(8, max(0, net.bits - i * 8))
        let mask: UInt8 = bits == 0 ? 0 : ~UInt8(0) << (8 - bits)
        if net.bytes[i] & mask != addr.bytes[i] & mask { return false }
    }
    return true
}

/// One "ipsets" entry: "[add|remove] <target>", where the target is an IP,
/// CIDR, range ("10.0.0.5-10.0.0.9"), host:name, ipset:name, or
/// autogroup:internet. Without an operation the entry is an add.
struct IPSetEntry {
    var remove: Bool
    var target: String

    init?(_ raw: String) {
        let words = raw.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        switch (words.count, words.first?.lowercased()) {
        case (1, _): (remove, target) = (false, words[0])
        case (2, "add"): (remove, target) = (false, words[1])
        case (2, "remove"): (remove, target) = (true, words[1])
        default: return nil
        }
        guard isAddressLike(target) || ipRange(target) != nil || target.hasPrefix("host:")
                || target.hasPrefix("ipset:") || target == "autogroup:internet" else { return nil }
    }
}

/// "10.0.0.5-10.0.0.9" (or IPv6) as byte bounds of one family.
func ipRange(_ s: String) -> (lo: [UInt8], hi: [UInt8])? {
    let ends = s.split(separator: "-", omittingEmptySubsequences: false)
    guard ends.count == 2, let lo = ipBytes(String(ends[0])), let hi = ipBytes(String(ends[1])),
          lo.count == hi.count else { return nil }
    return (lo, hi)
}

/// Public internet addresses (what autogroup:internet means): not private,
/// CGNAT/Tailscale, loopback, link-local, multicast, or reserved.
func isPublicAddress(_ s: String) -> Bool {
    guard let a = parseCIDR(s) else { return false }
    if a.bytes.count == 16 { return cidrContains(cidr: "2000::/3", ip: s) }
    return !["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
             "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3"].contains { cidrContains(cidr: $0, ip: s) }
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

// MARK: - Device checks (need nodes loaded from Headscale)

/// Checks that compare the policy against the real devices on the server.
func lintNodes(_ m: PolicyModel, nodes: [HeadscaleNode]) -> [LintIssue] {
    guard !nodes.isEmpty else { return [] }
    var issues: [LintIssue] = []
    let deviceTags = Set(nodes.flatMap(\.allTags))

    for tag in m.tagOrder where !deviceTags.contains(tag) {
        issues.append(.init(severity: .warning, title: "Tag not on any device",
                            detail: "\(tag) is defined in \"tagOwners\" but no current device carries it — possibly left over from a retired device.",
                            fixes: [.init(label: "Delete \(tag)", action: .deleteEntity(tag))], path: "tagOwners[\(tag)]"))
    }
    for node in nodes {
        for tag in node.allTags where m.tagOwners[tag] == nil {
            issues.append(.init(severity: .warning, title: "Undeclared device tag",
                                detail: "Device \(node.displayName) carries \(tag), which has no entry in \"tagOwners\".",
                                fixes: [.init(label: "Add to tagOwners", action: .addTagOwner(tag))]))
        }
    }

    // Rules whose sources, or whose device-type destinations, match no device.
    // Host aliases, IP sets, raw IPs, "*" and autogroup:internet are skipped:
    // they often point at subnet-routed machines that aren't Headscale nodes.
    let ev = Evaluator(model: m)
    func matchesSomeSource(_ spec: String) -> Bool {
        nodes.contains { n in n.identities.contains { ev.sourceMatches(spec: spec, sourceID: $0) } }
    }
    func isDeviceSelector(_ t: String) -> Bool {
        t.hasPrefix("tag:") || t.hasPrefix("group:") || t.contains("@")
            || t == "autogroup:member" || t == "autogroup:members" || t == "autogroup:tagged"
    }
    func matchesSomeDest(_ target: String) -> Bool {
        nodes.contains { n in n.identities.contains { ev.targetMatches(target: target, destID: $0) } }
    }
    func check(_ name: String, src: [String], dstTargets: [String]) {
        if !src.contains("*"), !src.contains(where: matchesSomeSource) {
            issues.append(.init(severity: .warning, title: "Rule matches no device",
                                detail: "No current device matches any source of \(name) (\(src.joined(separator: ", "))), so it never applies.", path: name))
        }
        let deviceDsts = dstTargets.filter(isDeviceSelector)
        if !deviceDsts.isEmpty, deviceDsts.count == dstTargets.count,
           !deviceDsts.contains(where: matchesSomeDest) {
            issues.append(.init(severity: .warning, title: "Rule reaches no device",
                                detail: "No current device matches any destination of \(name) (\(deviceDsts.joined(separator: ", "))).", path: name))
        }
    }
    for r in m.rules where r.action == "accept" {
        check("acls[\(r.index)]", src: r.src, dstTargets: r.dst.map { DestSpec($0).target })
    }
    for g in m.grants {
        check("grants[\(g.index)]", src: g.src, dstTargets: g.dst)
    }
    return issues
}
