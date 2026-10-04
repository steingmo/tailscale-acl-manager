import Foundation

struct RuleMatch: Identifiable {
    enum Kind { case acl, grant }

    var kind: Kind = .acl
    var ruleIndex: Int
    var srcSpec: String
    var dstSpec: String
    var ipSpec: String?
    /// Postures the source must meet (any one) for this match to apply,
    /// when the evaluator can't tell whether it does. Empty: unconditional.
    var posture: [String] = []
    /// Grant `via`: tags of the routers or exit nodes the traffic goes through.
    var via: [String] = []

    var id: String { "\(kind)-\(ruleIndex)-\(srcSpec)-\(dstSpec)-\(ipSpec ?? "")" }
}

struct AccessResult {
    var allowed: Bool
    var matches: [RuleMatch]

    /// Allowed only if the source device meets a posture.
    var conditional: Bool { allowed && matches.allSatisfy { !$0.posture.isEmpty } }
    var postures: [String] { matches.flatMap(\.posture).uniqued() }
}

/// Evaluates Tailscale ACL semantics: default deny, "accept" rules only.
struct Evaluator {
    var model: PolicyModel
    /// The source device's posture attributes ("node:os" → "macos"), if known.
    /// nil: rules with posture conditions match, marked as conditional.
    var sourceAttributes: [String: String]? = nil
    /// The attributes are the device's full set (a test's srcPostureAttrs),
    /// so a missing attribute is unset rather than unknown.
    var attributesComplete = false
    /// The query's IP protocol (6 TCP, 17 UDP) when known, e.g. for real
    /// traffic; nil asks about TCP or UDP alike, as the Simulator does.
    var proto: Int? = nil

    /// "tcp"/"udp"/"6" → IANA number.
    static func protoNumber(_ s: String) -> Int? {
        ["tcp": 6, "udp": 17, "icmp": 1, "sctp": 132][s.lowercased()] ?? Int(s)
    }

    /// Postures still in question for a rule: [] when none is required or one
    /// is met, nil when the source can't meet any (the rule doesn't apply).
    func pendingPostures(_ own: [String]) -> [String]? {
        let required = own.isEmpty ? model.defaultSrcPosture : own
        guard !required.isEmpty else { return [] }
        guard let attrs = sourceAttributes else { return required }
        var unknown: [String] = []
        for name in required {
            guard let conditions = model.postures[name] else { continue }
            switch postureHolds(conditions, attrs: attrs, complete: attributesComplete) {
            case true?: return []
            case nil: unknown.append(name)
            case false?: break
            }
        }
        return unknown.isEmpty ? nil : unknown
    }

    /// sourceID: user email, tag name ("tag:web"), or host name.
    /// destID: tag name or host name. port: numeric destination port.
    func evaluate(sourceID: String, destID: String, port: Int) -> AccessResult {
        var matches: [RuleMatch] = []
        for rule in model.rules where rule.action == "accept" {
            // Port queries are TCP/UDP, like grants' proto:port entries.
            if let proto = rule.proto?.lowercased(), !["tcp", "udp", "6", "17"].contains(proto) { continue }
            if let q = self.proto, let p = rule.proto.flatMap(Self.protoNumber), p != q { continue }
            guard let posture = pendingPostures(rule.srcPosture) else { continue }
            for src in rule.src where sourceMatches(spec: src, sourceID: sourceID) {
                for dst in rule.dst {
                    let d = DestSpec(dst)
                    if destMatches(d.target, sourceID: sourceID, destID: destID)
                        && portMatches(spec: d.ports, port: port) {
                        matches.append(RuleMatch(kind: .acl, ruleIndex: rule.index,
                                                 srcSpec: src, dstSpec: dst, posture: posture))
                    }
                }
            }
        }
        // Grants: app-only grants (empty ip) confer no network-layer access.
        for grant in model.grants {
            guard let posture = pendingPostures(grant.srcPosture) else { continue }
            for src in grant.src where sourceMatches(spec: src, sourceID: sourceID) {
                for dst in grant.dst where destMatches(dst, sourceID: sourceID, destID: destID) {
                    for spec in grant.ip where ipSpecMatches(spec: spec, port: port) {
                        matches.append(RuleMatch(kind: .grant, ruleIndex: grant.index,
                                                 srcSpec: src, dstSpec: dst, ipSpec: spec,
                                                 posture: posture, via: grant.via))
                    }
                }
            }
        }
        return AccessResult(allowed: !matches.isEmpty, matches: matches)
    }

    /// A real node matches as any of its identities (tags or user, plus IPs);
    /// matches are merged across all identity pairs.
    func evaluate(sourceIDs: [String], destIDs: [String], port: Int) -> AccessResult {
        var seen = Set<String>()
        var matches: [RuleMatch] = []
        for s in sourceIDs {
            for d in destIDs {
                for m in evaluate(sourceID: s, destID: d, port: port).matches
                where seen.insert(m.id).inserted {
                    matches.append(m)
                }
            }
        }
        return AccessResult(allowed: !matches.isEmpty, matches: matches)
    }

    /// Grant `ip` entries: "*", "443", "80-443", "proto:*", "proto:443",
    /// "proto:80-443". The simulator queries TCP/UDP-style ports, so specs
    /// pinned to other protocols (icmp, gre, …) don't match a port query.
    func ipSpecMatches(spec: String, port: Int) -> Bool {
        var portPart = spec
        if let colon = spec.firstIndex(of: ":") {
            let proto = String(spec[..<colon]).lowercased()
            guard ["tcp", "udp", "6", "17"].contains(proto) else { return false }
            if let q = self.proto, Self.protoNumber(proto) != q { return false }
            portPart = String(spec[spec.index(after: colon)...])
        }
        if portPart == "*" { return true }
        return portMatches(spec: portPart, port: port)
    }

    /// "host:dc01" and "dc01" refer to the same host entity.
    private func stripHost(_ s: String) -> String {
        s.hasPrefix("host:") ? String(s.dropFirst(5)) : s
    }

    /// Role-based autogroups: they match users the server says hold the
    /// role (Tailscale), or the role itself when simulated as the source.
    static let roleAutogroups: Set<String> = [
        "autogroup:owner", "autogroup:admin", "autogroup:it-admin", "autogroup:network-admin",
        "autogroup:billing-admin", "autogroup:auditor",
    ]

    func sourceMatches(spec rawSpec: String, sourceID rawSource: String) -> Bool {
        let spec = stripHost(rawSpec)
        let sourceID = stripHost(rawSource)
        if spec == sourceID { return true }
        if spec == "*" || spec == "autogroup:danger-all" { return true }
        if spec == "autogroup:members" || spec == "autogroup:member" {
            // Group members are tailnet users, so a group-as-source query
            // ("would a member of group:X be allowed?") is covered too; so is
            // a role, since everyone with a role is a member. Users shared
            // in from another tailnet aren't members.
            if serverAutogroups(sourceID).contains("autogroup:shared") { return false }
            return sourceID.contains("@") || sourceID.hasPrefix("group:") || Self.roleAutogroups.contains(sourceID)
        }
        if serverAutogroups(sourceID).contains(spec) { return true }
        if spec == "autogroup:tagged" { return sourceID.hasPrefix("tag:") }
        if spec.hasPrefix("group:") {
            return model.groups[spec]?.contains(sourceID) ?? false
        }
        return addressSelectorMatches(spec, id: sourceID)
    }

    func targetMatches(target rawTarget: String, destID rawDest: String) -> Bool {
        let target = stripHost(rawTarget)
        let destID = stripHost(rawDest)
        if target == "*" { return true }
        if target == destID { return true }
        if target == "autogroup:members" || target == "autogroup:member" {
            return destID.contains("@") || destID.hasPrefix("group:")
        }
        if target == "autogroup:tagged" { return destID.hasPrefix("tag:") }
        if target == "autogroup:internet" { return isPublicAddress(destID) }
        if serverAutogroups(destID).contains(target) { return true }
        if target.hasPrefix("group:") {
            return model.groups[target]?.contains(destID) ?? false
        }
        return addressSelectorMatches(target, id: destID)
    }

    /// Role autogroups the server says a user holds.
    private func serverAutogroups(_ id: String) -> Set<String> {
        id.contains("@") ? model.userAutogroups[id.lowercased()] ?? [] : []
    }

    /// A rule destination, including autogroup:self: the source user's own
    /// devices, i.e. the same user on both ends.
    func destMatches(_ target: String, sourceID: String, destID: String) -> Bool {
        target == "autogroup:self" ? sourceID == destID && sourceID.contains("@")
            : targetMatches(target: target, destID: destID)
    }

    /// Does a host alias, IP set, or raw IP/CIDR selector contain the address
    /// of `id` (a host alias or a bare IP, e.g. a Headscale node's address)?
    private func addressSelectorMatches(_ selector: String, id: String) -> Bool {
        guard let ip = model.hosts[id] ?? (isAddressLike(id) ? id : nil) else { return false }
        if let cidr = model.hosts[selector] { return cidrContains(cidr: cidr, ip: ip) }
        if model.ipsets[selector] != nil { return ipsetContains(selector, ip: ip) }
        return isAddressLike(selector) && cidrContains(cidr: selector, ip: ip)
    }

    /// Entries apply in order ("add 10.0.0.0/8", "remove 10.0.0.33"), so the
    /// last entry covering the address decides. `visiting` stops ipset cycles.
    func ipsetContains(_ name: String, ip: String, visiting: Set<String> = []) -> Bool {
        guard let entries = model.ipsets[name], !visiting.contains(name) else { return false }
        var member = false
        for entry in entries.compactMap(IPSetEntry.init) {
            let t = entry.target
            let covers: Bool
            if t.hasPrefix("ipset:") {
                covers = ipsetContains(t, ip: ip, visiting: visiting.union([name]))
            } else if t == "autogroup:internet" {
                covers = isPublicAddress(ip)
            } else if let r = ipRange(t), let a = parseCIDR(ip)?.bytes, a.count == r.lo.count {
                covers = !a.lexicographicallyPrecedes(r.lo) && !r.hi.lexicographicallyPrecedes(a)
            } else {
                let cidr = t.hasPrefix("host:") ? model.hosts[String(t.dropFirst(5))] ?? "" : t
                covers = cidrContains(cidr: cidr, ip: ip)
            }
            if covers { member = !entry.remove }
        }
        return member
    }

    func portMatches(spec: String, port: Int) -> Bool {
        if spec == "*" { return true }
        for part in spec.split(separator: ",") {
            if let dash = part.firstIndex(of: "-") {
                let lo = Int(part[..<dash]) ?? -1
                let hi = Int(part[part.index(after: dash)...]) ?? -1
                if port >= lo && port <= hi { return true }
            } else if Int(part) == port {
                return true
            }
        }
        return false
    }

    /// Does `spec` (a src spec) cover the entity `row` (a group/tag/autogroup/*)?
    /// Used by the access matrix, where rows are entities rather than identities.
    func sourceSpecCovers(spec: String, row: String) -> Bool {
        if spec == row { return true }
        if spec == "*" || spec == "autogroup:danger-all" { return true }
        if spec == "autogroup:tagged" { return row.hasPrefix("tag:") }
        if spec == "autogroup:members" || spec == "autogroup:member" {
            return row.hasPrefix("group:") || row.contains("@")
        }
        return false
    }

}

// MARK: - Test running

struct TestAssertion: Identifiable {
    var kind: Kind
    var dst: String
    var passed: Bool

    enum Kind { case accept, deny }

    var id: String { "\(kind)-\(dst)" }
}

extension TestAssertion {
    enum SSHKind: String { case accept, check, deny }
}

struct SSHTestAssertion: Identifiable {
    var dst: String
    var login: String
    var expected: TestAssertion.SSHKind
    var actual: TestAssertion.SSHKind
    var passed: Bool { expected == actual }
    var id: String { "\(dst)-\(login)-\(expected)" }
}

struct SSHTestResult: Identifiable {
    var testIndex: Int
    var src: String
    var assertions: [SSHTestAssertion]
    var passed: Bool { assertions.allSatisfy(\.passed) }
    var id: Int { testIndex }
}

struct TestResult: Identifiable {
    var testIndex: Int
    var src: String
    var assertions: [TestAssertion]

    var passed: Bool { assertions.allSatisfy(\.passed) }
    var id: Int { testIndex }
}

extension Evaluator {
    /// Like Tailscale, a test device has only the posture attributes the test
    /// gives it (srcPostureAttrs), so posture-gated rules need them to pass.
    func runTests() -> [TestResult] {
        model.tests.map { test in
            let ev = Evaluator(model: model, sourceAttributes: test.srcPostureAttrs ?? [:], attributesComplete: true)
            var assertions: [TestAssertion] = []
            for entry in test.accept {
                let d = DestSpec(entry)
                let allowed = ev.evaluate(sourceID: test.src, destID: d.target,
                                          port: Int(d.ports) ?? 0).allowed
                assertions.append(TestAssertion(kind: .accept, dst: entry, passed: allowed))
            }
            for entry in test.deny {
                let d = DestSpec(entry)
                let allowed = ev.evaluate(sourceID: test.src, destID: d.target,
                                          port: Int(d.ports) ?? 0).allowed
                assertions.append(TestAssertion(kind: .deny, dst: entry, passed: !allowed))
            }
            return TestResult(testIndex: test.index, src: test.src, assertions: assertions)
        }
    }
}

// MARK: - SSH

struct SSHMatch: Identifiable {
    var ruleIndex: Int
    var action: String   // "accept" or "check"
    var srcSpec: String
    var dstSpec: String

    var id: String { "\(ruleIndex)-\(srcSpec)-\(dstSpec)" }
}

extension Evaluator {
    /// SSH rules letting `sourceIDs` log in to `destIDs` as `login`. Tailscale
    /// also requires network access to the device (see `sshNetworkAllowed`).
    func evaluateSSH(sourceIDs: [String], destIDs: [String], login: String) -> [SSHMatch] {
        var matches: [SSHMatch] = []
        for rule in model.sshRules where loginAllowed(login, users: rule.users) {
            for src in rule.src where sourceIDs.contains(where: { sourceMatches(spec: src, sourceID: $0) }) {
                for dst in rule.dst where sshDestMatches(dst, sourceIDs: sourceIDs, destIDs: destIDs) {
                    matches.append(SSHMatch(ruleIndex: rule.index, action: rule.action,
                                            srcSpec: src, dstSpec: dst))
                }
            }
        }
        return matches
    }

    /// Network access for SSH: the session runs over TCP 22.
    func sshNetworkAllowed(sourceIDs: [String], destIDs: [String]) -> Bool {
        evaluate(sourceIDs: sourceIDs, destIDs: destIDs, port: 22).allowed
    }

    /// How SSH rules treat `login` from `src` to `dst`: accept, check, or deny.
    /// Like Tailscale's sshTests, only SSH rules are consulted (not network access).
    func sshOutcome(src: String, dst: String, login: String) -> TestAssertion.SSHKind {
        let matches = evaluateSSH(sourceIDs: [src], destIDs: [dst], login: login)
        if matches.contains(where: { $0.action == "accept" }) { return .accept }
        return matches.isEmpty ? .deny : .check
    }

    func runSSHTests() -> [SSHTestResult] {
        model.sshTests.map { test in
            var assertions: [SSHTestAssertion] = []
            for dst in test.dst {
                for (kind, logins) in [(TestAssertion.SSHKind.accept, test.accept), (.check, test.check), (.deny, test.deny)] {
                    for login in logins {
                        assertions.append(SSHTestAssertion(dst: dst, login: login, expected: kind,
                                                           actual: sshOutcome(src: test.src, dst: dst, login: login)))
                    }
                }
            }
            return SSHTestResult(testIndex: test.index, src: test.src, assertions: assertions)
        }
    }

    func loginAllowed(_ login: String, users: [String]) -> Bool {
        users.contains(login) || (users.contains("autogroup:nonroot") && login != "root")
    }

    private func sshDestMatches(_ spec: String, sourceIDs: [String], destIDs: [String]) -> Bool {
        if spec == "autogroup:self" {
            // Your own untagged devices: same user on both ends, neither tagged.
            let tagged = { (ids: [String]) in ids.contains { $0.hasPrefix("tag:") } }
            guard !tagged(sourceIDs), !tagged(destIDs) else { return false }
            let users = { (ids: [String]) in Set(ids.filter { !$0.contains(":") && !isAddressLike($0) }) }
            return !users(sourceIDs).isDisjoint(with: users(destIDs))
        }
        return destIDs.contains { targetMatches(target: spec, destID: $0) }
    }
}
