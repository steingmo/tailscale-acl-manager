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
            guard let posture = pendingPostures(rule.srcPosture) else { continue }
            for src in rule.src where sourceMatches(spec: src, sourceID: sourceID) {
                for dst in rule.dst {
                    let d = DestSpec(dst)
                    if targetMatches(target: d.target, destID: destID)
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
                for dst in grant.dst where targetMatches(target: dst, destID: destID) {
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
            portPart = String(spec[spec.index(after: colon)...])
        }
        if portPart == "*" { return true }
        return portMatches(spec: portPart, port: port)
    }

    /// "host:dc01" and "dc01" refer to the same host entity.
    private func stripHost(_ s: String) -> String {
        s.hasPrefix("host:") ? String(s.dropFirst(5)) : s
    }

    func sourceMatches(spec rawSpec: String, sourceID rawSource: String) -> Bool {
        let spec = stripHost(rawSpec)
        let sourceID = stripHost(rawSource)
        if spec == sourceID { return true }
        if spec == "*" { return true }
        if spec == "autogroup:members" || spec == "autogroup:member" {
            // Group members are tailnet users, so a group-as-source query
            // ("would a member of group:X be allowed?") is covered too.
            return sourceID.contains("@") || sourceID.hasPrefix("group:")
        }
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
        if target.hasPrefix("group:") {
            return model.groups[target]?.contains(destID) ?? false
        }
        return addressSelectorMatches(target, id: destID)
    }

    /// Does a host alias, IP set, or raw IP/CIDR selector contain the address
    /// of `id` (a host alias or a bare IP, e.g. a Headscale node's address)?
    private func addressSelectorMatches(_ selector: String, id: String) -> Bool {
        guard let ip = model.hosts[id] ?? (isAddressLike(id) ? id : nil) else { return false }
        if let cidr = model.hosts[selector] { return cidrContains(cidr: cidr, ip: ip) }
        if let entries = model.ipsets[selector] {
            return entries.contains { cidrContains(cidr: $0, ip: ip) }
        }
        return isAddressLike(selector) && cidrContains(cidr: selector, ip: ip)
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
        if spec == "*" { return true }
        if spec == "autogroup:members" || spec == "autogroup:member" {
            return row.hasPrefix("group:") || row.contains("@")
        }
        return false
    }

    // MARK: - IPv4 / CIDR

    /// `cidr` may be a bare IP (treated as /32) or "a.b.c.d/n".
    func cidrContains(cidr: String, ip: String) -> Bool {
        let parts = cidr.split(separator: "/")
        let bits = parts.count == 2 ? Int(parts[1]) ?? -1 : 32
        guard bits >= 0, bits <= 32,
              let base = ipv4(String(parts[0])),
              let addr = ipv4(ip.split(separator: "/").first.map(String.init) ?? ip)
        else { return false }
        let mask: UInt32 = bits == 0 ? 0 : ~UInt32(0) << (32 - bits)
        return (base & mask) == (addr & mask)
    }

    private func ipv4(_ s: String) -> UInt32? {
        let octets = s.split(separator: ".")
        guard octets.count == 4 else { return nil }
        var value: UInt32 = 0
        for o in octets {
            guard let byte = UInt32(o), byte <= 255 else { return nil }
            value = value << 8 | byte
        }
        return value
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
