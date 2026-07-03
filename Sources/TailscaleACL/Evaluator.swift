import Foundation

struct RuleMatch: Identifiable {
    var ruleIndex: Int
    var srcSpec: String
    var dstSpec: String

    var id: String { "\(ruleIndex)-\(srcSpec)-\(dstSpec)" }
}

struct AccessResult {
    var allowed: Bool
    var matches: [RuleMatch]
}

/// Evaluates Tailscale ACL semantics: default deny, "accept" rules only.
struct Evaluator {
    var model: PolicyModel

    /// sourceID: user email, tag name ("tag:web"), or host name.
    /// destID: tag name or host name. port: numeric destination port.
    func evaluate(sourceID: String, destID: String, port: Int) -> AccessResult {
        var matches: [RuleMatch] = []
        for rule in model.rules where rule.action == "accept" {
            for src in rule.src where sourceMatches(spec: src, sourceID: sourceID) {
                for dst in rule.dst {
                    let d = DestSpec(dst)
                    if targetMatches(target: d.target, destID: destID)
                        && portMatches(spec: d.ports, port: port) {
                        matches.append(RuleMatch(ruleIndex: rule.index, srcSpec: src, dstSpec: dst))
                    }
                }
            }
        }
        return AccessResult(allowed: !matches.isEmpty, matches: matches)
    }

    func sourceMatches(spec: String, sourceID: String) -> Bool {
        if spec == sourceID { return true }
        if spec == "*" { return true }
        if spec == "autogroup:members" || spec == "autogroup:member" {
            // Group members are tailnet users, so a group-as-source query
            // ("would a member of group:X be allowed?") is covered too.
            return sourceID.contains("@") || sourceID.hasPrefix("group:")
        }
        if spec.hasPrefix("group:") {
            return spec == sourceID || (model.groups[spec]?.contains(sourceID) ?? false)
        }
        if spec == sourceID { return true }
        // Host referenced by a CIDR host entry: spec is a host whose value is a
        // CIDR that contains sourceID's IP.
        if let cidr = model.hosts[spec], let ip = model.hosts[sourceID] {
            return cidrContains(cidr: cidr, ip: ip)
        }
        return false
    }

    func targetMatches(target: String, destID: String) -> Bool {
        if target == "*" { return true }
        if target == destID { return true }
        if target == "autogroup:members" || target == "autogroup:member" {
            return destID.contains("@") || destID.hasPrefix("group:")
        }
        if target.hasPrefix("group:") {
            return model.groups[target]?.contains(destID) ?? false
        }
        if let cidr = model.hosts[target], let ip = model.hosts[destID] {
            return cidrContains(cidr: cidr, ip: ip)
        }
        return false
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

    func cidrContains(cidr: String, ip: String) -> Bool {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2,
              let bits = Int(parts[1]), bits >= 0, bits <= 32,
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
    func runTests() -> [TestResult] {
        model.tests.map { test in
            var assertions: [TestAssertion] = []
            for entry in test.accept {
                let d = DestSpec(entry)
                let allowed = evaluate(sourceID: test.src, destID: d.target,
                                       port: Int(d.ports) ?? 0).allowed
                assertions.append(TestAssertion(kind: .accept, dst: entry, passed: allowed))
            }
            for entry in test.deny {
                let d = DestSpec(entry)
                let allowed = evaluate(sourceID: test.src, destID: d.target,
                                       port: Int(d.ports) ?? 0).allowed
                assertions.append(TestAssertion(kind: .deny, dst: entry, passed: !allowed))
            }
            return TestResult(testIndex: test.index, src: test.src, assertions: assertions)
        }
    }
}
