import Foundation

/// How network access between two real nodes differs between two policies.
struct AccessChange: Identifiable {
    var src: String
    var dst: String
    var gained: [String]
    var lost: [String]
    var sshGained: [String] = []
    var sshLost: [String] = []

    var id: String { "\(src)→\(dst)" }
}

/// Port label used for "any port not named explicitly in either policy".
let otherPortsLabel = "other ports"
/// SSH login label used for "any non-root account not named in either policy".
let otherLoginsLabel = "other users"

/// Diff node-to-node access between `old` and `new`.
/// ponytail: probes only ports named in either policy (singles and range
/// endpoints) plus one unnamed port standing in for "everything else", on
/// TCP/UDP; SSH is probed for root, every login named in either policy, and
/// one unnamed non-root login. A change strictly inside a port range, ICMP-only
/// rules, and accept↔check action changes are not detected.
func accessChanges(from old: PolicyModel, to new: PolicyModel,
                   nodes: [HeadscaleNode]) -> [AccessChange] {
    var named = mentionedPorts(old).union(mentionedPorts(new))
    let unnamed = (1...65535).first { !named.contains($0) } ?? 0
    named.insert(unnamed)
    let probes = named.sorted()

    let before = Evaluator(model: old)
    let after = Evaluator(model: new)
    func label(_ p: Int) -> String { p == unnamed ? otherPortsLabel : String(p) }

    var logins = Set((old.sshRules + new.sshRules).flatMap(\.users).filter { !$0.hasPrefix("autogroup:") })
    logins.insert("root")
    let unnamedLogin = "tailscale-acl-probe-user"
    let loginProbes = logins.sorted() + [unnamedLogin]
    func sshOK(_ ev: Evaluator, _ s: HeadscaleNode, _ d: HeadscaleNode, _ login: String) -> Bool {
        ev.sshNetworkAllowed(sourceIDs: s.identities, destIDs: d.identities)
            && !ev.evaluateSSH(sourceIDs: s.identities, destIDs: d.identities, login: login).isEmpty
    }

    var changes: [AccessChange] = []
    for s in nodes {
        for d in nodes where d.id != s.id {
            var gained: [String] = []
            var lost: [String] = []
            for p in probes {
                let was = before.evaluate(sourceIDs: s.identities, destIDs: d.identities, port: p).allowed
                let now = after.evaluate(sourceIDs: s.identities, destIDs: d.identities, port: p).allowed
                if now && !was { gained.append(label(p)) }
                if was && !now { lost.append(label(p)) }
            }
            var sshGained: [String] = []
            var sshLost: [String] = []
            for login in loginProbes {
                let was = sshOK(before, s, d, login)
                let now = sshOK(after, s, d, login)
                let name = login == unnamedLogin ? otherLoginsLabel : login
                if now && !was { sshGained.append(name) }
                if was && !now { sshLost.append(name) }
            }
            if !gained.isEmpty || !lost.isEmpty || !sshGained.isEmpty || !sshLost.isEmpty {
                changes.append(AccessChange(src: s.displayName, dst: d.displayName,
                                            gained: gained, lost: lost,
                                            sshGained: sshGained, sshLost: sshLost))
            }
        }
    }
    return changes
}

/// Every port number named in ACL dst specs or grant ip entries.
private func mentionedPorts(_ m: PolicyModel) -> Set<Int> {
    var specs = m.rules.flatMap { $0.dst.map { DestSpec($0).ports } }
    specs += m.grants.flatMap { $0.ip.map { $0.split(separator: ":").last.map(String.init) ?? $0 } }
    var ports = Set<Int>()
    for spec in specs {
        for part in spec.split(separator: ",") {
            for bound in part.split(separator: "-") {
                if let n = Int(bound.trimmingCharacters(in: .whitespaces)), (1...65535).contains(n) {
                    ports.insert(n)
                }
            }
        }
    }
    return ports
}

// MARK: - Rule summaries

/// One ACL, grant, or SSH rule, summarized for the access map and reports.
struct RuleSummary: Identifiable {
    enum Kind { case acl, grant, ssh }

    var kind: Kind
    var index: Int
    var name: String          // first comment line, or "Grant #3"-style fallback
    var badge: String         // ports / ip entries / SSH users
    var sources: [String]
    var destinations: [String] // targets, "host:" prefix removed

    var id: String { "\(kind)\(index)" }
    var section: String {
        switch kind {
        case .acl: return "acls"
        case .grant: return "grants"
        case .ssh: return "ssh"
        }
    }
}

/// Rules whose sources match any of `sourceIDs` (all rules when nil).
func ruleSummaries(_ m: PolicyModel, sourceIDs: [String]?) -> [RuleSummary] {
    let ev = Evaluator(model: m)
    func applies(_ src: [String]) -> Bool {
        guard let sourceIDs else { return true }
        return src.contains { spec in sourceIDs.contains { ev.sourceMatches(spec: spec, sourceID: $0) } }
    }
    func badge(_ entries: [String]) -> String {
        let e = entries.uniqued()
        return e == ["*"] ? "All" : e.map { $0 == "*" ? "all" : $0.uppercased() }.joined(separator: ", ")
    }
    func strip(_ t: String) -> String { t.hasPrefix("host:") ? String(t.dropFirst(5)) : t }

    var out: [RuleSummary] = []
    for r in m.rules where r.action == "accept" && applies(r.src) {
        out.append(RuleSummary(kind: .acl, index: r.index,
                               name: r.comments.first ?? "Rule #\(r.index + 1)",
                               badge: badge(r.dst.map { DestSpec($0).ports }), sources: r.src,
                               destinations: r.dst.map { strip(DestSpec($0).target) }.uniqued()))
    }
    for g in m.grants where applies(g.src) {
        out.append(RuleSummary(kind: .grant, index: g.index,
                               name: g.comments.first ?? "Grant #\(g.index + 1)",
                               badge: g.ip.isEmpty ? "APP" : badge(g.ip), sources: g.src,
                               destinations: g.dst.map(strip).uniqued()))
    }
    for s in m.sshRules where applies(s.src) {
        out.append(RuleSummary(kind: .ssh, index: s.index,
                               name: s.comments.first ?? "SSH rule #\(s.index + 1)",
                               badge: "SSH · \(s.users.joined(separator: ", "))", sources: s.src,
                               destinations: s.dst.map(strip).uniqued()))
    }
    return out
}

// MARK: - Line diff

struct DiffLine: Identifiable {
    enum Kind { case same, added, removed, skipped }
    var id: Int
    var kind: Kind
    var text: String
}

/// Unified line diff of `old` → `new`, keeping `context` unchanged lines
/// around each change and collapsing longer unchanged runs into one
/// `.skipped` line whose text is the number of lines hidden.
func lineDiff(old: String, new: String, context: Int = 3) -> [DiffLine] {
    let a = old.components(separatedBy: "\n")
    let b = new.components(separatedBy: "\n")
    let diff = b.difference(from: a)
    var removed = Set<Int>(), inserted = Set<Int>()
    for change in diff {
        switch change {
        case .remove(let offset, _, _): removed.insert(offset)
        case .insert(let offset, _, _): inserted.insert(offset)
        }
    }
    var full: [(DiffLine.Kind, String)] = []
    var i = 0, j = 0
    while i < a.count || j < b.count {
        if i < a.count, removed.contains(i) {
            full.append((.removed, a[i])); i += 1
        } else if j < b.count, inserted.contains(j) {
            full.append((.added, b[j])); j += 1
        } else {
            full.append((.same, a[i])); i += 1; j += 1
        }
    }
    let changed = full.indices.filter { full[$0].0 != .same }
    var keep = Set<Int>()
    for c in changed { keep.formUnion(max(0, c - context)...min(full.count - 1, c + context)) }

    var out: [DiffLine] = []
    var hidden = 0
    for (k, line) in full.enumerated() {
        if keep.contains(k) {
            if hidden > 0 { out.append(DiffLine(id: out.count, kind: .skipped, text: String(hidden))); hidden = 0 }
            out.append(DiffLine(id: out.count, kind: line.0, text: line.1))
        } else {
            hidden += 1
        }
    }
    if hidden > 0 { out.append(DiffLine(id: out.count, kind: .skipped, text: String(hidden))) }
    return out
}
