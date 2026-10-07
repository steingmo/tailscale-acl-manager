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
/// Ports are compared exactly: every port range named in either policy is cut
/// into intervals where access can't vary, and one port per interval is
/// probed. Ranges not named anywhere collapse into "other ports". SSH is
/// probed for root, every login named in either policy, and one unnamed
/// non-root login. ICMP-only rules and accept↔check changes aren't compared.
func accessChanges(from old: PolicyModel, to new: PolicyModel,
                   nodes: [HeadscaleNode]) -> [AccessChange] {
    let intervals = portIntervals([old, new])
    let before = Evaluator(model: old)
    let after = Evaluator(model: new)

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
            var gained: [PortInterval] = []
            var lost: [PortInterval] = []
            for iv in intervals {
                let p = iv.range.lowerBound
                let was = before.evaluate(sourceIDs: s.identities, destIDs: d.identities, port: p).allowed
                let now = after.evaluate(sourceIDs: s.identities, destIDs: d.identities, port: p).allowed
                if now && !was { gained.append(iv) }
                if was && !now { lost.append(iv) }
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
                                            gained: portLabels(gained), lost: portLabels(lost),
                                            sshGained: sshGained, sshLost: sshLost))
            }
        }
    }
    return changes
}

/// Where two policies disagree, by policy entity rather than device: every
/// source (users, groups, tags, hosts, autogroups) × destination × port
/// interval, plus posture conditions. Empty means the same access.
func entityAccessDifferences(_ old: PolicyModel, _ new: PolicyModel, limit: Int = 20) -> [String] {
    let ports = portIntervals([old, new])
    // Every name any rule uses as a source, users named directly included.
    let named = [old, new].flatMap { $0.rules.flatMap(\.src) + $0.grants.flatMap(\.src) }
    let srcs = ([old, new].flatMap { $0.sourceSpecs + $0.allUsers + $0.tagOrder + $0.hostOrder } + named).uniqued()
    let dsts = ([old, new].flatMap { $0.destTargets + $0.allUsers } + named.filter { $0.contains("@") }).uniqued()
    let before = Evaluator(model: old), after = Evaluator(model: new)
    var out: [String] = []
    for s in srcs {
        for d in dsts {
            for iv in ports {
                let a = before.evaluate(sourceID: s, destID: d, port: iv.range.lowerBound)
                let b = after.evaluate(sourceID: s, destID: d, port: iv.range.lowerBound)
                guard a.allowed != b.allowed || Set(a.postures) != Set(b.postures) else { continue }
                let port = portLabels([iv]).first ?? ""
                out.append("\(s) → \(d):\(port): \(a.allowed ? "allowed" : "denied") before, \(b.allowed ? "allowed" : "denied") after")
                if out.count >= limit { return out }
            }
        }
    }
    return out
}

// MARK: - Port intervals

/// A run of ports over which every rule in the compared policies agrees.
struct PortInterval {
    var range: ClosedRange<Int>
    /// False for gaps no policy names (they only matter via wildcards).
    var named: Bool
}

/// Cut 1...65535 at every boundary of every port range named in `models`.
func portIntervals(_ models: [PolicyModel]) -> [PortInterval] {
    let ranges = models.flatMap(mentionedPortRanges)
    var cuts: Set<Int> = [1, 65536]
    for r in ranges {
        cuts.insert(r.lowerBound)
        cuts.insert(r.upperBound + 1)
    }
    let sorted = cuts.sorted()
    return zip(sorted, sorted.dropFirst()).map { lo, next in
        // Intervals are atomic, so one contained port decides membership.
        PortInterval(range: lo...(next - 1), named: ranges.contains { $0.contains(lo) })
    }
}

/// "22", "8101-8200", adjacent named intervals merged; unnamed ones become
/// a single "other ports" label.
func portLabels(_ intervals: [PortInterval]) -> [String] {
    var merged: [ClosedRange<Int>] = []
    var other = false
    for iv in intervals {
        guard iv.named else { other = true; continue }
        if let last = merged.last, last.upperBound + 1 == iv.range.lowerBound {
            merged[merged.count - 1] = last.lowerBound...iv.range.upperBound
        } else {
            merged.append(iv.range)
        }
    }
    var labels = merged.map { $0.count == 1 ? String($0.lowerBound) : "\($0.lowerBound)-\($0.upperBound)" }
    if other { labels.append(otherPortsLabel) }
    return labels
}

/// Every port range named in ACL dst specs or grant ip entries.
func mentionedPortRanges(_ m: PolicyModel) -> [ClosedRange<Int>] {
    var specs = m.rules.flatMap { $0.dst.map { DestSpec($0).ports } }
    specs += m.grants.flatMap { $0.ip.map { $0.split(separator: ":").last.map(String.init) ?? $0 } }
    var ranges: [ClosedRange<Int>] = []
    for spec in specs {
        for part in spec.split(separator: ",") {
            let bounds = part.split(separator: "-").compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }
            guard let lo = bounds.first, let hi = bounds.last, 1 <= lo, lo <= hi, hi <= 65535 else { continue }
            ranges.append(lo...hi)
        }
    }
    return ranges
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
    /// Posture requirement, routing, and expiry, e.g. ["if posture:mac", "via tag:exit"].
    var notes: [String] = []

    var id: String { "\(kind)\(index)" }
    var section: String {
        switch kind {
        case .acl: return "acls"
        case .grant: return "grants"
        case .ssh: return "ssh"
        }
    }
}

/// Rules whose sources match any of `sourceIDs` and whose destinations match
/// any of `destIDs` (nil means no filter on that side).
func ruleSummaries(_ m: PolicyModel, sourceIDs: [String]?, destIDs: [String]? = nil) -> [RuleSummary] {
    let ev = Evaluator(model: m)
    func applies(_ src: [String]) -> Bool {
        guard let sourceIDs else { return true }
        return src.contains { spec in sourceIDs.contains { ev.sourceMatches(spec: spec, sourceID: $0) } }
    }
    func reaches(_ targets: [String], ssh: Bool = false) -> Bool {
        guard let destIDs else { return true }
        return targets.contains { t in
            // autogroup:self only ever means "the user's own devices".
            ssh && t == "autogroup:self" ? destIDs.contains { $0.contains("@") }
                : destIDs.contains { ev.targetMatches(target: t, destID: $0) }
        }
    }
    func badge(_ entries: [String]) -> String {
        let e = entries.uniqued()
        return e == ["*"] ? "All" : e.map { $0 == "*" ? "all" : $0.uppercased() }.joined(separator: ", ")
    }
    func strip(_ t: String) -> String { t.hasPrefix("host:") ? String(t.dropFirst(5)) : t }
    func notes(posture: [String], via: [String] = [], expires: String?) -> [String] {
        var out: [String] = []
        let required = posture.isEmpty ? m.defaultSrcPosture : posture
        if !required.isEmpty { out.append("if " + required.joined(separator: " or ")) }
        if !via.isEmpty { out.append("via " + via.joined(separator: ", ")) }
        if let expires { out.append("expires " + expires) }
        return out
    }

    var out: [RuleSummary] = []
    for r in m.rules where r.action == "accept" && applies(r.src) && reaches(r.dst.map { DestSpec($0).target }) {
        out.append(RuleSummary(kind: .acl, index: r.index,
                               name: r.comments.first ?? "Rule #\(r.index + 1)",
                               badge: badge(r.dst.map { DestSpec($0).ports }), sources: r.src,
                               destinations: r.dst.map { strip(DestSpec($0).target) }.uniqued(),
                               notes: notes(posture: r.srcPosture, expires: r.expires)))
    }
    // Indexed rather than `for g in … where …`: the latter crashes the Swift 6.4
    // optimizer (CopyPropagation ownership error) in release builds.
    for i in m.grants.indices {
        let g = m.grants[i]
        guard applies(g.src), reaches(g.dst) else { continue }
        out.append(RuleSummary(kind: .grant, index: g.index,
                               name: g.comments.first ?? "Grant #\(g.index + 1)",
                               badge: g.ip.isEmpty ? "APP" : badge(g.ip), sources: g.src,
                               destinations: g.dst.map(strip).uniqued(),
                               notes: notes(posture: g.srcPosture, via: g.via, expires: g.expires)))
    }
    for s in m.sshRules where applies(s.src) && reaches(s.dst, ssh: true) {
        out.append(RuleSummary(kind: .ssh, index: s.index,
                               name: s.comments.first ?? "SSH rule #\(s.index + 1)",
                               badge: "SSH · \(s.users.joined(separator: ", "))", sources: s.src,
                               destinations: s.dst.map(strip).uniqued(),
                               notes: s.expires.map { ["expires \($0)"] } ?? []))
    }
    return out
}

// MARK: - Exit nodes and subnet routes

/// What a source can do with the tailnet's routers: use exit nodes (and
/// which), and reach which advertised subnets through which routers.
struct RouteAccess {
    /// Some rule gives internet access (autogroup:internet or "*").
    var exitNode = false
    /// Tags exit traffic is limited to by "via"; empty means any exit node.
    var exitVia: [String] = []
    /// Devices with an approved exit-node route this source could use.
    var exitNodes: [String] = []
    /// Approved subnet routes the source's rules reach, with their routers.
    var subnets: [(route: String, routers: [String])] = []
}

func routeAccess(_ m: PolicyModel, sourceIDs: [String], nodes: [HeadscaleNode]) -> RouteAccess {
    let ev = Evaluator(model: m)
    func applies(_ src: [String]) -> Bool {
        src.contains { spec in sourceIDs.contains { ev.sourceMatches(spec: spec, sourceID: $0) } }
    }
    // Every rule that applies: its destination targets and via tags.
    var rules: [(dst: [String], via: [String])] = []
    for r in m.rules where r.action == "accept" && applies(r.src) { rules.append((r.dst.map { DestSpec($0).target }, [])) }
    for g in m.grants where applies(g.src) && !g.ip.isEmpty { rules.append((g.dst, g.via)) }

    var out = RouteAccess()
    let exitRules = rules.filter { $0.dst.contains("*") || $0.dst.contains("autogroup:internet") }
    out.exitNode = !exitRules.isEmpty
    // Any exit rule without via means any exit node will do.
    out.exitVia = exitRules.contains { $0.via.isEmpty } ? [] : exitRules.flatMap(\.via).uniqued()
    let isExit = { (n: HeadscaleNode) in (n.approvedRoutes ?? []).contains { $0 == "0.0.0.0/0" || $0 == "::/0" } }
    func carries(_ n: HeadscaleNode, _ via: [String]) -> Bool { via.isEmpty || !Set(n.allTags).isDisjoint(with: via) }
    if out.exitNode {
        out.exitNodes = nodes.filter { isExit($0) && carries($0, out.exitVia) }.map(\.displayName)
    }

    // Subnet routes: approved, non-exit, and overlapping something a rule reaches.
    var routers: [String: [HeadscaleNode]] = [:]
    for n in nodes {
        for r in n.approvedRoutes ?? [] where r != "0.0.0.0/0" && r != "::/0" { routers[r, default: []].append(n) }
    }
    for route in routers.keys.sorted() {
        var via: [String]? = nil  // nil: not reached; []: any router
        for rule in rules {
            // autogroup:internet is public addresses only, so it reaches no subnet route.
            let targets = rule.dst.filter { $0 != "autogroup:internet" }
            let reaches = targets.contains("*") || targets.flatMap { addressPrefixes($0, m) }.contains {
                prefixContains(route, $0) || prefixContains($0, route)
            }
            guard reaches else { continue }
            via = rule.via.isEmpty || via == [] ? [] : (via ?? []) + rule.via
        }
        guard let via else { continue }
        let serving = routers[route, default: []].filter { carries($0, via) }.map(\.displayName)
        out.subnets.append((route, serving))
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

// MARK: - Route auto-approval

extension Evaluator {
    /// Would `autoApprovers` approve `route` advertised by `node`? Exit-node
    /// routes use "exitNode"; others need an approver entry whose prefix
    /// contains the route.
    func autoApproves(route: String, node: HeadscaleNode) -> Bool {
        let approvers: [String]
        if route == "0.0.0.0/0" || route == "::/0" {
            approvers = model.exitNodeApprovers
        } else {
            approvers = model.routeApprovers.filter { prefixContains($0.route, route) }.flatMap(\.approvers)
        }
        return approvers.contains { a in node.identities.contains { sourceMatches(spec: a, sourceID: $0) } }
    }

}

// MARK: - Tests from current behavior

/// Tests pinning today's access. For each source: an accept for every named
/// port (one per named interval) it reaches on each tag and host, and a deny
/// for every such port some other source reaches there but it doesn't.
func generateTests(_ m: PolicyModel, sources: [String]) -> [ACLTest] {
    // Same view as the test runner: a test device has no posture attributes.
    let ev = Evaluator(model: m, sourceAttributes: [:], attributesComplete: true)
    let ports = portIntervals([m]).filter(\.named).map(\.range.lowerBound)
    let dests = m.tagOrder + m.hostOrder
    let srcs = sources.uniqued()
    // allowed[s][d] = set of ports
    var allowed: [String: [String: Set<Int>]] = [:]
    for s in srcs {
        for d in dests {
            allowed[s, default: [:]][d] = Set(ports.filter { ev.evaluate(sourceID: s, destID: d, port: $0).allowed })
        }
    }
    return srcs.compactMap { s in
        var accept: [String] = []
        var deny: [String] = []
        for d in dests {
            let mine = allowed[s]?[d] ?? []
            let anyone = srcs.reduce(into: Set<Int>()) { $0.formUnion(allowed[$1]?[d] ?? []) }
            accept += mine.sorted().map { "\(d):\($0)" }
            deny += anyone.subtracting(mine).sorted().map { "\(d):\($0)" }
        }
        return accept.isEmpty && deny.isEmpty ? nil : ACLTest(index: 0, src: s, accept: accept, deny: deny)
    }
}

/// SSH tests pinning today's SSH access: for each source and SSH
/// destination the rules name (a user's own devices via autogroup:self),
/// every login the rules name plus root, as accept, check, or deny.
/// Pairs with no SSH access at all are left out.
func generateSSHTests(_ m: PolicyModel, sources: [String]) -> [SSHTest] {
    let ev = Evaluator(model: m)
    let dsts = m.sshRules.flatMap(\.dst).filter { !$0.hasPrefix("autogroup:") && $0 != "*" }.uniqued()
    let usesSelf = m.sshRules.contains { $0.dst.contains("autogroup:self") }
    let logins = (m.sshRules.flatMap(\.users).filter { !$0.hasPrefix("autogroup:") } + ["root"]).uniqued()
    var out: [SSHTest] = []
    for s in sources.uniqued() {
        for d in dsts + (usesSelf && s.contains("@") ? [s] : []) {
            var t = SSHTest(index: 0, src: s, dst: [d])
            for login in logins {
                switch ev.sshOutcome(src: s, dst: d, login: login) {
                case .accept: t.accept.append(login)
                case .check: t.check.append(login)
                case .deny: t.deny.append(login)
                }
            }
            if !t.accept.isEmpty || !t.check.isEmpty { out.append(t) }
        }
    }
    return out
}

// MARK: - Failing test explanation

/// Why a test assertion fails. For an unexpected allow: the rules that allow
/// it. For a missing allow: the rules that reach the destination, split into
/// "from this source but not this port" and "not from this source".
func explainFailure(_ m: PolicyModel, src: String, entry: String,
                    expectAllowed: Bool) -> (summary: String, rules: [RuleSummary]) {
    let ev = Evaluator(model: m)
    let d = DestSpec(entry)
    let port = Int(d.ports) ?? 0
    let all = ruleSummaries(m, sourceIDs: nil)
    // Rule names come from comments, which often end with a period.
    func names(_ rules: [RuleSummary]) -> String {
        rules.map { $0.name.hasSuffix(".") ? String($0.name.dropLast()) : $0.name }.joined(separator: "; ")
    }
    if !expectAllowed {
        let matches = ev.evaluate(sourceID: src, destID: d.target, port: port).matches
        let rules = all.filter { r in
            matches.contains { ($0.kind == .grant ? RuleSummary.Kind.grant : .acl) == r.kind && $0.ruleIndex == r.index }
        }
        return ("Allowed by \(names(rules)).", rules)
    }
    let gated = ev.evaluate(sourceID: src, destID: d.target, port: port)
    if gated.conditional {
        return ("Allowed only on devices meeting \(gated.postures.joined(separator: " or ")) — give the test matching srcPostureAttrs.", [])
    }
    let reaching = ruleSummaries(m, sourceIDs: nil, destIDs: [d.target]).filter { $0.kind != .ssh }
    let fromSource = reaching.filter { r in r.sources.contains { ev.sourceMatches(spec: $0, sourceID: src) } }
    if !fromSource.isEmpty {
        return ("\(src) reaches \(d.target) through \(names(fromSource)), but not on port \(d.ports).",
                fromSource)
    }
    if !reaching.isEmpty {
        return ("Rules reach \(d.target), but none from \(src).", Array(reaching.prefix(4)))
    }
    return ("No rule reaches \(d.target) at all.", [])
}
