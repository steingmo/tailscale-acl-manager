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
    /// A finding of the security review, shown in its own section.
    var security = false

    var id: String { "\(severity)-\(title)-\(detail)" }
}

struct LintFix: Identifiable {
    enum Action {
        case addTagOwner(String)          // tagOwners[tag] = []
        case defineGroup(String)          // groups[group] = []
        case deleteEntity(String)         // definition + every reference
        case deleteRule(section: String, index: Int)
        case removeGroupMember(group: String, member: String)
        case setSSHCheck(index: Int)
        case setTagOwners(tag: String, owners: [String])
        case replacePostureCondition(posture: String, index: Int, with: String)
        /// New group with `members`; the first rule's src becomes the group, the others are deleted.
        case moveToGroup(section: String, indices: [Int], group: String, members: [String])
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
    for t in m.sshTests {
        references.append((t.src, "sshTests[\(t.index)]"))
        for d in t.dst { references.append((d, "sshTests[\(t.index)]")) }
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
        issues += lintPostureValues(name, m.postures[name] ?? [])
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

    issues += lintDERP(m.derpRegions)
    issues += lintPersonalRules(m)
    issues += lintSecurity(m)
    return issues.sorted { a, b in
        if a.severity != b.severity { return a.severity == .error }
        return a.title < b.title
    }
}

/// Integration attributes (Huntress) that don't exist, and values they never
/// report — e.g. Tailscale's own example's huntress:defenderStatus == 'Healthy',
/// which no device meets.
func lintPostureValues(_ name: String, _ conditions: [String]) -> [LintIssue] {
    var issues: [LintIssue] = []
    for (i, text) in conditions.enumerated() {
        guard let c = PostureCondition(text) else { continue }
        let path = "postures[\(name)]"
        guard let allowed = knownPostureAttributes[c.attribute] else {
            let namespace = c.attribute.split(separator: ":").first.map(String.init) ?? ""
            let known = knownPostureAttributes.keys.filter { $0.hasPrefix(namespace + ":") }.sorted()
            if !known.isEmpty {
                let fix = known.first { $0.caseInsensitiveCompare(c.attribute) == .orderedSame }
                issues.append(.init(severity: .error, title: "Unknown \(namespace) attribute",
                                    detail: "\(name) checks \(c.attribute), which \(namespace) doesn't set, so no device has it. Known: \(known.joined(separator: ", ")).",
                                    fixes: fix.map { [.init(label: "Use \($0)", action: .replacePostureCondition(posture: name, index: i, with: text.replacingOccurrences(of: c.attribute, with: $0)))] } ?? [],
                                    path: path))
            }
            continue
        }
        guard ["==", "!=", "IN", "NOT IN"].contains(c.op) else { continue }
        let bad = c.values.filter { !allowed.contains($0) }
        guard !bad.isEmpty else { continue }
        // == or IN with nothing reachable: no device ever meets the posture.
        let never = (c.op == "==" || c.op == "IN") && bad.count == c.values.count
        var fixed = text
        for b in bad {
            if let good = likelyPostureValue(b, allowed: allowed) {
                fixed = fixed.replacingOccurrences(of: "'\(b)'", with: "'\(good)'")
                    .replacingOccurrences(of: "\"\(b)\"", with: "\"\(good)\"")
            }
        }
        let quoted = bad.map { "'\($0)'" }.joined(separator: ", ")
        issues.append(.init(severity: never ? .error : .warning,
                            title: never ? "Posture no device can meet" : "Value never reported",
                            detail: "\(name): \(c.attribute) is never \(quoted). It's one of \(allowed.joined(separator: ", ")) (case matters)."
                                + (never ? " As written, every rule requiring \(name) blocks everyone." : ""),
                            fixes: fixed == text ? [] : [.init(label: "Change to \(fixed)", action: .replacePostureCondition(posture: name, index: i, with: fixed))],
                            path: path))
    }
    return issues
}

// MARK: - Access given to people one by one

/// Rules whose sources are only people (no group, tag, or autogroup).
/// Rules giving the same access are merged into one rule with a new group.
/// Temporary rules (with an expires comment) are left alone.
func lintPersonalRules(_ m: PolicyModel) -> [LintIssue] {
    func isPerson(_ s: String) -> Bool {
        s.contains("@") && !["group:", "tag:", "autogroup:"].contains { s.hasPrefix($0) }
    }
    // Same access = same section, destinations, ports/protocols, via, and postures.
    var buckets: [String: (section: String, indices: [Int], dst: [String], people: [String])] = [:]
    var order: [String] = []
    func add(_ section: String, _ index: Int, _ src: [String], _ dst: [String], _ rest: [String]) {
        guard !src.isEmpty, src.allSatisfy(isPerson) else { return }
        let key = ([section] + dst.sorted() + ["|"] + rest).joined(separator: "\u{1}")
        if buckets[key] == nil { order.append(key); buckets[key] = (section, [], dst, []) }
        buckets[key]!.indices.append(index)
        buckets[key]!.people = (buckets[key]!.people + src).uniqued()
    }
    for r in m.rules where r.action == "accept" && r.expires == nil {
        add("acls", r.index, r.src, r.dst, [r.proto ?? ""] + r.srcPosture.sorted())
    }
    for g in m.grants where g.expires == nil && !g.hasApp {
        add("grants", g.index, g.src, g.dst, g.ip.sorted() + ["|"] + g.via.sorted() + ["|"] + g.srcPosture.sorted())
    }
    return order.compactMap { buckets[$0] }.map { b in
        let rules = b.indices.map { "\(b.section)[\($0)]" }
        let group = suggestedGroupName(b.dst, m)
        let people = b.people.joined(separator: ", ")
        let single = b.indices.count == 1 && b.people.count == 1
        return LintIssue(
            severity: .warning,
            title: single ? "Access given to one person" : "Access given to people one by one",
            detail: single
                ? "\(rules[0]) gives \(people) access directly. With a group the access is easy to review, and it ends when they leave the group."
                : "\(rules.joined(separator: ", ")) give\(rules.count == 1 ? "s" : "") the same access to \(people). One rule with a group does the same and is easier to review.",
            fixes: [.init(label: "Move to new \(group)",
                          action: .moveToGroup(section: b.section, indices: b.indices, group: group, members: b.people))],
            path: "\(rules[0]).src")
    }
}

/// "ipset:windmill" → "group:windmill-users"; IPs use their host name if
/// there is one. Never an existing group.
func suggestedGroupName(_ dst: [String], _ m: PolicyModel) -> String {
    var base = dst.first.map { DestSpec($0).target } ?? "access"
    for p in ["ipset:", "tag:", "host:", "group:", "autogroup:"] where base.hasPrefix(p) { base = String(base.dropFirst(p.count)) }
    if isAddressLike(base) || base == "*" {
        base = m.hosts.first { $0.value == base }?.key ?? (base == "*" ? "all" : "access-" + base)
    }
    base = base.replacingOccurrences(of: "[^A-Za-z0-9-]+", with: "-", options: .regularExpression)
        .trimmingCharacters(in: CharacterSet(charactersIn: "-"))
    var name = "group:\(base)-users", n = 2
    while m.groups[name] != nil { name = "group:\(base)-users-\(n)"; n += 1 }
    return name
}

// MARK: - Security review

/// Ports worth singling out when they're open to everyone.
let sensitivePorts: [(port: Int, name: String)] = [
    (22, "SSH"), (23, "Telnet"), (3389, "RDP"), (445, "SMB"), (5985, "WinRM"), (5986, "WinRM"),
    (1433, "SQL Server"), (3306, "MySQL"), (5432, "PostgreSQL"), (6379, "Redis"), (27017, "MongoDB"),
]

/// Risky patterns in a policy: tag owners who gain access by tagging, broad
/// auto-approvers, root SSH without check mode, sensitive ports open to
/// everyone, servers reaching people's devices, danger-all, and sensitive
/// access without a deny test.
func lintSecurity(_ m: PolicyModel) -> [LintIssue] {
    var issues: [LintIssue] = []
    func add(_ title: String, _ detail: String, path: String?, fixes: [LintFix] = []) {
        var issue = LintIssue(severity: .warning, title: title, detail: detail, fixes: fixes, path: path)
        issue.security = true
        issues.append(issue)
    }
    let everyone: Set<String> = ["*", "autogroup:member", "autogroup:members", "autogroup:danger-all"]
    let ev = Evaluator(model: m)
    func reach(_ ids: [String]) -> Set<String> {
        Set(ruleSummaries(m, sourceIDs: ids).filter { $0.kind != .ssh }.flatMap(\.destinations))
    }

    // Tag owners: whoever can apply a tag gets the tag's access.
    for tag in m.tagOrder {
        let owners = m.tagOwners[tag] ?? []
        let fix = [LintFix(label: "Only admins may apply \(tag)", action: .setTagOwners(tag: tag, owners: ["autogroup:admin"]))]
        if owners.contains(where: everyone.contains) {
            add("Anyone can apply \(tag)", "Every user may tag their own device \(tag) and so gain everything \(tag) can reach.",
                path: "tagOwners[\(tag)]", fixes: fix)
            continue
        }
        let tagReach = reach([tag])
        for owner in owners where owner.hasPrefix("group:") || owner.contains("@") {
            let ids = [owner] + (m.groups[owner] ?? [])
            // Covered when the owner already reaches it, directly or through
            // something broader ("*", a CIDR or IP set containing it, …).
            let ownerReach = reach(ids)
            let gained = tagReach.subtracting([tag]).filter { d in
                !ownerReach.contains { $0 == "*" || $0 == d || ev.targetMatches(target: $0, destID: d) }
            }.sorted()
            guard !gained.isEmpty else { continue }
            add("Tag owners gain access through \(tag)",
                "\(owner) can tag one of their own devices \(tag) and so reach \(gained.prefix(4).joined(separator: ", "))\(gained.count > 4 ? ", …" : "") — access they don't have themselves.",
                path: "tagOwners[\(tag)]", fixes: fix)
        }
    }

    // Auto-approvers: anyone listed can advertise routes that get approved.
    for (route, approvers) in m.routeApprovers where approvers.contains(where: everyone.contains) {
        add("Anyone can get \(route) approved", "Any user's device can advertise \(route) and have it approved automatically, pulling that traffic through their device.",
            path: "autoApprovers.routes[\(route)]")
    }
    if m.exitNodeApprovers.contains(where: everyone.contains) {
        add("Anyone can become an exit node", "Any user's device can offer itself as an approved exit node and see other people's internet traffic.",
            path: "autoApprovers.exitNode")
    }

    // Root SSH for people without re-authentication.
    for r in m.sshRules where r.action == "accept" && r.users.contains("root") && r.src.contains(where: { !$0.hasPrefix("tag:") }) {
        add("SSH as root without check mode", "ssh[\(r.index)] lets \(r.src.joined(separator: ", ")) log in as root without re-authenticating. Check mode asks them to confirm recently.",
            path: "ssh[\(r.index)]", fixes: [LintFix(label: "Use check mode", action: .setSSHCheck(index: r.index))])
    }

    // Sensitive ports open to everyone; remember what's reached on them.
    var sensitiveTargets = Set<String>()
    var firstReach: [String: String] = [:]  // target → the first rule reaching it on a sensitive port
    func services(_ open: (Int) -> Bool) -> [String] { sensitivePorts.filter { open($0.port) }.map(\.name).uniqued() }
    for r in m.rules where r.action == "accept" {
        for d in r.dst.map(DestSpec.init) {
            let found = services { ev.portMatches(spec: d.ports, port: $0) }
            if !found.isEmpty, d.target != "*" {
                sensitiveTargets.insert(d.target)
                firstReach[d.target] = firstReach[d.target] ?? "acls[\(r.index)]"
            }
            if r.src.contains(where: everyone.contains), !found.isEmpty, !(d.target == "*" && d.ports == "*") {
                add("\(found.joined(separator: ", ")) open to everyone", "acls[\(r.index)] lets every user reach \(d.target) on \(found.joined(separator: ", ")).",
                    path: "acls[\(r.index)]")
            }
        }
    }
    for g in m.grants where !g.ip.isEmpty {
        let found = services { port in g.ip.contains { ev.ipSpecMatches(spec: $0, port: port) } }
        guard !found.isEmpty else { continue }
        for t in g.dst where t != "*" {
            sensitiveTargets.insert(t)
            firstReach[t] = firstReach[t] ?? "grants[\(g.index)]"
        }
        if g.src.contains(where: everyone.contains), !(g.dst.contains("*") && g.ip.contains("*")) {
            add("\(found.joined(separator: ", ")) open to everyone", "grants[\(g.index)] lets every user reach \(g.dst.joined(separator: ", ")) on \(found.joined(separator: ", ")).",
                path: "grants[\(g.index)]")
        }
    }

    // Servers that can reach people's devices (lateral movement from a breached server).
    let people = { (t: String) in t == "*" || t == "autogroup:member" || t == "autogroup:members" || t.contains("@") || t.hasPrefix("group:") }
    for r in ruleSummaries(m, sourceIDs: nil) where r.kind != .ssh {
        let tags = r.sources.filter { $0.hasPrefix("tag:") }
        let reached = r.destinations.filter(people)
        guard !tags.isEmpty, !reached.isEmpty else { continue }
        add("Servers can reach people's devices", "\(r.name): \(tags.joined(separator: ", ")) can reach \(reached.joined(separator: ", ")). If such a device is breached, so are users' laptops.",
            path: "\(r.section)[\(r.index)]")
    }

    for r in ruleSummaries(m, sourceIDs: nil) where r.sources.contains("autogroup:danger-all") {
        add("autogroup:danger-all in use", "\(r.name) admits every device, including ones shared from outside the tailnet.",
            path: "\(r.section)[\(r.index)]")
    }

    // Sensitive access nobody pins with a deny test.
    let denied = Set(m.tests.flatMap(\.deny).map { DestSpec($0).target })
    // Autogroups can't be a test's destination, so they're left out.
    let unpinned = sensitiveTargets.subtracting(denied).filter { !$0.hasPrefix("autogroup:") }.sorted()
    if !unpinned.isEmpty {
        add("Sensitive access without deny tests",
            "\(unpinned.prefix(6).joined(separator: ", "))\(unpinned.count > 6 ? ", …" : "") \(unpinned.count == 1 ? "is" : "are") reached on SSH, RDP, or database ports, but no test says who must not reach \(unpinned.count == 1 ? "it" : "them"). Add one with Pin as test in the Simulator.",
            path: m.tests.isEmpty ? firstReach[unpinned[0]] : "tests")
    }
    return issues
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

/// Is prefix `inner` (or an address) entirely inside prefix `outer`?
func prefixContains(_ outer: String, _ inner: String) -> Bool {
    guard let o = parseCIDR(outer), let i = parseCIDR(inner) else { return outer == inner }
    return o.bits <= i.bits && cidrContains(cidr: outer, ip: inner)
}

/// The address prefixes a destination stands for: IPs, CIDRs, host
/// addresses, and what IP sets add; the internet as 0.0.0.0/0. Empty for
/// device selectors (tags, groups, users), which need no route. With
/// `internet: false` autogroup:internet stands for nothing.
func addressPrefixes(_ target: String, _ m: PolicyModel, internet: Bool = true, visiting: Set<String> = []) -> [String] {
    let t = target.hasPrefix("host:") ? String(target.dropFirst(5)) : target
    if isAddressLike(t) { return [t] }
    if let ip = m.hosts[t] { return [ip] }
    if t == "autogroup:internet" { return internet ? ["0.0.0.0/0"] : [] }
    guard let entries = m.ipsets[t], !visiting.contains(t) else { return [] }
    return entries.compactMap(IPSetEntry.init).filter { !$0.remove }
        .flatMap { addressPrefixes($0.target, m, internet: internet, visiting: visiting.union([t])) }
}

/// Is the destination autogroup:internet, or an IP set that adds it?
func includesInternet(_ target: String, _ m: PolicyModel, visiting: Set<String> = []) -> Bool {
    if target == "autogroup:internet" { return true }
    guard let entries = m.ipsets[target], !visiting.contains(target) else { return false }
    return entries.compactMap(IPSetEntry.init).contains {
        !$0.remove && includesInternet($0.target, m, visiting: visiting.union([target]))
    }
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

// MARK: - User checks (need the server's user list)

/// Users the policy names who aren't users on the server (anymore): stale
/// group members, and users named directly in rules.
func lintUsers(_ m: PolicyModel, logins: Set<String>?) -> [LintIssue] {
    guard let logins, !logins.isEmpty else { return [] }
    func known(_ u: String) -> Bool { !u.contains("@") || u.contains("*") || logins.contains(u.lowercased()) }
    var issues: [LintIssue] = []
    for g in m.groupOrder {
        for u in m.groups[g] ?? [] where !known(u) {
            issues.append(.init(severity: .warning, title: "Not a user on the server",
                                detail: "\(u) is in \(g) but isn't a user on the server — maybe they left. Remove them so access doesn't return if the address is reused.",
                                fixes: [.init(label: "Remove from \(g)", action: .removeGroupMember(group: g, member: u))],
                                path: "groups[\(g)]"))
        }
    }
    let direct = m.rules.map { ("acls[\($0.index)]", $0.src) } + m.grants.map { ("grants[\($0.index)]", $0.src) }
        + m.sshRules.map { ("ssh[\($0.index)]", $0.src) }
    for (where_, src) in direct {
        for u in src where !known(u) {
            issues.append(.init(severity: .warning, title: "Not a user on the server",
                                detail: "\(u) in \(where_) isn't a user on the server — maybe they left.", path: where_))
        }
    }
    return issues
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

    // "via" sends traffic through devices with those tags, so one of them
    // must have an approved route covering each destination address.
    for g in m.grants where !g.via.isEmpty {
        let prefixes = g.dst.flatMap { addressPrefixes($0, m) }.uniqued()
        guard !prefixes.isEmpty else { continue }
        let via = g.via.joined(separator: " or ")
        let routers = nodes.filter { !Set($0.allTags).isDisjoint(with: g.via) }
        if routers.isEmpty {
            issues.append(.init(severity: .warning, title: "No router for via",
                                detail: "grants[\(g.index)] routes via \(via), but no current device carries that tag, so the traffic has no path.",
                                path: "grants[\(g.index)].via"))
            continue
        }
        func served(_ p: String, by routes: (HeadscaleNode) -> [String]?) -> Bool {
            routers.contains { r in (routes(r) ?? []).contains { prefixContains($0, p) } }
        }
        let missing = prefixes.filter { !served($0, by: \.approvedRoutes) }
        guard !missing.isEmpty else { continue }
        let advertised = missing.filter { served($0, by: \.availableRoutes) }
        let shown = missing.prefix(4).joined(separator: ", ") + (missing.count > 4 ? ", …" : "")
        issues.append(.init(severity: .warning, title: "Route not served via",
                            detail: "grants[\(g.index)] sends \(shown) via \(via), but no \(via) device (\(routers.map(\.displayName).joined(separator: ", "))) has an approved route covering \(missing.count == 1 ? "it" : "them")"
                                + (advertised.isEmpty ? "." : " — \(advertised.count == missing.count ? "they are" : "some are") advertised but not yet approved (see Routes)."),
                            path: "grants[\(g.index)].via"))
    }
    for g in m.grants {
        check("grants[\(g.index)]", src: g.src, dstTargets: g.dst)
    }
    return issues
}
