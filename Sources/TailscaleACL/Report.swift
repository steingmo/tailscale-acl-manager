import Foundation

/// Markdown documentation of a policy: groups, tags, devices, rules, who can
/// reach what, and open problems. For audits and customer documentation.
func policyReport(workspace: String, model m: PolicyModel, nodes: [HeadscaleNode],
                  problems: [LintIssue], mapImages: [(title: String, path: String)] = [],
                  date: Date = Date()) -> String {
    func cell(_ s: String) -> String { s.isEmpty ? "—" : s.replacingOccurrences(of: "|", with: "\\|") }
    func list(_ a: [String]) -> String { cell(a.joined(separator: ", ")) }
    let rules = ruleSummaries(m, sourceIDs: nil)
    var out: [String] = []

    out.append("# Access report — \(workspace)")
    out.append("")
    out.append("Generated \(date.formatted(date: .long, time: .shortened)).")
    out.append("")
    out.append("\(m.groupOrder.count) groups · \(m.tagOrder.count) tags · \(m.hostOrder.count) hosts · "
               + "\(m.ipsetOrder.count) IP sets · \(rules.count) rules"
               + (nodes.isEmpty ? "" : " · \(nodes.count) devices"))

    if !m.groupOrder.isEmpty {
        out += ["", "## Groups", "", "| Group | Members |", "| --- | --- |"]
        for g in m.groupOrder { out.append("| \(cell(g)) | \(list(m.groups[g] ?? [])) |") }
    }
    if !m.tagOrder.isEmpty {
        out += ["", "## Tags", ""]
        out.append(nodes.isEmpty ? "| Tag | Owners |" : "| Tag | Owners | Devices |")
        out.append(nodes.isEmpty ? "| --- | --- |" : "| --- | --- | --- |")
        for t in m.tagOrder {
            let devices = nodes.filter { $0.allTags.contains(t) }.map(\.displayName)
            out.append("| \(cell(t)) | \(list(m.tagOwners[t] ?? []))"
                       + (nodes.isEmpty ? " |" : " | \(list(devices)) |"))
        }
    }
    if !m.hostOrder.isEmpty || !m.ipsetOrder.isEmpty {
        out += ["", "## Hosts and IP sets", "", "| Name | Addresses |", "| --- | --- |"]
        for h in m.hostOrder { out.append("| \(cell(h)) | \(cell(m.hosts[h] ?? "")) |") }
        for s in m.ipsetOrder { out.append("| \(cell(s)) | \(list(m.ipsets[s] ?? [])) |") }
    }
    if !nodes.isEmpty {
        out += ["", "## Devices", "", "| Device | User | Tags | Addresses | Status |", "| --- | --- | --- | --- | --- |"]
        for n in nodes {
            out.append("| \(cell(n.displayName)) | \(cell(n.user?.name ?? "")) | \(list(n.allTags)) | "
                       + "\(list(n.ipAddresses ?? [])) | \(cell(n.statusText)) |")
        }
    }

    out += ["", "## Rules", ""]
    if rules.isEmpty { out.append("No rules.") }
    for r in rules {
        out.append("- **\(r.name)** — \(r.sources.joined(separator: ", ")) → "
                   + "\(r.destinations.joined(separator: ", ")) · \(r.badge)")
    }

    // Who can reach what: every group and tag, plus every device when loaded.
    var sources: [(title: String, ids: [String])] = m.groupOrder.map { ($0, [$0]) } + m.tagOrder.map { ($0, [$0]) }
    sources += nodes.map { ("\($0.displayName) (device)", $0.identities) }
    if !sources.isEmpty {
        out += ["", "## Who can reach what"]
        for s in sources {
            out += ["", "### \(s.title)", ""]
            let applying = ruleSummaries(m, sourceIDs: s.ids)
            if applying.isEmpty { out.append("No rules apply.") }
            for r in applying {
                out.append("- \(r.destinations.joined(separator: ", ")) · \(r.badge) (\(r.name))")
            }
        }
    }

    if !mapImages.isEmpty {
        out += ["", "## Access maps"]
        for image in mapImages {
            // Angle brackets keep paths with spaces valid in Markdown.
            out += ["", "### \(image.title)", "", "![\(image.title)](<\(image.path)>)"]
        }
    }

    out += ["", "## Problems", ""]
    if problems.isEmpty { out.append("No problems found.") }
    for p in problems {
        out.append("- \(p.severity == .error ? "Error" : "Warning"): **\(p.title)** — \(p.detail)")
    }
    return out.joined(separator: "\n") + "\n"
}

/// What a push review covers, for exporting it.
struct PushReview {
    var workspace: String
    var host: String
    var isRestore = false
    var serverText: String?
    var candidate: String
    var changes: [AccessChange] = []
    var deviceCount = 0
    /// Why there is no access comparison, if there isn't one.
    var note: String?
    /// Tailscale's verdict: nil not checked, "" passed, otherwise the failure.
    var verdict: String?
    var errors: [LintIssue] = []
    var tests: [TestResult] = []
    var sshTests: [SSHTestResult] = []
    /// The server changed since the last pull/push; pushing overwrites it.
    var conflict = false
    /// Recent real connections this push would block; nil when not checked.
    var blockedTraffic: [String]?
}

/// A push review as Markdown, to paste into a ticket or pull request so
/// someone else can approve the change before it goes live.
func pushReviewMarkdown(_ r: PushReview, date: Date = Date()) -> String {
    func cell(_ s: String) -> String { s.isEmpty ? "—" : s.replacingOccurrences(of: "|", with: "\\|") }
    var out = ["# Policy change review — \(r.workspace)", ""]
    out.append("\(r.isRestore ? "Restore an earlier policy" : "Push") to **\(r.host)** · prepared \(date.formatted(date: .long, time: .shortened))")
    out += ["", "## Summary", ""]
    if r.serverText == r.candidate {
        out.append("- The policy is identical to what's on the server.")
    } else if let note = r.note {
        out.append("- \(note)")
    } else {
        out.append(r.changes.isEmpty ? "- No network or SSH access changes between the \(r.deviceCount) devices."
                   : "- \(r.changes.count) device pair\(r.changes.count == 1 ? "" : "s") of \(r.deviceCount) devices change access.")
    }
    if let blocked = r.blockedTraffic {
        out.append(blocked.isEmpty ? "- ✅ No recent real traffic (flow logs) would be blocked."
                   : "- ❌ \(blocked.count) kind\(blocked.count == 1 ? "" : "s") of recent real traffic would be blocked.")
    }
    if r.conflict { out.append("- ⚠️ The server's policy changed since the last pull or push; this push overwrites those changes.") }
    if let v = r.verdict { out.append(v.isEmpty ? "- ✅ Tailscale's own check passed." : "- ❌ Tailscale's check failed: \(v)") }
    let failing = r.tests.filter { !$0.passed }.count + r.sshTests.filter { !$0.passed }.count
    let total = r.tests.count + r.sshTests.count
    if total > 0 { out.append(failing == 0 ? "- ✅ All \(total) policy tests pass." : "- ❌ \(failing) of \(total) policy tests fail.") }
    if !r.errors.isEmpty { out.append("- ❌ \(r.errors.count) problem\(r.errors.count == 1 ? "" : "s") (errors).") }

    if !r.changes.isEmpty {
        out += ["", "## Access changes", "", "| From | To | Gains | Loses |", "| --- | --- | --- | --- |"]
        for c in r.changes {
            let gains = c.gained + c.sshGained.map { "SSH as \($0)" }
            let loses = c.lost + c.sshLost.map { "SSH as \($0)" }
            out.append("| \(cell(c.src)) | \(cell(c.dst)) | \(cell(gains.joined(separator: ", "))) | \(cell(loses.joined(separator: ", "))) |")
        }
    }
    // Plain loops: the chained flatMap form timed out the type checker on CI.
    var failures: [String] = []
    for t in r.tests {
        for a in t.assertions where !a.passed {
            let verb = a.kind == .accept ? "reach" : "not reach"
            failures.append("- tests[\(t.testIndex)] \(t.src) should \(verb) \(a.dst)")
        }
    }
    for t in r.sshTests {
        for a in t.assertions where !a.passed {
            failures.append("- sshTests[\(t.testIndex)] \(t.src) → \(a.dst) as \(a.login): expected \(a.expected.rawValue), got \(a.actual.rawValue)")
        }
    }
    if let blocked = r.blockedTraffic, !blocked.isEmpty {
        out += ["", "## Real traffic this would block", ""]
        for b in blocked { out.append("- " + b) }
    }
    if !failures.isEmpty { out += ["", "## Failing tests", ""] + failures }
    if !r.errors.isEmpty {
        out += ["", "## Problems", ""]
        for e in r.errors { out.append("- **\(e.title)**: \(e.detail)") }
    }

    if let old = r.serverText, old != r.candidate {
        out += ["", "## Text changes", "", "```diff"]
        var lines = lineDiff(old: old, new: r.candidate)
        while let last = lines.last, last.kind == .same, last.text.isEmpty { lines.removeLast() }  // final newline
        for line in lines {
            switch line.kind {
            case .same: out.append(" " + line.text)
            case .added: out.append("+" + line.text)
            case .removed: out.append("-" + line.text)
            case .skipped: out.append("@@ \(line.text) unchanged line\(line.text == "1" ? "" : "s") @@")
            }
        }
        out.append("```")
    }
    return out.joined(separator: "\n") + "\n"
}

/// A least-privilege audit for periodic reviews: security findings,
/// temporary access, users who left, stale devices and keys, rule usage
/// from real traffic (when loaded), and the credential's reach.
func auditReport(workspace: String, server: String?, model m: PolicyModel, nodes: [HeadscaleNode],
                 traffic: TrafficSummary?, serverLogins: Set<String>?, credential: CredentialInfo?,
                 date: Date = Date()) -> String {
    var out = ["# Access audit — \(workspace)", ""]
    out.append("Prepared \(date.formatted(date: .long, time: .shortened))" + (server.map { " · \($0)" } ?? "") + ".")

    let security = lintSecurity(m)
    let problems = lintPolicy(m, now: date).filter { !$0.security }
    let left = lintUsers(m, logins: serverLogins)
    let stale = nodes.filter { $0.isStale(now: date) }
    let keys = nodes.filter { ($0.keyDaysLeft(now: date) ?? .max) <= 14 }
    var dated: [(String, String, Int)] = []
    for (section, index, expires) in m.rules.map({ ("acls", $0.index, $0.expires) }) + m.grants.map({ ("grants", $0.index, $0.expires) })
        + m.sshRules.map({ ("ssh", $0.index, $0.expires) }) {
        if let expires, let days = RuleExpiry.daysLeft(expires, now: date) { dated.append(("\(section)[\(index)]", expires, days)) }
    }

    out += ["", "## Summary", ""]
    out.append("- \(security.count) security finding\(security.count == 1 ? "" : "s")")
    out.append("- \(dated.filter { $0.2 < 0 }.count) expired and \(dated.filter { (0...14).contains($0.2) }.count) soon-expiring temporary rules")
    if serverLogins != nil { out.append("- \(left.count) policy reference\(left.count == 1 ? "" : "s") to people who aren't users on the server") }
    if !nodes.isEmpty { out.append("- \(stale.count) device\(stale.count == 1 ? "" : "s") not seen in 30 days, \(keys.count) with keys expired or expiring within 14 days") }
    out.append("- \(problems.filter { $0.severity == .error }.count) policy errors, \(problems.filter { $0.severity == .warning }.count) warnings")

    out += ["", "## Security review", ""]
    out += security.isEmpty ? ["No findings."] : security.map { "- **\($0.title)** — \($0.detail)" }

    out += ["", "## Temporary access", ""]
    out += dated.isEmpty ? ["No rules carry an expiry date."] : dated.sorted { $0.2 < $1.2 }.map { rule, expires, days in
        "- \(rule): \(days < 0 ? "**expired** \(expires) and still grants access" : "expires \(expires) (in \(days) day\(days == 1 ? "" : "s"))")"
    }

    out += ["", "## People", ""]
    if serverLogins == nil {
        out.append("Not checked: connect the server (with permission to list users) to compare the policy with real users.")
    } else {
        out += left.isEmpty ? ["Everyone the policy names is a user on the server."] : left.map { "- \($0.detail)" }
    }

    out += ["", "## Devices", ""]
    if nodes.isEmpty {
        out.append("Not checked: load devices from the server.")
    } else {
        out += stale.isEmpty ? ["No device has been offline for 30 days."] : stale.map { "- \($0.displayName): \($0.statusText)" }
        out += keys.map { n in
            let d = n.keyDaysLeft(now: date) ?? 0
            return "- \(n.displayName): key \(d < 0 ? "expired" : "expires in \(d) day\(d == 1 ? "" : "s")")"
        }
    }

    out += ["", "## Rule usage", ""]
    if let traffic {
        let usage = ruleUsage(traffic.connections, m, nodes: nodes)
        let rules = ruleSummaries(m, sourceIDs: nil).filter { $0.kind != .ssh }
        let key = { (r: RuleSummary) in "\(r.kind == .grant ? RuleMatch.Kind.grant : .acl)-\(r.index)" }
        out.append("From flow logs \(traffic.start.formatted(date: .abbreviated, time: .omitted)) – \(traffic.end.formatted(date: .abbreviated, time: .omitted)); only successful connections are logged.")
        let unused = rules.filter { usage[key($0)] == nil }
        out += ["", "No traffic in the period (candidates for removal):"]
        out += unused.isEmpty ? ["- none"] : unused.map { "- \($0.section)[\($0.index)] \($0.name)" }
        let broad = rules.compactMap { r -> String? in
            guard let u = usage[key(r)], r.badge == "All" || r.badge.contains("-"), u.ports.count <= 6 else { return nil }
            return "- \(r.section)[\(r.index)] \(r.name): allows \(r.badge == "All" ? "every port" : r.badge), used only \(u.ports.keys.sorted().joined(separator: ", "))"
        }
        out += ["", "Broad rules where only a few ports were used:"]
        out += broad.isEmpty ? ["- none"] : broad
    } else {
        out.append("Not checked: load traffic on the Traffic screen (Tailscale) to see which rules real connections use.")
    }

    if let credential {
        out += ["", "## Credential", ""]
        out.append("- Stored " + (credential.reference.map { "in 1Password: \($0)" } ?? "in the Keychain of the Mac running the app"))
        out.append("- \(credential.kind)" + (credential.isFullAccess ? ", full access" : credential.scopes.map { ", scopes: \($0.joined(separator: ", "))" } ?? ""))
        if let expires = credential.expires { out.append("- Expires \(expires.formatted(date: .long, time: .omitted))") }
    }
    return out.joined(separator: "\n") + "\n"
}
