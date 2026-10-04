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
