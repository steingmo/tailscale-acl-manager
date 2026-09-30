import Foundation

/// Markdown documentation of a policy: groups, tags, devices, rules, who can
/// reach what, and open problems. For audits and customer documentation.
func policyReport(workspace: String, model m: PolicyModel, nodes: [HeadscaleNode],
                  problems: [LintIssue], date: Date = Date()) -> String {
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

    out += ["", "## Problems", ""]
    if problems.isEmpty { out.append("No problems found.") }
    for p in problems {
        out.append("- \(p.severity == .error ? "Error" : "Warning"): **\(p.title)** — \(p.detail)")
    }
    return out.joined(separator: "\n") + "\n"
}
