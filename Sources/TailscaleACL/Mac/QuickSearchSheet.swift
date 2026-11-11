import SwiftUI

enum SearchResult {
    case entity(String)   // focus the Access Map ("node:<id>" for devices)
    case rule(RuleSummary)
    case line(Int)        // show the Policy Editor at this line
}

/// Everything in a policy that covers an IP address: hosts, IP sets, rules
/// (other than through "*"), tests, and devices with that address, each with
/// its policy path for jumping to the line.
struct IPLookupHit: Identifiable {
    var title: String
    var detail: String
    var path: String?
    var deviceID: String?
    var id: String { "\(title)|\(detail)" }
}

func ipLookup(_ ip: String, _ m: PolicyModel, nodes: [HeadscaleNode] = []) -> [IPLookupHit] {
    let ev = Evaluator(model: m)
    var hits: [IPLookupHit] = []
    for h in m.hostOrder where cidrContains(cidr: m.hosts[h] ?? "", ip: ip) {
        hits.append(.init(title: h, detail: "host = \(m.hosts[h] ?? "")", path: "hosts[\(h)]"))
    }
    for s in m.ipsetOrder where ev.ipsetContains(s, ip: ip) {
        hits.append(.init(title: s, detail: "IP set contains \(ip)", path: "ipsets[\(s)]"))
    }
    for r in ruleSummaries(m, sourceIDs: nil) {
        let to = r.destinations.filter { $0 != "*" && ev.targetMatches(target: $0, destID: ip) }
        let from = r.sources.filter { $0 != "*" && ev.sourceMatches(spec: $0, sourceID: ip) }
        guard !to.isEmpty || !from.isEmpty else { continue }
        let how = (to.isEmpty ? [] : ["reaches it via \(to.joined(separator: ", "))"])
            + (from.isEmpty ? [] : ["it is a source via \(from.joined(separator: ", "))"])
        hits.append(.init(title: r.name, detail: "\(r.section) · \(r.badge) · " + how.joined(separator: "; "),
                          path: "\(r.section)[\(r.index)]"))
    }
    for t in m.tests {
        let entries = (t.accept + t.deny).filter { e in
            let target = DestSpec(e).target
            return target != "*" && ev.targetMatches(target: target, destID: ip)
        }
        if !entries.isEmpty || ev.sourceMatches(spec: t.src, sourceID: ip) && t.src != "*" {
            hits.append(.init(title: "Test #\(t.index + 1) (\(t.src))",
                              detail: entries.isEmpty ? "source covers it" : entries.joined(separator: ", "),
                              path: "tests[\(t.index)]"))
        }
    }
    for n in nodes where (n.ipAddresses ?? []).contains(ip) {
        hits.append(.init(title: n.displayName, detail: "device · \(n.policyName ?? "")", deviceID: n.id))
    }
    return hits
}

/// ⌘K: find any group, tag, user, host, IP set, device, or rule.
struct QuickSearchSheet: View {
    var onPick: (SearchResult) -> Void

    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var query = ""
    @State private var highlighted = 0
    @FocusState private var focused: Bool

    private struct Item: Identifiable {
        var id: String
        var title: String
        var subtitle: String
        var icon: String
        var color: Color
        var result: SearchResult
    }

    private var allItems: [Item] {
        let m = store.model
        var items: [Item] = []
        func entity(_ name: String, _ subtitle: String) {
            items.append(Item(id: "e:" + name, title: name, subtitle: subtitle, icon: Theme.entityIcon(name),
                              color: Theme.entityColor(name), result: .entity(name)))
        }
        m.groupOrder.forEach { g in
            let n = m.groups[g]?.count ?? 0
            entity(g, "group · \(n) member\(n == 1 ? "" : "s")")
        }
        m.tagOrder.forEach { entity($0, "tag") }
        m.allUsers.forEach { entity($0, "user") }
        m.hostOrder.forEach { entity($0, "host · \(m.hosts[$0] ?? "")") }
        m.ipsetOrder.forEach { entity($0, "IP set") }
        for n in store.headscaleNodes {
            items.append(Item(id: "n:" + n.id, title: n.displayName,
                              subtitle: "device · \(([n.policyName] + [n.ipAddresses?.first]).compactMap { $0 }.joined(separator: " · "))",
                              icon: "desktopcomputer", color: Theme.textPrimary, result: .entity("node:\(n.id)")))
        }
        for r in ruleSummaries(m, sourceIDs: nil) {
            let kind = r.kind == .grant ? "grant" : r.kind == .ssh ? "SSH rule" : "ACL rule"
            items.append(Item(id: "r:" + r.id, title: r.name,
                              subtitle: "\(kind) · \(r.sources.joined(separator: ", ")) → \(r.destinations.joined(separator: ", "))",
                              icon: "line.3.horizontal.decrease", color: Theme.lineGreen, result: .rule(r)))
        }
        return items
    }

    private var results: [Item] {
        let q = query.trimmingCharacters(in: .whitespaces)
        let all = allItems
        guard !q.isEmpty else { return Array(all.prefix(60)) }
        let matches = all.filter { $0.title.localizedCaseInsensitiveContains(q) || $0.subtitle.localizedCaseInsensitiveContains(q) }
        guard isAddressLike(q) else { return matches }
        // An IP: everything covering it first, each opening its line.
        let lookup = ipLookup(q, store.model, nodes: store.headscaleNodes).map { hit in
            Item(id: "ip:" + hit.id, title: hit.title, subtitle: hit.detail,
                 icon: hit.deviceID != nil ? "desktopcomputer" : "scope", color: Theme.orange,
                 result: hit.deviceID.map { .entity("node:\($0)") }
                    ?? hit.path.flatMap { store.tree?.line(at: $0) }.map { .line($0) } ?? .entity(hit.title))
        }
        return lookup + matches.filter { m in !lookup.contains { $0.title == m.title } }
    }

    var body: some View {
        let results = self.results
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(Theme.textSecondary)
                TextField("Search groups, tags, users, devices, rules, or an IP…", text: $query)
                    .textFieldStyle(.plain)
                    .font(.system(size: 14))
                    .focused($focused)
                    .onSubmit { pick(results) }
            }
            .padding(14)
            Divider().overlay(Theme.panelBorder)
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(spacing: 1) {
                        ForEach(Array(results.enumerated()), id: \.element.id) { i, item in
                            Button { onPick(item.result) } label: {
                                HStack(spacing: 10) {
                                    Image(systemName: item.icon)
                                        .font(.system(size: 11))
                                        .foregroundStyle(item.color)
                                        .frame(width: 18)
                                    VStack(alignment: .leading, spacing: 1) {
                                        Text(verbatim: item.title)
                                            .font(.system(size: 12.5, weight: .medium))
                                            .foregroundStyle(Theme.textPrimary)
                                            .lineLimit(1)
                                        Text(verbatim: item.subtitle)
                                            .font(.system(size: 10.5))
                                            .foregroundStyle(Theme.textSecondary)
                                            .lineLimit(1)
                                    }
                                    Spacer()
                                }
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                                .background(RoundedRectangle(cornerRadius: 6)
                                    .fill(i == highlighted ? Color.white.opacity(0.09) : .clear))
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .id(i)
                        }
                        if results.isEmpty {
                            Text("No matches.")
                                .font(.system(size: 12))
                                .foregroundStyle(Theme.textSecondary)
                                .padding(20)
                        }
                    }
                    .padding(6)
                }
                .onChange(of: highlighted) { proxy.scrollTo(highlighted) }
            }
        }
        .frame(width: 520, height: 420)
        .background(Theme.background)
        .onAppear { focused = true }
        .onChange(of: query) { highlighted = 0 }
        .onKeyPress(.downArrow) {
            highlighted = min(highlighted + 1, max(results.count - 1, 0))
            return .handled
        }
        .onKeyPress(.upArrow) {
            highlighted = max(highlighted - 1, 0)
            return .handled
        }
        .onKeyPress(.escape) {
            dismiss()
            return .handled
        }
    }

    private func pick(_ results: [Item]) {
        guard results.indices.contains(highlighted) else { return }
        onPick(results[highlighted].result)
    }
}
