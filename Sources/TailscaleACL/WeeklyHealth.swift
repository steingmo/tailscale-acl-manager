import SwiftUI

/// One line of the weekly health check, with the things behind it.
struct HealthItem: Identifiable {
    var icon: String
    var title: String
    var details: [String]
    var id: String { title }
}

/// What changed or needs attention in the last week: problems the policy
/// didn't have a week ago, policy changes made outside this app, device keys
/// and rules about to expire. Empty when there's nothing to report.
/// `pushes` are this app's pushes to the same server.
func weeklyHealth(model: PolicyModel, weekAgo: PolicyModel?, policyChanges: [PolicyChange], pushes: [PushRecord],
                  nodes: [HeadscaleNode], now: Date = Date()) -> [HealthItem] {
    var items: [HealthItem] = []
    func add(_ icon: String, _ count: Int, _ one: String, _ many: String, _ details: [String]) {
        if count > 0 { items.append(HealthItem(icon: icon, title: "\(count) \(count == 1 ? one : many)", details: details)) }
    }
    func days(_ n: Int) -> String {
        n < 0 ? "expired \(-n) day\(n == -1 ? "" : "s") ago" : n == 0 ? "expires today" : "expires in \(n) day\(n == 1 ? "" : "s")"
    }

    // Expiry problems are listed on their own below, and their text changes daily.
    func problems(_ m: PolicyModel) -> [LintIssue] { lintPolicy(m).filter { !$0.title.lowercased().contains("expir") } }
    if let weekAgo {
        let before = Set(problems(weekAgo).map(\.id))
        let new = problems(model).filter { !before.contains($0.id) }
        add("exclamationmark.triangle", new.count, "new problem since last week", "new problems since last week",
            new.map { "\($0.title): \($0.detail)" })
    }

    // The audit log also lists this app's own pushes; leave those out.
    let weekStart = now.addingTimeInterval(-7 * 86_400)
    let outside = policyChanges.filter { change in
        change.date >= weekStart && !pushes.contains { abs($0.date.timeIntervalSince(change.date)) < 300 }
    }
    add("person.crop.circle.badge.exclamationmark", outside.count, "policy change made outside this app",
        "policy changes made outside this app",
        outside.map { "\($0.date.formatted(date: .abbreviated, time: .shortened)) — \($0.who) (\($0.origin))" })

    let keys = nodes.compactMap { n in n.keyDaysLeft(now: now).map { (n, $0) } }.filter { (-7...14).contains($0.1) }
        .sorted { $0.1 < $1.1 }
    add("key", keys.count, "device key expiring", "device keys expiring", keys.map { "\($0.0.displayName) — \(days($0.1))" })

    let dated = model.rules.map { ("acls", $0.index, $0.expires) } + model.grants.map { ("grants", $0.index, $0.expires) }
        + model.sshRules.map { ("ssh", $0.index, $0.expires) }
    let expiring = dated.compactMap { section, index, expires -> String? in
        guard let expires, let left = RuleExpiry.daysLeft(expires, now: now), left <= 14 else { return nil }
        return "\(section)[\(index)] — \(days(left))"
    }
    add("clock.badge.exclamationmark", expiring.count, "rule expiring or expired", "rules expiring or expired", expiring)
    return items
}

extension PolicyStore {
    /// The weekly health check for the open workspace, against its snapshot
    /// from a week ago (History) and the server data already loaded.
    /// ponytail: policy changes come from what the Server screen last loaded
    /// (or its cache), not a fresh request.
    func weeklyHealthItems(now: Date = Date()) -> [HealthItem] {
        let old = SnapshotStore.load(currentWorkspaceID).first { $0.date <= now.addingTimeInterval(-7 * 86_400) }
        var weekAgo = old.flatMap { try? HuJSONParser.parse($0.text) }.map(PolicyModel.init(tree:))
        weekAgo?.userAutogroups = model.userAutogroups
        return weeklyHealth(model: model, weekAgo: weekAgo, policyChanges: policyChanges ?? [],
                            pushes: PushHistory.load().filter { $0.server == serverDisplayName },
                            nodes: headscaleNodes, now: now)
    }
}

/// Help ▸ Weekly Health Check, and the banner's "Show".
struct HealthSheet: View {
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var items: [HealthItem] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(verbatim: "This week in \(store.currentWorkspace.name)")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            if items.isEmpty {
                Label("Nothing needs attention: no new problems, no changes made outside this app, and nothing about to expire.",
                      systemImage: "checkmark.seal.fill")
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.green)
                    .fixedSize(horizontal: false, vertical: true)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(items) { item in
                        VStack(alignment: .leading, spacing: 3) {
                            Label(item.title, systemImage: item.icon)
                                .font(.system(size: 12.5, weight: .semibold))
                                .foregroundStyle(Theme.textPrimary)
                            ForEach(item.details, id: \.self) {
                                Text(verbatim: $0).font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                                    .fixedSize(horizontal: false, vertical: true)
                                    .textSelection(.enabled)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                        .background(RoundedRectangle(cornerRadius: 7).fill(Theme.panel))
                    }
                }
            }
            .frame(maxHeight: 420)
            Text("Compared with this workspace's version from a week ago in History. Device keys and policy changes come from the server data last loaded.")
                .font(.system(size: 10.5))
                .foregroundStyle(Theme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 560)
        .background(Theme.background)
        .onAppear { items = store.weeklyHealthItems() }
    }
}
