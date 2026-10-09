import Foundation
import CryptoKit

/// One thing a periodic access review signs off: a group's membership or a rule.
struct ReviewItem: Identifiable {
    enum Kind { case group, rule }
    var kind: Kind
    /// Changes whenever the item does (members, sources, targets, ports), so
    /// a changed item needs a fresh decision.
    var key: String
    var title: String
    var detail: String
    /// Lint-style path for the editor line, e.g. "groups[group:eng]" or "grants[3]".
    var path: String
    var id: String { key }
}

func reviewItems(_ m: PolicyModel) -> [ReviewItem] {
    func digest(_ parts: [String]) -> String {
        SHA256.hash(data: Data(parts.joined(separator: "\u{1}").utf8)).prefix(12).map { String(format: "%02x", $0) }.joined()
    }
    var items: [ReviewItem] = m.groupOrder.map { name in
        let members = m.groups[name] ?? []
        return ReviewItem(kind: .group, key: digest(["group", name] + members.sorted()), title: name,
                          detail: members.isEmpty ? "no members" : "\(members.count) member\(members.count == 1 ? "" : "s"): " + members.joined(separator: ", "),
                          path: "groups[\(name)]")
    }
    for r in ruleSummaries(m, sourceIDs: nil) {
        let detail = ([r.sources.joined(separator: ", ") + " → " + r.destinations.joined(separator: ", "), r.badge] + r.notes)
            .joined(separator: " · ")
        items.append(ReviewItem(kind: .rule, key: digest([r.section] + r.sources.sorted() + ["→"] + r.destinations.sorted() + [r.badge] + r.notes),
                                title: r.name, detail: detail, path: "\(r.section)[\(r.index)]"))
    }
    return items
}

struct ReviewDecision: Codable {
    var keep: Bool
    var by: String
    var at: Date
    var note = ""
    /// What was decided on, for the report even after the item changes or goes.
    var title: String
    var detail: String
}

/// A workspace's current access review: when it started and each decision,
/// keyed by `ReviewItem.key`. <data>/reviews/<workspace id>.json, encrypted
/// like the other data files.
struct AccessReview: Codable {
    var started: Date?
    var decisions: [String: ReviewDecision] = [:]

    static func fileURL(_ workspace: UUID) -> URL {
        appDataDirectory.appendingPathComponent("reviews", isDirectory: true)
            .appendingPathComponent("\(workspace.uuidString).json")
    }

    static func load(_ workspace: UUID) -> AccessReview {
        guard let data = DataEncryption.read(fileURL(workspace)) else { return AccessReview() }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode(AccessReview.self, from: data)) ?? AccessReview()
    }

    func save(_ workspace: UUID) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        if let data = try? encoder.encode(self) { try? DataEncryption.write(data, to: Self.fileURL(workspace)) }
    }

    static func delete(_ workspace: UUID) {
        try? FileManager.default.removeItem(at: fileURL(workspace))
    }
}

/// The review as Markdown, for auditors: decisions with who and when,
/// what's still open, and decided items no longer in the policy.
func accessReviewReport(workspace: String, review: AccessReview, items: [ReviewItem], date: Date = Date()) -> String {
    let day = DateFormatter()
    day.dateFormat = "yyyy-MM-dd"
    day.locale = Locale(identifier: "en_US_POSIX")
    func line(_ title: String, _ detail: String, _ d: ReviewDecision?) -> String {
        var s = "- **\(title)** — \(detail)"
        if let d { s += " — \(d.by), \(day.string(from: d.at))" + (d.note.isEmpty ? "" : ": \(d.note)") }
        return s
    }
    let current = Set(items.map(\.key))
    let kept = items.filter { review.decisions[$0.key]?.keep == true }
    let remove = items.filter { review.decisions[$0.key]?.keep == false }
    let open = items.filter { review.decisions[$0.key] == nil }
    let gone = review.decisions.filter { !current.contains($0.key) }.values.sorted { $0.at < $1.at }

    var out = ["# Access review — \(workspace)", ""]
    out.append("Started \(review.started.map(day.string) ?? "—"), exported \(day.string(from: date)). "
               + "\(items.count) items: \(kept.count) kept, \(remove.count) to remove, \(open.count) not reviewed.")
    let reviewers = Set(review.decisions.values.map(\.by)).sorted()
    if !reviewers.isEmpty { out.append("Reviewed by \(reviewers.joined(separator: ", ")).") }
    func section(_ title: String, _ lines: [String]) {
        guard !lines.isEmpty else { return }
        out += ["", "## \(title)", ""] + lines
    }
    section("To remove", remove.map { line($0.title, $0.detail, review.decisions[$0.key]) })
    section("Not reviewed", open.map { line($0.title, $0.detail, nil) })
    section("Kept", kept.map { line($0.title, $0.detail, review.decisions[$0.key]) })
    section("No longer in the policy (removed or changed since the decision)",
            gone.map { line($0.title, $0.detail, $0) + ($0.keep ? " (was kept)" : " (was marked for removal)") })
    return out.joined(separator: "\n") + "\n"
}

extension PolicyStore {
    func decide(_ item: ReviewItem, keep: Bool?, by reviewer: String) {
        if let keep {
            let note = review.decisions[item.key]?.note ?? ""
            review.decisions[item.key] = ReviewDecision(keep: keep, by: reviewer, at: Date(), note: note,
                                                        title: item.title, detail: item.detail)
        } else {
            review.decisions[item.key] = nil
        }
        review.save(currentWorkspaceID)
    }

    func setReviewNote(_ item: ReviewItem, _ note: String) {
        review.decisions[item.key]?.note = note
        review.save(currentWorkspaceID)
    }

    func startNewReview() {
        review = AccessReview(started: Date())
        review.save(currentWorkspaceID)
    }

    /// Delete the rules and groups marked for removal in one undoable edit;
    /// groups go with every reference to them. Push as usual afterwards.
    func applyReviewRemovals(_ items: [ReviewItem]) {
        let marked = items.filter { review.decisions[$0.key]?.keep == false }
        let rules = marked.filter { $0.kind == .rule }.compactMap { item -> (String, Int)? in
            guard let open = item.path.firstIndex(of: "["), let i = Int(item.path[item.path.index(after: open)...].dropLast()) else { return nil }
            return (String(item.path[..<open]), i)
        }
        mutate { tree in
            for (section, index) in rules.sorted(by: { $0.1 > $1.1 }) {
                guard var list = tree[section]?.elements, list.indices.contains(index) else { continue }
                list.remove(at: index)
                tree[section] = .array(list)
            }
        }
        for group in marked.filter({ $0.kind == .group }) { deleteEntity(group.title) }
    }
}
