import Foundation

/// A saved copy of a workspace's policy at a milestone (opened, pulled,
/// imported, pushed, restored, or saved by hand).
struct Snapshot: Codable, Identifiable {
    var id = UUID()
    var date: Date
    var reason: String
    var text: String
}

/// Per-workspace snapshots in <app data>/snapshots/<workspace id>.json.
/// ponytail: whole-file rewrite per snapshot, newest 100 kept; fine for
/// policy-sized text, split per snapshot if files grow large.
enum SnapshotStore {
    private static let limit = 100

    static func fileURL(_ workspace: UUID) -> URL {
        appDataDirectory.appendingPathComponent("snapshots", isDirectory: true)
            .appendingPathComponent("\(workspace.uuidString).json")
    }

    static func load(_ workspace: UUID) -> [Snapshot] {
        guard let data = try? Data(contentsOf: fileURL(workspace)) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode([Snapshot].self, from: data)) ?? []
    }

    /// Records `text` unless it equals the newest snapshot. Newest first.
    static func record(_ workspace: UUID, text: String, reason: String, date: Date = Date()) {
        var list = load(workspace)
        guard list.first?.text != text else { return }
        list.insert(Snapshot(date: date, reason: reason, text: text), at: 0)
        let url = fileURL(workspace)
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        try? encoder.encode(Array(list.prefix(limit))).write(to: url, options: .atomic)
    }

    static func delete(_ workspace: UUID) {
        try? FileManager.default.removeItem(at: fileURL(workspace))
    }
}
