import Foundation

/// One push to a Headscale server: the policy that was on the server before,
/// and the policy that replaced it.
struct PushRecord: Codable, Identifiable {
    var id = UUID()
    var date: Date
    var server: String
    var before: String
    var pushed: String
}

/// Local push history in ~/Library/Application Support/TailscaleACL.
/// ponytail: one JSON file, newest 50 kept; move to per-push files if
/// policies ever get large enough for rewrite cost to matter.
enum PushHistory {
    private static let limit = 50

    static var fileURL: URL { appDataDirectory.appendingPathComponent("push-history.json") }

    static func load() -> [PushRecord] {
        guard let data = try? Data(contentsOf: fileURL) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode([PushRecord].self, from: data)) ?? []
    }

    static func append(_ record: PushRecord) throws {
        try save(Array(([record] + load()).prefix(limit)))
    }

    static func remove(id: UUID) {
        try? save(load().filter { $0.id != id })
    }

    private static func save(_ records: [PushRecord]) throws {
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted]
        try encoder.encode(records).write(to: fileURL, options: .atomic)
    }
}

/// The app's data folder. Tests point it at a temp folder with
/// TAILSCALE_ACL_DATA_DIR so they never touch real workspaces or history.
var appDataDirectory: URL {
    if let dir = ProcessInfo.processInfo.environment["TAILSCALE_ACL_DATA_DIR"] {
        return URL(fileURLWithPath: dir, isDirectory: true)
    }
    return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("TailscaleACL", isDirectory: true)
}
