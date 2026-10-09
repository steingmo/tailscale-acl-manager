import Foundation

/// The last devices (with posture attributes), users, and policy changes
/// from a workspace's server, shown at once when the workspace opens while
/// fresh ones load. <data>/server-cache/<workspace id>.json, encrypted like
/// the other data files.
struct ServerCache: Codable {
    var saved: Date
    var nodes: [HeadscaleNode]
    var accounts: [ServerAccount]
    var policyChanges: [PolicyChange]?

    static func fileURL(_ workspace: UUID) -> URL {
        appDataDirectory.appendingPathComponent("server-cache", isDirectory: true)
            .appendingPathComponent("\(workspace.uuidString).json")
    }

    static func load(_ workspace: UUID) -> ServerCache? {
        guard let data = DataEncryption.read(fileURL(workspace)) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(ServerCache.self, from: data)
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
