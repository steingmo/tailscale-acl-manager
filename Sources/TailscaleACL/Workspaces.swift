import Foundation

/// A named policy + optional Headscale server (e.g. home lab, work, a customer).
/// The server's API key lives in the Keychain under the workspace id.
struct Workspace: Codable, Identifiable, Equatable {
    var id = UUID()
    var name: String
    var serverURL: String
    var policy: String
    /// Server policy text as of the last pull or push, to detect changes made
    /// on the server by someone else before the next push.
    var lastSyncedPolicy: String?
}

/// Workspaces persisted in ~/Library/Application Support/TailscaleACL.
enum WorkspaceStore {
    static var fileURL: URL {
        appDataDirectory.appendingPathComponent("workspaces.json")
    }

    static func load() -> [Workspace] {
        guard let data = try? Data(contentsOf: fileURL) else { return [] }
        return (try? JSONDecoder().decode([Workspace].self, from: data)) ?? []
    }

    static func save(_ workspaces: [Workspace]) throws {
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted]
        try encoder.encode(workspaces).write(to: fileURL, options: .atomic)
    }

    /// First launch after workspaces were introduced: carry the single saved
    /// server URL and API key over into a "Default" workspace.
    static func migrateLegacy() -> Workspace {
        let ws = Workspace(name: "Default",
                           serverURL: UserDefaults.standard.string(forKey: "headscaleURL") ?? "",
                           policy: SamplePolicy.text)
        if let key = HeadscaleKeychain.load(account: HeadscaleKeychain.legacyAccount) {
            HeadscaleKeychain.save(key, account: ws.id.uuidString)
            // Old item is removed only once the workspace file is safely written.
            if (try? save([ws])) != nil {
                HeadscaleKeychain.save("", account: HeadscaleKeychain.legacyAccount)
            }
        }
        return ws
    }
}
