import XCTest
import CryptoKit
@testable import TailscaleACL

/// Encryption is exercised with an injected key; enable()/disable() also
/// touch the real Keychain and defaults, so they're left to manual testing.
final class DataProtectionTests: XCTestCase {
    var dir: URL!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        setenv("TAILSCALE_ACL_DATA_DIR", dir.path, 1)
        DataEncryption.key = nil
    }

    override func tearDown() async throws {
        DataEncryption.key = nil
        try? FileManager.default.removeItem(at: dir)
        unsetenv("TAILSCALE_ACL_DATA_DIR")
    }

    func testRoundTripHidesContents() throws {
        DataEncryption.key = SymmetricKey(size: .bits256)
        let url = dir.appendingPathComponent("x.json")
        let secret = Data(#"{"groups": {"group:dc-admins": ["amy@x.com"]}}"#.utf8)
        try DataEncryption.write(secret, to: url)
        let raw = try Data(contentsOf: url)
        XCTAssertTrue(DataEncryption.isEncrypted(raw))
        XCTAssertNil(raw.range(of: Data("dc-admins".utf8)), "nothing readable on disk")
        XCTAssertEqual(DataEncryption.read(url), secret)

        DataEncryption.key = SymmetricKey(size: .bits256)
        XCTAssertNil(DataEncryption.read(url), "a different key can't read it")
        DataEncryption.key = nil
        XCTAssertTrue(DataEncryption.isUnreadable(url))
    }

    func testNeverOverwritesEncryptedWithPlainText() throws {
        DataEncryption.key = SymmetricKey(size: .bits256)
        let url = dir.appendingPathComponent("x.json")
        try DataEncryption.write(Data("a".utf8), to: url)
        DataEncryption.key = nil
        XCTAssertThrowsError(try DataEncryption.write(Data("b".utf8), to: url))
        XCTAssertTrue(DataEncryption.isEncrypted(try Data(contentsOf: url)), "file untouched")
    }

    func testMigratesEveryStoreBothWays() throws {
        let ws = Workspace(name: "Office", serverURL: "", policy: #"{"groups": {"group:secret": []}}"#)
        try WorkspaceStore.save([ws])
        try PushHistory.append(PushRecord(date: Date(), server: "hs", before: "{}", pushed: "{\"a\": 1}"))
        SnapshotStore.record(ws.id, text: "{\"snap\": 1}", reason: "test")
        ActivityLog.record(ActivityEntry(date: Date(), user: "u", workspace: "Office", server: "hs",
                                         action: "Push the policy", detail: "x", error: nil))
        XCTAssertEqual(DataEncryption.dataFiles.count, 4)

        DataEncryption.key = SymmetricKey(size: .bits256)
        try DataEncryption.rewriteAll(encrypted: true)
        for url in DataEncryption.dataFiles {
            XCTAssertTrue(DataEncryption.isEncrypted(try Data(contentsOf: url)), url.lastPathComponent)
        }
        // The stores read through it transparently, and new writes stay encrypted.
        XCTAssertEqual(WorkspaceStore.load().first?.name, "Office")
        XCTAssertEqual(PushHistory.load().count, 1)
        XCTAssertEqual(SnapshotStore.load(ws.id).first?.text, "{\"snap\": 1}")
        ActivityLog.record(ActivityEntry(date: Date(), user: "u", workspace: "Office", server: "hs",
                                         action: "Delete a device", detail: "7", error: nil))
        XCTAssertEqual(ActivityLog.recent().map(\.action), ["Delete a device", "Push the policy"])
        XCTAssertTrue(DataEncryption.isEncrypted(try Data(contentsOf: ActivityLog.fileURL)))

        try DataEncryption.rewriteAll(encrypted: false)
        DataEncryption.key = nil
        for url in DataEncryption.dataFiles {
            XCTAssertFalse(DataEncryption.isEncrypted(try Data(contentsOf: url)), url.lastPathComponent)
        }
        XCTAssertEqual(WorkspaceStore.load().first?.policy, #"{"groups": {"group:secret": []}}"#)
        XCTAssertEqual(ActivityLog.recent().count, 2)
    }

    func testPlainFilesStillReadWithAKey() throws {
        let url = dir.appendingPathComponent("legacy.json")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try Data("[]".utf8).write(to: url)
        DataEncryption.key = SymmetricKey(size: .bits256)
        XCTAssertEqual(DataEncryption.read(url), Data("[]".utf8))
    }
}
