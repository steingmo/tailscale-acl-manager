import XCTest
@testable import TailscaleACL

/// Store tests run against a temp data folder, never the real app data.
@MainActor
final class StoreTests: XCTestCase {
    var dir: URL!
    var seedA: Workspace!
    var seedB: Workspace!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        setenv("TAILSCALE_ACL_DATA_DIR", dir.path, 1)
        // Pre-seeded workspaces keep the one-time Keychain migration from running.
        seedA = Workspace(name: "Home", serverURL: "", policy: SamplePolicy.text)
        seedB = Workspace(name: "Customer", serverURL: "https://hs.example", policy: "{\"groups\": {}}\n")
        try WorkspaceStore.save([seedA, seedB])
        UserDefaults.standard.set(seedA.id.uuidString, forKey: "currentWorkspaceID")
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        unsetenv("TAILSCALE_ACL_DATA_DIR")
    }

    func testDataDirOverride() {
        XCTAssertEqual(WorkspaceStore.fileURL.deletingLastPathComponent().path, dir.path)
    }

    func testUndoRedoOfVisualEdits() {
        let store = PolicyStore()
        let um = UndoManager()
        um.groupsByEvent = false
        store.undoManager = um
        let original = store.text
        um.beginUndoGrouping()
        store.addGrant(src: "group:ops", dstTarget: "tag:ci", ports: "22", proto: "tcp")
        um.endUndoGrouping()
        XCTAssertNotEqual(store.text, original)
        um.undo()
        XCTAssertEqual(store.text, original)
        um.redo()
        XCTAssertNotEqual(store.text, original)
    }

    func testWorkspacesPersistAndSwitch() {
        let store = PolicyStore()
        XCTAssertEqual(store.currentWorkspace.name, "Home")
        store.switchWorkspace(to: seedB.id)
        XCTAssertEqual(store.text, "{\"groups\": {}}\n")
        store.markSynced("server text")
        store.addWorkspace(name: "Lab", duplicatingCurrent: false)
        XCTAssertTrue(store.isValid)
        let reloaded = PolicyStore()
        XCTAssertEqual(reloaded.workspaces.map(\.name), ["Home", "Customer", "Lab"])
        XCTAssertEqual(reloaded.workspaces[1].lastSyncedPolicy, "server text")
    }

    func testOldWorkspaceFilesStillLoad() throws {
        // Files written before lastSyncedPolicy existed must decode, or the app would reset them.
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let legacy = #"[{"id": "\#(UUID().uuidString)", "name": "Old", "serverURL": "", "policy": "{}"}]"#
        try Data(legacy.utf8).write(to: WorkspaceStore.fileURL)
        XCTAssertEqual(WorkspaceStore.load().map(\.name), ["Old"])
        XCTAssertNil(WorkspaceStore.load().first?.lastSyncedPolicy)
    }

    func testSaveRuleKeepsOtherFieldsAndNamesRule() {
        let store = PolicyStore()
        store.loadPolicy("""
        {"grants": [
          // Old name
          {"src": ["group:a"], "dst": ["tag:x"], "ip": ["tcp:22"], "via": ["tag:router"]},
        ]}
        """)
        store.saveRule(section: "grants", index: 0, name: "Admins reach x",
                       fields: [("src", .array([.init(comments: [], value: .string("group:b"))]))])
        let g = store.model.grants[0]
        XCTAssertEqual(g.src, ["group:b"])
        XCTAssertEqual(g.via, ["tag:router"]) // untouched field kept
        XCTAssertEqual(g.comments, ["Admins reach x"])

        store.saveRule(section: "ssh", index: nil, name: "", fields: [
            ("action", .string("accept")),
            ("src", .array([.init(comments: [], value: .string("group:b"))])),
            ("dst", .array([.init(comments: [], value: .string("tag:x"))])),
            ("users", .array([.init(comments: [], value: .string("root"))])),
        ])
        XCTAssertEqual(store.model.sshRules.count, 1)
        XCTAssertTrue(store.model.sshRules[0].comments.isEmpty)
        store.deleteRule(section: "grants", index: 0)
        XCTAssertTrue(store.model.grants.isEmpty)
    }

    func testPushHistoryCap() throws {
        for i in 0..<55 {
            try PushHistory.append(PushRecord(date: Date(), server: "x", before: "\(i)", pushed: ""))
        }
        XCTAssertEqual(PushHistory.load().count, 50)
        XCTAssertEqual(PushHistory.load().first?.before, "54")
    }
}
