import XCTest
@testable import TailscaleACL

/// Regression: results of server calls that finished after a workspace switch
/// landed in the newly opened workspace (a Pull overwrote it with the other
/// workspace's policy), and typing just before a switch wasn't saved.
@MainActor
final class WorkspaceSwitchTests: XCTestCase {
    var dir: URL!
    var a: Workspace!
    var b: Workspace!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        setenv("TAILSCALE_ACL_DATA_DIR", dir.path, 1)
        a = Workspace(name: "A", serverURL: "", policy: #"{"grants": [{"src": ["group:a"], "dst": ["tag:a"], "ip": ["*"]}]}"#)
        b = Workspace(name: "B", serverURL: "", policy: #"{"grants": [{"src": ["group:b"], "dst": ["tag:b"], "ip": ["443"]}, {"src": ["group:b"], "dst": ["tag:c"], "ip": ["22"]}]}"#)
        try WorkspaceStore.save([a, b])
        UserDefaults.standard.set(a.id.uuidString, forKey: "currentWorkspaceID")
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        unsetenv("TAILSCALE_ACL_DATA_DIR")
    }

    func saved(_ ws: Workspace) -> String? { WorkspaceStore.load().first { $0.id == ws.id }?.policy }

    func testEachWorkspaceShowsItsOwnRules() {
        let store = PolicyStore()
        for _ in 0..<3 {
            XCTAssertEqual(store.model.grants.map(\.src), [["group:a"]])
            store.switchWorkspace(to: b.id)
            XCTAssertEqual(store.model.grants.map(\.src), [["group:b"], ["group:b"]])
            XCTAssertEqual(store.text, b.policy)
            store.switchWorkspace(to: a.id)
        }
        XCTAssertEqual(saved(a), a.policy)
        XCTAssertEqual(saved(b), b.policy)
    }

    /// Switching away from a workspace whose server users were loaded wrote
    /// its policy into the workspace being opened.
    func testSwitchingWithServerUsersLoadedKeepsPolicies() {
        let store = PolicyStore()
        store.serverUserAutogroups = ["amy@example.com": ["autogroup:admin"]]
        store.switchWorkspace(to: b.id)
        XCTAssertEqual(store.text, b.policy)
        XCTAssertEqual(saved(a), a.policy)
        XCTAssertEqual(saved(b), b.policy)
        store.serverUserAutogroups = ["bob@example.com": ["autogroup:owner"]]
        store.switchWorkspace(to: a.id)
        XCTAssertEqual(store.text, a.policy)
        XCTAssertEqual(saved(b), b.policy)
    }

    func testLateServerResultsDontLandInAnotherWorkspace() {
        let store = PolicyStore()
        let startedOn = store.currentWorkspaceID          // a Pull starts in A…
        store.switchWorkspace(to: b.id)                   // …the user switches to B…
        // …and A's server answers afterwards.
        XCTAssertFalse(store.applyPulledPolicy(#"{"grants": []}"#, for: startedOn))
        XCTAssertFalse(store.applyNodes([HeadscaleNode(id: "1", name: "a-device")], for: startedOn))
        XCTAssertFalse(store.applyPolicyChanges([PolicyChange(date: Date(), who: "x", origin: "API")], for: startedOn))
        XCTAssertEqual(store.text, b.policy, "B still shows B")
        XCTAssertTrue(store.headscaleNodes.isEmpty)
        XCTAssertNil(store.policyChanges)
        XCTAssertEqual(saved(a), a.policy)
        XCTAssertEqual(saved(b), b.policy, "nothing autosaved into B")
        XCTAssertNil(WorkspaceStore.load().first { $0.id == b.id }?.lastSyncedPolicy)

        // Results for the open workspace still apply.
        XCTAssertTrue(store.applyPulledPolicy(#"{"grants": []}"#, for: b.id))
        XCTAssertEqual(saved(b), #"{"grants": []}"#)
    }

    func testTypingJustBeforeASwitchIsSavedToItsWorkspace() {
        let store = PolicyStore()
        let edited = #"{"grants": [{"src": ["group:a2"], "dst": ["tag:a"], "ip": ["*"]}]}"#
        store.text = edited                     // still inside the typing debounce
        store.switchWorkspace(to: b.id)
        XCTAssertEqual(saved(a), edited)
        XCTAssertEqual(saved(b), b.policy)
        store.switchWorkspace(to: a.id)
        XCTAssertEqual(store.model.grants.first?.src, ["group:a2"])
    }
}
