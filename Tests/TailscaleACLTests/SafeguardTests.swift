import XCTest
@testable import TailscaleACL

/// Push guard, History's large-change snapshot, automatic backups, rule
/// explanations, and the weekly health check.
@MainActor
final class SafeguardTests: XCTestCase {
    var dir: URL!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        setenv("TAILSCALE_ACL_DATA_DIR", dir.path, 1)
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        unsetenv("TAILSCALE_ACL_DATA_DIR")
    }

    func policy(_ name: String, rules: Int) -> String {
        let grants = (0..<rules).map { #"{"src": ["group:\#(name)\#($0)"], "dst": ["tag:\#(name)-server-\#($0)"], "ip": ["tcp:443"]}"# }
        return "{\"grants\": [\n" + grants.joined(separator: ",\n") + "\n]}"
    }

    // MARK: History

    func testLargeChangeIsAReplacementNotTyping() {
        let a = policy("alpha", rules: 6)
        XCTAssertFalse(isLargeChange(from: a, to: a.replacingOccurrences(of: "tcp:443\"]}\n", with: "tcp:443\", \"tcp:22\"]}\n")))
        XCTAssertFalse(isLargeChange(from: a, to: a + "\n// a comment added at the end"))
        XCTAssertTrue(isLargeChange(from: a, to: policy("beta", rules: 6)))
        XCTAssertTrue(isLargeChange(from: a, to: ""))
        XCTAssertFalse(isLargeChange(from: "", to: a))
    }

    func testReplacingASavedPolicyKeepsTheOldOneInHistory() throws {
        let a = Workspace(name: "A", serverURL: "", policy: policy("alpha", rules: 6))
        let b = Workspace(name: "B", serverURL: "", policy: "{}")
        try WorkspaceStore.save([a, b])
        UserDefaults.standard.set(a.id.uuidString, forKey: "currentWorkspaceID")
        let store = PolicyStore()
        // Not a pull, import, or restore: the text just changes, as in the 1.31.5 bug.
        store.text = policy("beta", rules: 6)
        store.reparseNow()
        // Already History's newest version (saved on open): not saved twice.
        XCTAssertEqual(SnapshotStore.load(a.id).map(\.text), [a.policy])

        // Typed edits since the last version are what would otherwise be lost.
        let typed = a.policy + "\n// typed since opening"
        store.text = typed
        store.reparseNow()
        XCTAssertEqual(SnapshotStore.load(a.id).count, 2, "going back is a large change too")
        store.text = policy("gamma", rules: 6)
        store.switchWorkspace(to: b.id)
        let newest = SnapshotStore.load(a.id).first
        XCTAssertEqual(newest?.text, typed)
        XCTAssertEqual(newest?.reason, largeChangeReason)
    }

    // MARK: Push guard

    func testPushWarnings() {
        let prod = Workspace(name: "Prod", serverURL: "https://prod.example.com", policy: policy("prod", rules: 6))
        let test = Workspace(name: "Test", serverURL: "https://test.example.com", policy: policy("test", rules: 6))
        let copy = Workspace(name: "Prod copy", serverURL: "https://prod.example.com", policy: prod.policy)
        let all = [prod, test, copy]

        // Test's policy about to go to prod: both warnings.
        let wrong = pushWarnings(server: prod.policy, candidate: test.policy + "\n", workspace: prod, all: all)
        XCTAssertEqual(wrong.count, 2)
        XCTAssertTrue(wrong[0].contains("Test"))
        XCTAssertTrue(wrong[1].hasPrefix("6 of the 6 rules"))

        // One rule edited; a duplicate workspace for the same server holds the same text.
        let edited = prod.policy.replacingOccurrences(of: "group:prod0", with: "group:ops")
        XCTAssertEqual(pushWarnings(server: prod.policy, candidate: edited, workspace: prod, all: all), [])
        XCTAssertEqual(pushWarnings(server: edited, candidate: prod.policy, workspace: prod, all: all), [])
        // Nothing to push, nothing to warn about.
        XCTAssertEqual(pushWarnings(server: test.policy, candidate: test.policy, workspace: prod, all: all), [])
    }

    // MARK: Automatic backup

    func testAutoBackupWritesOnePerDayAndKeepsTheNewest() throws {
        try WorkspaceStore.save([Workspace(name: "A", serverURL: "", policy: "{}")])
        let folder = dir.appendingPathComponent("out")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let manual = folder.appendingPathComponent("Tailscale ACL backup 2020-01-01.tsaclbackup")
        try Data("mine".utf8).write(to: manual)
        let day = Date(timeIntervalSince1970: 1_800_000_000)
        var last: URL!
        for i in 0..<4 {
            last = try AutoBackup.run(password: "correct horse", folder: folder, now: day.addingTimeInterval(Double(i) * 86_400),
                                      rounds: 1_000, keep: 2)
        }
        // The same day again replaces that day's file.
        try AutoBackup.run(password: "correct horse", folder: folder, now: day.addingTimeInterval(3 * 86_400), rounds: 1_000, keep: 2)
        let files = try FileManager.default.contentsOfDirectory(atPath: folder.path).sorted()
        XCTAssertEqual(files.filter { $0.hasPrefix(AutoBackup.prefix) }.count, 2)
        XCTAssertTrue(files.contains(last.lastPathComponent))
        XCTAssertTrue(files.contains(manual.lastPathComponent), "only automatic backups are pruned")
        let archive = try Backup.open(Data(contentsOf: last), password: "correct horse")
        XCTAssertNotNil(archive.files["workspaces.json"])
        // Backups aren't data files: the next backup doesn't contain them.
        XCTAssertFalse(DataEncryption.dataFiles.contains { $0.path.contains("backups") })
    }

    // MARK: Explanations

    func testRuleExplanations() {
        let m = model("""
        {
          "hosts": {"nas": "10.0.0.5"},
          "postures": {"posture:managed": ["node:os == 'macos'"]},
          "grants": [
            {"src": ["group:mgmt-vpn"], "dst": ["tag:prod"], "ip": ["tcp:22", "tcp:443"], "srcPosture": ["posture:managed"]},
            {"src": ["*"], "dst": ["autogroup:internet"], "ip": ["*"], "via": ["tag:exit"]},
            {"src": ["autogroup:member"], "dst": ["tag:dns"], "ip": ["tcp:53", "udp:53", "icmp:*"]},
          ],
          "acls": [
            {"action": "accept", "src": ["alice@example.com", "tag:ci"], "dst": ["nas:445", "tag:db:5432,8000-8100", "tag:web:*"]},
          ],
          "ssh": [
            {"action": "check", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["autogroup:nonroot", "root"]},
          ],
        }
        """)
        XCTAssertEqual(ruleExplanation(m, kind: .grant, index: 0),
                       "Everyone in mgmt-vpn can reach devices tagged prod on SSH and HTTPS, only from devices that pass the managed posture check.")
        XCTAssertEqual(ruleExplanation(m, kind: .grant, index: 1),
                       "Everyone can reach the internet through exit nodes on any port, routed through devices tagged exit.")
        XCTAssertEqual(ruleExplanation(m, kind: .grant, index: 2),
                       "Every member of the tailnet can reach devices tagged dns on DNS and ping.")
        XCTAssertEqual(ruleExplanation(m, kind: .acl, index: 0),
                       "Alice@example.com and devices tagged ci can reach nas (10.0.0.5) on SMB, devices tagged db on PostgreSQL and ports 8000-8100 and devices tagged web on any port.")
        XCTAssertEqual(ruleExplanation(m, kind: .ssh, index: 0),
                       "Every member of the tailnet can SSH into their own devices as any user except root or root, after signing in again.")
        XCTAssertNil(ruleExplanation(m, kind: .grant, index: 9))
    }

    // MARK: Weekly health

    func testWeeklyHealth() {
        let now = RuleExpiry.formatter.date(from: "2026-11-09")!.addingTimeInterval(12 * 3_600)
        let before = model(#"{"groups": {"group:eng": ["a@example.com"]}, "grants": [{"src": ["group:eng"], "dst": ["*"], "ip": ["*"]}]}"#)
        let after = model("""
        {"groups": {"group:eng": ["a@example.com"]}, "grants": [
          {"src": ["group:eng"], "dst": ["*"], "ip": ["*"]},
          // expires: 2026-11-12
          {"src": ["group:gone"], "dst": ["*"], "ip": ["*"]},
        ]}
        """)
        let push = PushRecord(date: now.addingTimeInterval(-3 * 86_400), server: "s", before: "", pushed: "")
        let changes = [
            PolicyChange(date: now.addingTimeInterval(-3 * 86_400 + 20), who: "me@example.com", origin: "API"),   // our push
            PolicyChange(date: now.addingTimeInterval(-2 * 86_400), who: "bob@example.com", origin: "admin console"),
            PolicyChange(date: now.addingTimeInterval(-20 * 86_400), who: "bob@example.com", origin: "admin console"),
        ]
        let soon = ISO8601DateFormatter().string(from: now.addingTimeInterval(5 * 86_400 + 60))
        let later = ISO8601DateFormatter().string(from: now.addingTimeInterval(90 * 86_400))
        let devices = [HeadscaleNode(id: "1", name: "laptop", expiry: soon), HeadscaleNode(id: "2", name: "desk", expiry: later),
                       HeadscaleNode(id: "3", name: "server")]

        let items = weeklyHealth(model: after, weekAgo: before, policyChanges: changes, pushes: [push], nodes: devices, now: now)
        XCTAssertEqual(items.map(\.title), ["1 new problem since last week", "1 policy change made outside this app",
                                            "1 device key expiring", "1 rule expiring or expired"])
        XCTAssertTrue(items[0].details[0].contains("group:gone"))
        XCTAssertTrue(items[1].details[0].contains("bob@example.com"))
        XCTAssertEqual(items[2].details, ["laptop — expires in 5 days"])
        XCTAssertEqual(items[3].details, ["grants[1] — expires in 3 days"])
        XCTAssertTrue(weeklyHealth(model: before, weekAgo: before, policyChanges: [], pushes: [], nodes: [devices[1]], now: now).isEmpty)
    }

    func testWorkspaceColourDefaultsToListPosition() throws {
        let a = Workspace(name: "A", serverURL: "", policy: "{}"), b = Workspace(name: "B", serverURL: "", policy: "{}")
        try WorkspaceStore.save([a, b])
        UserDefaults.standard.set(b.id.uuidString, forKey: "currentWorkspaceID")
        let store = PolicyStore()
        XCTAssertEqual(store.colorIndex(of: a.id), 0)
        XCTAssertEqual(store.colorIndex(of: b.id), 1)
        store.setWorkspaceColor(4)
        XCTAssertEqual(WorkspaceStore.load().first { $0.id == b.id }?.color, 4)
    }
}
