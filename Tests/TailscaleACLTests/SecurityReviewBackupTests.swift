import XCTest
import CryptoKit
@testable import TailscaleACL

final class SecurityReviewTests: XCTestCase {
    func titles(_ text: String) -> [String] { lintSecurity(model(text)).map(\.title) }

    func testTagOwnersWhoGainAccess() {
        let m = model("""
        {"groups": {"group:eng": ["amy@x.com"]},
         "tagOwners": {"tag:server": ["group:eng"], "tag:open": ["autogroup:member"], "tag:ok": ["group:eng"]},
         "grants": [
           {"src": ["tag:server"], "dst": ["10.0.0.0/8"], "ip": ["*"]},
           {"src": ["tag:ok"], "dst": ["tag:ok"], "ip": ["443"]},
           {"src": ["group:eng"], "dst": ["tag:ok"], "ip": ["443"]},
         ]}
        """)
        let issues = lintSecurity(m)
        let gain = issues.first { $0.title == "Tag owners gain access through tag:server" }
        XCTAssertNotNil(gain)
        XCTAssertTrue(gain!.detail.contains("10.0.0.0/8"))
        XCTAssertTrue(issues.contains { $0.title == "Anyone can apply tag:open" })
        XCTAssertFalse(issues.contains { $0.title.contains("tag:ok") }, "no new access through tag:ok")
        if case .setTagOwners(let tag, let owners)? = gain?.fixes.first?.action {
            XCTAssertEqual(tag, "tag:server")
            XCTAssertEqual(owners, ["autogroup:admin"])
        } else { XCTFail("expected a fix") }
        XCTAssertTrue(issues.allSatisfy(\.security))
    }

    func testOwnerWhoAlreadyReachesEverythingGainsNothing() {
        // In the sample, group:ops owns tag:web but already reaches *:*.
        let t = titles(SamplePolicy.text)
        XCTAssertFalse(t.contains { $0.hasPrefix("Tag owners gain access") }, t.joined(separator: "; "))
        XCTAssertTrue(t.contains("SSH as root without check mode"))
        let covered = titles("""
        {"groups": {"group:net": ["amy@x.com"]}, "tagOwners": {"tag:r": ["group:net"]},
         "grants": [{"src": ["tag:r"], "dst": ["10.1.2.0/24"], "ip": ["*"]},
                    {"src": ["group:net"], "dst": ["10.0.0.0/8"], "ip": ["*"]}]}
        """)
        XCTAssertFalse(covered.contains { $0.hasPrefix("Tag owners gain access") }, "10.0.0.0/8 covers 10.1.2.0/24")
    }

    func testBroadApproversRootSSHAndOpenPorts() {
        let t = titles("""
        {"autoApprovers": {"routes": {"10.0.0.0/8": ["autogroup:member"]}, "exitNode": ["*"]},
         "acls": [{"action": "accept", "src": ["*"], "dst": ["tag:win:3389,443"]}],
         "grants": [{"src": ["autogroup:member"], "dst": ["tag:db"], "ip": ["tcp:5432"]}],
         "ssh": [{"action": "accept", "src": ["group:ops"], "dst": ["tag:server"], "users": ["root"]},
                 {"action": "accept", "src": ["tag:ci"], "dst": ["tag:server"], "users": ["root"]}],
         "tagOwners": {"tag:win": [], "tag:db": [], "tag:server": [], "tag:ci": []}, "groups": {"group:ops": []}}
        """)
        XCTAssertTrue(t.contains("Anyone can get 10.0.0.0/8 approved"))
        XCTAssertTrue(t.contains("Anyone can become an exit node"))
        XCTAssertTrue(t.contains("RDP open to everyone"))
        XCTAssertTrue(t.contains("PostgreSQL open to everyone"))
        XCTAssertEqual(t.filter { $0 == "SSH as root without check mode" }.count, 1, "tag-only sources are machines, not people")
        XCTAssertTrue(t.contains("Sensitive access without deny tests"))
    }

    func testServersReachingPeopleDangerAllAndDenyTests() {
        let t = titles("""
        {"grants": [
           {"src": ["tag:web"], "dst": ["autogroup:member"], "ip": ["*"]},
           {"src": ["autogroup:danger-all"], "dst": ["tag:pub"], "ip": ["443"]},
           {"src": ["group:eng"], "dst": ["tag:db"], "ip": ["tcp:5432"]},
         ],
         "tests": [{"src": "eve@x.com", "deny": ["tag:db:5432"]}],
         "tagOwners": {"tag:web": [], "tag:pub": [], "tag:db": []}, "groups": {"group:eng": []}}
        """)
        XCTAssertTrue(t.contains("Servers can reach people's devices"))
        XCTAssertTrue(t.contains("autogroup:danger-all in use"))
        XCTAssertFalse(t.contains("Sensitive access without deny tests"), "tag:db is pinned by a deny test")
    }
}

@MainActor
final class SecurityFixStoreTests: XCTestCase {
    var dir: URL!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        setenv("TAILSCALE_ACL_DATA_DIR", dir.path, 1)
        let ws = Workspace(name: "Home", serverURL: "", policy: """
        {"ssh": [{"action": "accept", "src": ["group:ops"], "dst": ["tag:s"], "users": ["root"]}],
         "tagOwners": {"tag:s": ["autogroup:member"]}, "groups": {"group:ops": []},
         "grants": [{"src": ["group:ops"], "dst": ["tag:s"], "ip": ["*"]}]}
        """)
        try WorkspaceStore.save([ws])
        UserDefaults.standard.set(ws.id.uuidString, forKey: "currentWorkspaceID")
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        unsetenv("TAILSCALE_ACL_DATA_DIR")
    }

    func testFixesApply() {
        let store = PolicyStore()
        for title in ["SSH as root without check mode", "Anyone can apply tag:s"] {
            let issue = store.lintIssues.first { $0.title == title }
            XCTAssertNotNil(issue, title)
            store.apply(issue!.fixes[0].action)
        }
        XCTAssertEqual(store.model.sshRules.first?.action, "check")
        XCTAssertEqual(store.model.tagOwners["tag:s"], ["autogroup:admin"])
    }

    func testNarrowing() {
        let store = PolicyStore()
        store.narrowRule(section: "grants", index: 0, to: ["udp:88", "tcp:443", "tcp:88"])
        XCTAssertEqual(store.model.grants.first?.ip, ["tcp:88", "udp:88", "tcp:443"])

        var tree = try! HuJSONParser.parse(#"{"acls": [{"action": "accept", "src": ["a@x.com"], "dst": ["tag:a:*", "[fd7a::1]:*"]}]}"#)
        XCTAssertTrue(narrowRulePorts(&tree, section: "acls", index: 0, to: ["tcp:443", "udp:443", "tcp:22"]))
        XCTAssertEqual(PolicyModel(tree: tree).rules.first?.dst, ["tag:a:22,443", "[fd7a::1]:22,443"])
        XCTAssertFalse(narrowRulePorts(&tree, section: "acls", index: 5, to: ["tcp:1"]))
    }
}

final class BackupTests: XCTestCase {
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

    func testBackupRoundTripAndRestore() throws {
        let ws = Workspace(name: "Office", serverURL: "", policy: #"{"groups": {"group:secret": []}}"#)
        try WorkspaceStore.save([ws])
        SnapshotStore.record(ws.id, text: "{\"v\": 1}", reason: "test")
        let backup = try Backup.make(password: "correct horse battery", rounds: 1_000)
        XCTAssertNil(backup.range(of: Data("group:secret".utf8)), "encrypted")
        XCTAssertThrowsError(try Backup.open(backup, password: "wrong password!!"))

        // Change the data, then restore: the backup wins, the old files are kept aside.
        try WorkspaceStore.save([Workspace(name: "Changed", serverURL: "", policy: "{}")])
        let archive = try Backup.open(backup, password: "correct horse battery")
        XCTAssertEqual(Set(archive.files.keys), ["workspaces.json", "snapshots/\(ws.id.uuidString).json"])
        DataEncryption.key = SymmetricKey(size: .bits256)   // restoring follows the current encryption setting
        let aside = try Backup.restore(archive)
        XCTAssertEqual(WorkspaceStore.load().map(\.name), ["Office"])
        XCTAssertEqual(SnapshotStore.load(ws.id).first?.text, "{\"v\": 1}")
        XCTAssertTrue(DataEncryption.isEncrypted(try Data(contentsOf: WorkspaceStore.fileURL)))
        let kept = try Data(contentsOf: aside.appendingPathComponent("workspaces.json"))
        XCTAssertTrue(String(decoding: kept, as: UTF8.self).contains("Changed"))
    }

    func testRejectsPathsOutsideTheDataFolder() {
        XCTAssertTrue(Backup.isAllowedPath("workspaces.json"))
        XCTAssertTrue(Backup.isAllowedPath("snapshots/\(UUID().uuidString).json"))
        XCTAssertFalse(Backup.isAllowedPath("../workspaces.json"))
        XCTAssertFalse(Backup.isAllowedPath("snapshots/../../.zshrc"))
        XCTAssertFalse(Backup.isAllowedPath("/etc/hosts"))
    }
}

final class AuditReportTests: XCTestCase {
    func testSections() {
        let m = model("""
        {"grants": [
           // Contractor
           // expires: 2026-09-01
           {"src": ["old@x.com"], "dst": ["tag:db"], "ip": ["*"]},
           {"src": ["*"], "dst": ["tag:db"], "ip": ["tcp:5432"]},
         ], "tagOwners": {"tag:db": []}}
        """)
        let stale = HeadscaleNode(id: "1", name: "old-pi", online: false, lastSeen: "2026-06-01T00:00:00Z")
        let date = ISO8601DateFormatter().date(from: "2026-10-07T00:00:00Z")!
        let report = auditReport(workspace: "Office", server: "Tailscale (-)", model: m, nodes: [stale], traffic: nil,
                                 serverLogins: ["amy@x.com"], credential: CredentialInfo(kind: "OAuth client", scopes: ["policy_file"]),
                                 date: date)
        XCTAssertTrue(report.hasPrefix("# Access audit — Office"))
        XCTAssertTrue(report.contains("**PostgreSQL open to everyone**"))
        XCTAssertTrue(report.contains("**expired** 2026-09-01"))
        XCTAssertTrue(report.contains("old@x.com in grants[0] isn't a user on the server"))
        XCTAssertTrue(report.contains("- old-pi: last seen"))
        XCTAssertTrue(report.contains("Not checked: load traffic"))
        XCTAssertTrue(report.contains("- OAuth client, scopes: policy_file"))
    }
}
