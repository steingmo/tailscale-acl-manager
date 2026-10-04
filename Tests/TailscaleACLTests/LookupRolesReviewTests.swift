import XCTest
@testable import TailscaleACL

final class IPLookupTests: XCTestCase {
    let m = model("""
    {"hosts": {"dc1": "10.114.32.11", "lan": "10.114.32.0/24"},
     "ipsets": {"ipset:mgmt": ["add 10.114.32.0/24", "remove 10.114.32.99"]},
     "grants": [
       // Admins reach the DC
       {"src": ["group:ops"], "dst": ["dc1"], "ip": ["88"]},
       {"src": ["group:ops"], "dst": ["ipset:mgmt"], "ip": ["*"]},
       {"src": ["*"], "dst": ["*"], "ip": ["443"]},
     ],
     "groups": {"group:ops": ["amy@x.com"]},
     "tests": [{"src": "amy@x.com", "accept": ["10.114.32.11:88"]}]}
    """)

    func testFindsEverythingCoveringTheAddress() {
        let node = HeadscaleNode(id: "7", name: "dc-1", ipAddresses: ["10.114.32.11"])
        let hits = ipLookup("10.114.32.11", m, nodes: [node])
        XCTAssertEqual(hits.map(\.path), ["hosts[dc1]", "hosts[lan]", "ipsets[ipset:mgmt]",
                                          "grants[0]", "grants[1]", "tests[0]", nil])
        XCTAssertEqual(hits.last?.deviceID, "7")
        XCTAssertTrue(hits[3].detail.contains("reaches it via dc1"))
        XCTAssertFalse(hits.contains { $0.path == "grants[2]" }, "matching only through * is noise")
        // Every path resolves to a line in the editor.
        let tree = try! HuJSONParser.parse(model_text)
        XCTAssertTrue(hits.compactMap(\.path).allSatisfy { tree.line(at: $0) != nil })
    }

    func testRemovedAddressIsNotInTheSet() {
        XCTAssertFalse(ipLookup("10.114.32.99", m).contains { $0.path == "ipsets[ipset:mgmt]" })
    }

    var model_text: String {
        """
        {"hosts": {"dc1": "10.114.32.11", "lan": "10.114.32.0/24"},
         "ipsets": {"ipset:mgmt": ["add 10.114.32.0/24", "remove 10.114.32.99"]},
         "grants": [{"src": ["group:ops"], "dst": ["dc1"], "ip": ["88"]}, {"src": ["group:ops"], "dst": ["ipset:mgmt"], "ip": ["*"]}],
         "tests": [{"src": "amy@x.com", "accept": ["10.114.32.11:88"]}]}
        """
    }
}

final class RoleTests: XCTestCase {
    func testRolesFromTheServerMatchRealUsers() {
        var m = model("""
        {"grants": [
          {"src": ["autogroup:admin"], "dst": ["tag:db"], "ip": ["5432"]},
          {"src": ["autogroup:member"], "dst": ["tag:web"], "ip": ["443"]},
          {"src": ["tag:ci"], "dst": ["autogroup:it-admin"], "ip": ["22"]},
        ], "tagOwners": {"tag:db": [], "tag:web": [], "tag:ci": []}}
        """)
        XCTAssertFalse(Evaluator(model: m).evaluate(sourceID: "amy@x.com", destID: "tag:db", port: 5432).allowed,
                       "without the user list, roles are unknown")
        m.userAutogroups = ["amy@x.com": ["autogroup:admin"], "guest@other.com": ["autogroup:shared"],
                            "it@x.com": ["autogroup:it-admin"]]
        let ev = Evaluator(model: m)
        XCTAssertTrue(ev.evaluate(sourceID: "Amy@x.com", destID: "tag:db", port: 5432).allowed, "case-insensitive")
        XCTAssertFalse(ev.evaluate(sourceID: "bob@x.com", destID: "tag:db", port: 5432).allowed)
        XCTAssertTrue(ev.evaluate(sourceID: "bob@x.com", destID: "tag:web", port: 443).allowed)
        XCTAssertFalse(ev.evaluate(sourceID: "guest@other.com", destID: "tag:web", port: 443).allowed,
                       "shared-in users aren't members")
        XCTAssertTrue(ev.evaluate(sourceID: "tag:ci", destID: "it@x.com", port: 22).allowed, "role as destination")
    }

    func testTailscaleUserListGivesRoles() async throws {
        StubProtocol.requests = []
        StubProtocol.handler = { _, _ in .init(body: Data("""
        {"users": [
          {"loginName": "Amy@x.com", "role": "admin", "type": "member"},
          {"loginName": "bob@x.com", "role": "member", "type": "member"},
          {"loginName": "guest@other.com", "role": "member", "type": "shared"}
        ]}
        """.utf8)) }
        let c = makeServer(kind: .tailscale, serverURL: "", tailnet: "-", credential: "tskey-api-x",
                           session: StubProtocol.session())!
        let users = try await c.serverUsers()
        XCTAssertEqual(users.logins, ["amy@x.com", "bob@x.com", "guest@other.com"])
        XCTAssertEqual(users.autogroups, ["amy@x.com": ["autogroup:admin"], "guest@other.com": ["autogroup:shared"]])
    }
}

@MainActor
final class RoleStoreTests: XCTestCase {
    var dir: URL!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        setenv("TAILSCALE_ACL_DATA_DIR", dir.path, 1)
        let ws = Workspace(name: "Home", serverURL: "", policy: """
        {"grants": [{"src": ["autogroup:admin"], "dst": ["tag:db"], "ip": ["5432"]}], "tagOwners": {"tag:db": []},
         "tests": [{"src": "amy@x.com", "accept": ["tag:db:5432"]}]}
        """)
        try WorkspaceStore.save([ws])
        UserDefaults.standard.set(ws.id.uuidString, forKey: "currentWorkspaceID")
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        unsetenv("TAILSCALE_ACL_DATA_DIR")
    }

    func testLoadingRolesReevaluatesTests() {
        let store = PolicyStore()
        XCTAssertEqual(store.testResults.map(\.passed), [false])
        store.serverUserAutogroups = ["amy@x.com": ["autogroup:admin"]]
        XCTAssertEqual(store.testResults.map(\.passed), [true])
        XCTAssertEqual(store.model.userAutogroups["amy@x.com"], ["autogroup:admin"])
    }
}

final class ReviewExportTests: XCTestCase {
    func testMarkdownHasSummaryChangesChecksAndDiff() {
        let m = model(#"{"tests": [{"src": "a@x.com", "accept": ["tag:x:22"]}]}"#)
        let md = pushReviewMarkdown(PushReview(
            workspace: "Office", host: "Tailscale (-)", serverText: "{\n  \"a\": 1\n}\n", candidate: "{\n  \"a\": 2\n}\n",
            changes: [AccessChange(src: "laptop", dst: "nas", gained: ["445"], lost: [], sshGained: ["root"])],
            deviceCount: 12, verdict: "", errors: [LintIssue(severity: .error, title: "Undefined group", detail: "group:x …")],
            tests: Evaluator(model: m).runTests(), conflict: true))
        XCTAssertTrue(md.hasPrefix("# Policy change review — Office"))
        XCTAssertTrue(md.contains("- 1 device pair of 12 devices change access."))
        XCTAssertTrue(md.contains("- ⚠️ The server's policy changed"))
        XCTAssertTrue(md.contains("- ✅ Tailscale's own check passed."))
        XCTAssertTrue(md.contains("- ❌ 1 of 1 policy tests fail."))
        XCTAssertTrue(md.contains("| laptop | nas | 445, SSH as root | — |"))
        XCTAssertTrue(md.contains("- tests[0] a@x.com should reach tag:x:22"))
        XCTAssertTrue(md.contains("- **Undefined group**"))
        XCTAssertTrue(md.contains("```diff\n {\n-  \"a\": 1\n+  \"a\": 2\n }\n```"), md)
    }
}
