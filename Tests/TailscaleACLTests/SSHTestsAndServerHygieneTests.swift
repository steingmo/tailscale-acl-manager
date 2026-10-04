import XCTest
@testable import TailscaleACL

final class SSHTestsTests: XCTestCase {
    let policy = """
    {
      "groups": {"group:ops": ["amy@x.com"], "group:dev": ["bob@x.com"]},
      "tagOwners": {"tag:server": []},
      "ssh": [
        {"action": "accept", "src": ["group:ops"], "dst": ["tag:server"], "users": ["root", "ubuntu"]},
        {"action": "check", "src": ["group:dev"], "dst": ["tag:server"], "users": ["ubuntu"]},
        {"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["autogroup:nonroot"]},
      ],
      "sshTests": [
        {"src": "amy@x.com", "dst": ["tag:server"], "accept": ["root", "ubuntu"]},
        {"src": "bob@x.com", "dst": ["tag:server"], "check": ["ubuntu"], "deny": ["root"]},
        {"src": "bob@x.com", "dst": ["tag:server"], "accept": ["ubuntu"]},
      ],
    }
    """

    func testRunsAcceptCheckDeny() {
        let m = model(policy)
        XCTAssertEqual(m.sshTests.count, 3)
        let results = Evaluator(model: m).runSSHTests()
        XCTAssertEqual(results.map(\.passed), [true, true, false])
        let failing = results[2].assertions[0]
        XCTAssertEqual(failing.expected, .accept)
        XCTAssertEqual(failing.actual, .check)
        XCTAssertEqual(Evaluator(model: m).sshOutcome(src: "bob@x.com", dst: "bob@x.com", login: "bob"), .accept, "own devices")
    }

    func testGenerationPinsTodaysSSHAccess() throws {
        var m = model(policy)
        let generated = generateSSHTests(m, sources: ["amy@x.com", "bob@x.com", "eve@x.com"])
        let amy = generated.first { $0.src == "amy@x.com" && $0.dst == ["tag:server"] }
        XCTAssertEqual(amy?.accept, ["root", "ubuntu"])
        let bob = generated.first { $0.src == "bob@x.com" && $0.dst == ["tag:server"] }
        XCTAssertEqual(bob?.check, ["ubuntu"])
        XCTAssertEqual(bob?.deny, ["root"])
        XCTAssertFalse(generated.contains { $0.src == "eve@x.com" && $0.dst == ["tag:server"] }, "no access, no test")

        // Written back and read again, they all pass.
        var tree = try HuJSONParser.parse(policy)
        tree["sshTests"] = .array(sshTestElements(generated))
        m = PolicyModel(tree: try HuJSONParser.parse(HuJSONSerializer.serialize(tree)))
        XCTAssertEqual(m.sshTests.count, generated.count)
        XCTAssertTrue(Evaluator(model: m).runSSHTests().allSatisfy(\.passed))
    }

    func testCommandLineAndLint() throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("\(UUID().uuidString).hujson")
        defer { try? FileManager.default.removeItem(at: file) }
        try policy.write(to: file, atomically: true, encoding: .utf8)
        var out: [String] = []
        XCTAssertEqual(runCommandLine(["test", file.path]) { out.append($0) }, 1)
        XCTAssertTrue(out.contains { $0.contains("FAIL sshTests[2] bob@x.com → tag:server as ubuntu: expected accept, got check") },
                      out.joined(separator: "\n"))
        XCTAssertTrue(out.last?.hasPrefix("3 tests, 1 failed") == true, out.last ?? "")

        let bad = model(#"{"sshTests": [{"src": "group:nope", "dst": ["tag:nope"], "accept": ["root"]}]}"#)
        let titles = lintPolicy(bad).map(\.title)
        XCTAssertTrue(titles.contains("Undefined group"))
        XCTAssertTrue(titles.contains("Tag without owner"))
    }
}

final class ViaRouteTests: XCTestCase {
    let m = model("""
    {"tagOwners": {"tag:router": [], "tag:exit": []},
     "ipsets": {"ipset:office": ["add 10.114.32.0/24", "add 10.20.0.0/16"]},
     "grants": [
       {"src": ["*"], "dst": ["ipset:office"], "ip": ["*"], "via": ["tag:router"]},
       {"src": ["*"], "dst": ["autogroup:internet"], "ip": ["*"], "via": ["tag:exit"]},
     ]}
    """)

    func titles(_ nodes: [HeadscaleNode]) -> [String] { lintNodes(m, nodes: nodes).map(\.title) }

    func testCoveredByApprovedRoutes() {
        let router = HeadscaleNode(id: "1", availableRoutes: ["10.114.0.0/16", "10.20.0.0/16"],
                                   approvedRoutes: ["10.114.0.0/16", "10.20.0.0/16"], tags: ["tag:router"])
        let exit = HeadscaleNode(id: "2", availableRoutes: ["0.0.0.0/0", "::/0"],
                                 approvedRoutes: ["0.0.0.0/0", "::/0"], tags: ["tag:exit"])
        XCTAssertFalse(titles([router, exit]).contains("Route not served via"))
        XCTAssertFalse(titles([router, exit]).contains("No router for via"))
    }

    func testMissingAndUnapprovedRoutes() {
        let router = HeadscaleNode(id: "1", name: "r1", availableRoutes: ["10.114.32.0/24", "10.20.0.0/16"],
                                   approvedRoutes: ["10.114.32.0/24"], tags: ["tag:router"])
        let issues = lintNodes(m, nodes: [router])
        let notServed = issues.first { $0.title == "Route not served via" }
        XCTAssertNotNil(notServed)
        XCTAssertTrue(notServed!.detail.contains("10.20.0.0/16"))
        XCTAssertFalse(notServed!.detail.contains("10.114.32.0/24"))
        XCTAssertTrue(notServed!.detail.contains("advertised but not yet approved"))
        XCTAssertEqual(notServed!.path, "grants[0].via")
        XCTAssertTrue(issues.contains { $0.title == "No router for via" && $0.detail.contains("tag:exit") })
    }

    func testPrefixHelpers() {
        XCTAssertTrue(prefixContains("10.114.0.0/16", "10.114.32.0/24"))
        XCTAssertFalse(prefixContains("10.114.32.0/24", "10.114.0.0/16"))
        XCTAssertEqual(addressPrefixes("ipset:office", m), ["10.114.32.0/24", "10.20.0.0/16"])
        XCTAssertEqual(addressPrefixes("tag:router", m), [])
    }
}

final class StaleUserTests: XCTestCase {
    override func setUp() {
        StubProtocol.requests = []
    }

    func testFlagsMembersWhoAreNotUsers() {
        let m = model("""
        {"groups": {"group:eng": ["amy@x.com", "Gone@x.com", "carl@"]},
         "grants": [{"src": ["old@x.com", "group:eng"], "dst": ["*"], "ip": ["22"]}]}
        """)
        let issues = lintUsers(m, logins: ["amy@x.com", "carl@"])
        XCTAssertEqual(issues.map(\.detail).filter { $0.contains("Gone@x.com") }.count, 1, "case-insensitive, flagged once")
        XCTAssertTrue(issues.contains { $0.detail.contains("old@x.com") && $0.path == "grants[0]" })
        if case .removeGroupMember(let g, let u)? = issues.first?.fixes.first?.action {
            XCTAssertEqual(g, "group:eng")
            XCTAssertEqual(u, "Gone@x.com")
        } else { XCTFail("expected a remove fix") }
        XCTAssertTrue(lintUsers(m, logins: nil).isEmpty, "unknown user list: no warnings")
    }

    func testServerUserLogins() async throws {
        StubProtocol.handler = { _, _ in .init(body: Data("""
        {"users": [{"id": "1", "name": "carl", "email": ""}, {"id": "2", "name": "amy", "email": "Amy@X.com"}]}
        """.utf8)) }
        let hs = makeServer(kind: .headscale, serverURL: "https://hs.example", tailnet: "", credential: "k",
                            session: StubProtocol.session())!
        let headscaleLogins = try await hs.serverUsers().logins
        XCTAssertEqual(headscaleLogins, ["carl", "carl@", "amy", "amy@", "amy@x.com"])

        StubProtocol.handler = { _, _ in .init(body: Data(#"{"users": [{"loginName": "Amy@x.com"}, {"loginName": "bob@x.com"}]}"#.utf8)) }
        let ts = makeServer(kind: .tailscale, serverURL: "", tailnet: "-", credential: "tskey-api-x",
                            session: StubProtocol.session())!
        let tailscaleLogins = try await ts.serverUsers().logins
        XCTAssertEqual(tailscaleLogins, ["amy@x.com", "bob@x.com"])
        XCTAssertEqual(StubProtocol.requests.last?.request.url?.path, "/api/v2/tailnet/-/users")
    }
}

@MainActor
final class RemoveMemberFixTests: XCTestCase {
    var dir: URL!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        setenv("TAILSCALE_ACL_DATA_DIR", dir.path, 1)
        let ws = Workspace(name: "Home", serverURL: "", policy: #"{"groups": {"group:eng": ["amy@x.com", "gone@x.com"]}}"#)
        try WorkspaceStore.save([ws])
        UserDefaults.standard.set(ws.id.uuidString, forKey: "currentWorkspaceID")
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        unsetenv("TAILSCALE_ACL_DATA_DIR")
    }

    func testFixRemovesTheMemberAndTheWarning() {
        let store = PolicyStore()
        store.serverLogins = ["amy@x.com"]
        let issue = store.lintIssues.first { $0.title == "Not a user on the server" }
        XCTAssertNotNil(issue)
        store.apply(issue!.fixes[0].action)
        XCTAssertEqual(store.model.groups["group:eng"], ["amy@x.com"])
        XCTAssertFalse(store.lintIssues.contains { $0.title == "Not a user on the server" })
    }
}
