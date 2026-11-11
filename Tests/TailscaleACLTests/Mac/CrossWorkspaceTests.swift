import XCTest
@testable import TailscaleACL

final class CrossCheckTests: XCTestCase {
    func testPolicyWithTestsReplacesOnlyTests() throws {
        let text = try policyWithTests(SamplePolicy.text, [ACLTest(index: 0, src: "alice@example.com",
                                                                   accept: ["tag:server:22"], deny: [])])
        let m = model(text)
        XCTAssertEqual(m.tests.count, 1)
        XCTAssertEqual(m.tests[0].accept, ["tag:server:22"])
        XCTAssertEqual(m.rules.count, model(SamplePolicy.text).rules.count)
        XCTAssertTrue(text.contains("// Engineers reach app"), "comments kept")
    }

    func testDisagreementsAreFoundPerSource() {
        let local = [
            TestResult(testIndex: 0, src: "alice@x", assertions: [.init(kind: .accept, dst: "tag:a:22", passed: true)]),
            TestResult(testIndex: 1, src: "bob@x", assertions: [.init(kind: .deny, dst: "tag:a:22", passed: false)]),
            TestResult(testIndex: 2, src: "carol@x", assertions: [.init(kind: .accept, dst: "tag:a:22", passed: true)]),
        ]
        let report = ValidationReport(message: "test(s) failed", failures: [
            ("alice@x", ["address \"tag:a:22\": want: Accept, got: Drop"]),
            ("bob@x", ["address \"tag:a:22\": want: Drop, got: Accept"]),
        ])
        let d = compareWithServer(local: local, report: report)!
        XCTAssertEqual(d.map(\.src), ["alice@x"]) // bob fails on both sides; carol passes on both
        XCTAssertTrue(d[0].appPasses)
        XCTAssertTrue(compareWithServer(local: local, report: ValidationReport())!.map(\.src) == ["bob@x"])
        XCTAssertNil(compareWithServer(local: local, report: ValidationReport(message: "parse error")))
    }
}

final class CopyBetweenWorkspacesTests: XCTestCase {
    let source = try! HuJSONParser.parse("""
    {"groups": {"group:admins": ["boss@x"], "group:netops": ["n@x"]},
     "tagOwners": {"tag:server": ["group:netops"]},
     "hosts": {"nas": "10.0.0.5"},
     "grants": [
       // Admins reach servers
       {"src": ["group:admins"], "dst": ["tag:server", "host:nas"], "ip": ["tcp:22"]},
     ]}
    """)

    func testRuleCopiesWithItsDefinitions() {
        let (text, outcome) = copyRule(section: "grants", index: 0, from: source,
                                       into: #"{"groups": {"group:admins": ["someone-else@y"]}}"#)
        XCTAssertEqual(outcome, .copied)
        let m = model(text!)
        XCTAssertEqual(m.grants.first?.comments, ["Admins reach servers"])
        XCTAssertEqual(m.groups["group:admins"], ["someone-else@y"], "existing definitions are never overwritten")
        XCTAssertEqual(m.tagOwners["tag:server"], ["group:netops"])
        XCTAssertEqual(m.groups["group:netops"], ["n@x"], "groups owning a copied tag come along")
        XCTAssertEqual(m.hosts["nas"], "10.0.0.5", "host: references resolve")
        XCTAssertTrue(lintPolicy(m).filter { $0.severity == .error }.isEmpty)

        let again = copyRule(section: "grants", index: 0, from: source, into: text!)
        XCTAssertEqual(again.outcome, .alreadyThere)
        XCTAssertNil(again.text)
    }

    func testEntitiesTemplatesAndBrokenTargets() {
        XCTAssertEqual(copyEntities(["tag:server"], from: source, into: "{}").outcome, .copied)
        XCTAssertEqual(copyEntities(["group:admins"], from: source, into: #"{"groups": {"group:admins": []}}"#).outcome,
                       .alreadyThere)
        XCTAssertEqual(copyRule(section: "grants", index: 0, from: source, into: "{ broken").outcome,
                       .failed("its policy doesn't parse"))
        let t = policyTemplates.first { $0.id == "self" }!
        let applied = applyTemplate(t, values: [:], to: "{}")
        XCTAssertEqual(model(applied.text!).grants.first?.dst, ["autogroup:self"])
    }
}

@MainActor
final class WorkspaceCopyStoreTests: XCTestCase {
    var dir: URL!
    let other = Workspace(name: "Customer B", serverURL: "", policy: "{}\n")

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        setenv("TAILSCALE_ACL_DATA_DIR", dir.path, 1)
        let home = Workspace(name: "Home", serverURL: "", policy: SamplePolicy.text)
        try WorkspaceStore.save([home, other])
        UserDefaults.standard.set(home.id.uuidString, forKey: "currentWorkspaceID")
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        unsetenv("TAILSCALE_ACL_DATA_DIR")
    }

    func testCopyIntoAnotherWorkspaceIsSavedAndSnapshotted() {
        let store = PolicyStore()
        let tree = store.tree!
        let results = store.modifyWorkspaces([other.id, store.currentWorkspaceID], reason: "copied from Home") {
            copyRule(section: "grants", index: 0, from: tree, into: $0)
        }
        XCTAssertEqual(results.map(\.name), ["Customer B"], "the open workspace is never a target")
        XCTAssertEqual(results.first?.outcome, .copied)
        let saved = WorkspaceStore.load().first { $0.id == other.id }!
        XCTAssertEqual(model(saved.policy).grants.count, 1)
        XCTAssertEqual(SnapshotStore.load(other.id).map(\.reason), ["copied from Home", "before copied from Home"])
    }
}

final class AuthKeyClientTests: XCTestCase {
    override func setUp() { StubProtocol.requests = [] }

    func testTailscaleAuthKey() async throws {
        StubProtocol.handler = { _, _ in .init(body: Data(#"{"key": "tskey-auth-xyz", "id": "k1"}"#.utf8)) }
        let c = makeServer(kind: .tailscale, serverURL: "", tailnet: "-", credential: "tskey-api-abc",
                           session: StubProtocol.session())!
        let key = try await c.createAuthKey(AuthKeyRequest(tags: ["tag:server"], reusable: true, expiry: 3600))
        XCTAssertEqual(key, "tskey-auth-xyz")
        let req = StubProtocol.requests[0]
        XCTAssertEqual(req.request.url?.path, "/api/v2/tailnet/-/keys")
        let body = try JSONSerialization.jsonObject(with: req.body) as! [String: Any]
        XCTAssertEqual(body["expirySeconds"] as? Int, 3600)
        let create = ((body["capabilities"] as! [String: Any])["devices"] as! [String: Any])["create"] as! [String: Any]
        XCTAssertEqual(create["tags"] as? [String], ["tag:server"])
        XCTAssertEqual(create["reusable"] as? Bool, true)
        let users = try await c.listUsers()
        XCTAssertTrue(users.isEmpty)
    }

    func testHeadscaleAuthKeyAndUsers() async throws {
        let c = makeServer(kind: .headscale, serverURL: "https://hs.example.com", tailnet: "", credential: "k",
                           session: StubProtocol.session())!
        StubProtocol.handler = { _, _ in .init(body: Data(#"{"users": [{"id": "1", "name": "sos"}, {"id": 2, "email": "b@x"}]}"#.utf8)) }
        let users = try await c.listUsers()
        XCTAssertEqual(users, [ServerUser(id: "1", name: "sos"), ServerUser(id: "2", name: "b@x")])

        StubProtocol.handler = { _, _ in .init(body: Data(#"{"preAuthKey": {"key": "hskey123", "id": "5"}}"#.utf8)) }
        let key = try await c.createAuthKey(AuthKeyRequest(tags: [], ephemeral: true, user: "1"))
        XCTAssertEqual(key, "hskey123")
        let body = try JSONSerialization.jsonObject(with: StubProtocol.requests.last!.body) as! [String: Any]
        XCTAssertEqual(body["user"] as? String, "1")
        XCTAssertEqual(body["ephemeral"] as? Bool, true)
        XCTAssertNotNil(body["expiration"] as? String)
        XCTAssertEqual(StubProtocol.requests.last!.request.url?.path, "/api/v1/preauthkey")
    }
}
