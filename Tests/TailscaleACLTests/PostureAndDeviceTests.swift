import XCTest
@testable import TailscaleACL

final class PostureTests: XCTestCase {
    let policy = """
    {
      "postures": {
        "posture:mac": ["node:os == 'macos'", "node:tsVersion >= '1.60'"],
        "posture:mobile": ["node:os IN ['ios', 'android']"],
      },
      "grants": [
        {"src": ["group:eng"], "dst": ["tag:db"], "ip": ["5432"], "srcPosture": ["posture:mac", "posture:mobile"]},
        {"src": ["group:eng"], "dst": ["tag:web"], "ip": ["443"]},
        {"src": ["group:eng"], "dst": ["10.1.0.0/16"], "ip": ["*"], "via": ["tag:router"]},
      ],
      "groups": {"group:eng": ["amy@x.com"]},
      "tagOwners": {"tag:db": [], "tag:web": [], "tag:router": []},
    }
    """

    func testConditionGrammar() {
        let c = PostureCondition("node:os IN ['macos', \"ios\"]")
        XCTAssertEqual(c?.op, "IN")
        XCTAssertEqual(c?.values, ["macos", "ios"])
        XCTAssertEqual(PostureCondition("node:tsVersion >= '1.60'")?.op, ">=")
        XCTAssertEqual(PostureCondition("custom:x NOT SET")?.op, "NOT SET")
        XCTAssertNil(PostureCondition("node:os"))
        XCTAssertNil(PostureCondition("node:os IN 'macos'"))

        let mac = ["node:os": "macos", "node:tsVersion": "1.62.1"]
        XCTAssertEqual(PostureCondition("node:tsVersion >= '1.60'")?.evaluate(mac, complete: true), true)
        XCTAssertEqual(PostureCondition("node:tsVersion < '1.9'")?.evaluate(mac, complete: true), false, "numeric, not string, order")
        XCTAssertEqual(PostureCondition("node:os NOT IN ['windows']")?.evaluate(mac, complete: true), true)
        XCTAssertEqual(PostureCondition("custom:x IS SET")?.evaluate(mac, complete: true), false)
        XCTAssertNil(PostureCondition("custom:x == 'y'")?.evaluate(mac, complete: false), "unknown attribute")
    }

    func testPostureGatedAccess() {
        let m = model(policy)
        // Unknown device: allowed, but only conditionally.
        let unknown = Evaluator(model: m).evaluate(sourceID: "amy@x.com", destID: "tag:db", port: 5432)
        XCTAssertTrue(unknown.allowed)
        XCTAssertTrue(unknown.conditional)
        XCTAssertEqual(unknown.postures, ["posture:mac", "posture:mobile"])
        // Meets one of the postures (OR): unconditional.
        let ios = Evaluator(model: m, sourceAttributes: ["node:os": "ios"])
            .evaluate(sourceID: "amy@x.com", destID: "tag:db", port: 5432)
        XCTAssertTrue(ios.allowed)
        XCTAssertFalse(ios.conditional)
        // Fails all of them: denied.
        let old = Evaluator(model: m, sourceAttributes: ["node:os": "macos", "node:tsVersion": "1.50"])
            .evaluate(sourceID: "amy@x.com", destID: "tag:db", port: 5432)
        XCTAssertFalse(old.allowed)
        // A Windows device fails both even though tsVersion is unknown.
        XCTAssertFalse(Evaluator(model: m, sourceAttributes: ["node:os": "windows"])
            .evaluate(sourceID: "amy@x.com", destID: "tag:db", port: 5432).allowed)
        // A mac with unknown version can't be decided.
        XCTAssertTrue(Evaluator(model: m, sourceAttributes: ["node:os": "macos"])
            .evaluate(sourceID: "amy@x.com", destID: "tag:db", port: 5432).conditional)
        // Rules without srcPosture are unaffected.
        XCTAssertFalse(Evaluator(model: m).evaluate(sourceID: "amy@x.com", destID: "tag:web", port: 443).conditional)
    }

    func testDefaultSrcPostureAppliesToRulesWithoutTheirOwn() {
        let m = model("""
        {"postures": {"posture:mac": ["node:os == 'macos'"]}, "defaultSrcPosture": ["posture:mac"],
         "acls": [{"action": "accept", "src": ["*"], "dst": ["*:22"]}]}
        """)
        XCTAssertTrue(Evaluator(model: m).evaluate(sourceID: "a@x.com", destID: "1.2.3.4", port: 22).conditional)
        XCTAssertFalse(Evaluator(model: m, sourceAttributes: ["node:os": "linux"])
            .evaluate(sourceID: "a@x.com", destID: "1.2.3.4", port: 22).allowed)
    }

    func testTestsUseSrcPostureAttrs() {
        let m = model(policy.replacingOccurrences(of: "\"groups\":", with: """
        "tests": [
          {"src": "amy@x.com", "srcPostureAttrs": {"node:os": "macos", "node:tsVersion": "1.70.0"}, "accept": ["tag:db:5432"]},
          {"src": "amy@x.com", "accept": ["tag:db:5432"]},
        ],
        "groups":
        """))
        XCTAssertEqual(m.tests.first?.srcPostureAttrs, ["node:os": "macos", "node:tsVersion": "1.70.0"])
        let results = Evaluator(model: m).runTests()
        XCTAssertEqual(results.map(\.passed), [true, false], "without attributes a test device meets no posture, as on Tailscale")
        XCTAssertTrue(explainFailure(m, src: "amy@x.com", entry: "tag:db:5432", expectAllowed: true).summary
            .contains("posture:mac"))
        // Serialized for Tailscale's check, attributes included.
        let text = HuJSONSerializer.serialize(.array(testElements(m.tests)))
        XCTAssertTrue(text.contains("\"srcPostureAttrs\""))
    }

    func testViaIsCarriedAndLinted() {
        let m = model(policy)
        let r = Evaluator(model: m).evaluate(sourceID: "amy@x.com", destID: "10.1.2.3", port: 80)
        XCTAssertEqual(r.matches.first?.via, ["tag:router"])
        XCTAssertEqual(ruleSummaries(m, sourceIDs: nil).first { $0.index == 2 }?.notes, ["via tag:router"])
        let bad = model(#"{"grants": [{"src": ["*"], "dst": ["10.0.0.0/8"], "ip": ["*"], "via": ["router1"]}]}"#)
        XCTAssertTrue(lintPolicy(bad).contains { $0.title == "Invalid via" })
    }

    func testPostureLint() {
        let m = model("""
        {"postures": {"posture:ok": ["node:os == 'macos'"], "posture:bad": ["node:os maybe 'x'"], "posture:unused": ["node:os IS SET"]},
         "grants": [{"src": ["*"], "dst": ["tag:a"], "ip": ["*"], "srcPosture": ["posture:ok", "posture:bad", "posture:missing"]}],
         "tagOwners": {"tag:a": []}}
        """)
        let titles = lintPolicy(m).map(\.title)
        XCTAssertTrue(titles.contains("Undefined posture"))
        XCTAssertTrue(titles.contains("Invalid posture condition"))
        XCTAssertEqual(titles.filter { $0 == "Unused posture" }.count, 1)
    }

    func testPostureGatedRuleDoesNotShadow() {
        let m = model("""
        {"postures": {"posture:mac": ["node:os == 'macos'"]},
         "grants": [{"src": ["*"], "dst": ["tag:a"], "ip": ["*"], "srcPosture": ["posture:mac"]},
                    {"src": ["*"], "dst": ["tag:a"], "ip": ["22"]}],
         "tagOwners": {"tag:a": []}}
        """)
        XCTAssertFalse(lintPolicy(m).contains { $0.title == "Shadowed grant" })
    }
}

final class ExpiryAndBroadRuleTests: XCTestCase {
    let now = RuleExpiry.formatter.date(from: "2026-10-03")!

    func testExpiryCommentsAreParsedOutOfNames() {
        let m = model("""
        {"grants": [
          // Contractor access
          // expires: 2026-10-01
          {"src": ["a@x.com"], "dst": ["tag:a"], "ip": ["22"]},
          // Expires 2026-10-06
          {"src": ["b@x.com"], "dst": ["tag:a"], "ip": ["22"]},
        ], "tagOwners": {"tag:a": []}}
        """)
        XCTAssertEqual(m.grants[0].comments, ["Contractor access"])
        XCTAssertEqual(m.grants[0].expires, "2026-10-01")
        XCTAssertEqual(m.grants[1].expires, "2026-10-06")
        let issues = lintPolicy(m, now: now)
        let expired = issues.first { $0.title == "Expired rule" }
        XCTAssertEqual(expired?.fixes.count, 1)
        if case .deleteRule(let section, let index)? = expired?.fixes.first?.action {
            XCTAssertEqual(section, "grants")
            XCTAssertEqual(index, 0)
        } else { XCTFail("expected a delete fix") }
        XCTAssertTrue(issues.contains { $0.title == "Rule expires soon" && $0.detail.contains("in 3 days") })
    }

    func testWideOpenRules() {
        let titles = lintPolicy(model("""
        {"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
         "grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}
        """)).map(\.title)
        XCTAssertEqual(titles.filter { $0 == "Allows everything" }.count, 2)
    }
}

@MainActor
final class ExpiryAndFileLinkStoreTests: XCTestCase {
    var dir: URL!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        setenv("TAILSCALE_ACL_DATA_DIR", dir.path, 1)
        let ws = Workspace(name: "Home", serverURL: "", policy: "{\"grants\": []}\n")
        try WorkspaceStore.save([ws])
        UserDefaults.standard.set(ws.id.uuidString, forKey: "currentWorkspaceID")
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        unsetenv("TAILSCALE_ACL_DATA_DIR")
    }

    func testSaveRuleSetsKeepsAndRemovesExpiry() {
        let store = PolicyStore()
        let fields: [(key: String, value: JSON?)] = [("src", stringArrayJSON(["a@x.com"])),
                                                      ("dst", stringArrayJSON(["tag:a"])), ("ip", stringArrayJSON(["22"]))]
        store.saveRule(section: "grants", index: nil, name: "Contractor", expires: .some("2026-11-01"), fields: fields)
        XCTAssertEqual(store.model.grants[0].expires, "2026-11-01")
        XCTAssertEqual(store.model.grants[0].comments, ["Contractor"])
        store.saveRule(section: "grants", index: 0, name: "Renamed", fields: fields)
        XCTAssertEqual(store.model.grants[0].expires, "2026-11-01", "nil leaves the expiry alone")
        XCTAssertEqual(store.model.grants[0].comments, ["Renamed"])
        store.saveRule(section: "grants", index: 0, name: "Renamed", expires: .some(nil), fields: fields)
        XCTAssertNil(store.model.grants[0].expires)
    }

    func testLinkedFileSyncsBothWays() async throws {
        let file = dir.appendingPathComponent("policy.hujson")
        try "{\n  // from git\n  \"groups\": {\"group:a\": []},\n}\n".write(to: file, atomically: true, encoding: .utf8)
        let store = PolicyStore()
        store.setLinkedFile(file.path)
        XCTAssertTrue(store.text.contains("from git"), "the file replaces the editor")
        XCTAssertEqual(store.model.groupOrder, ["group:a"])

        store.addEntity(kind: .group, name: "group:b", address: "")
        let written = try String(contentsOf: file, encoding: .utf8)
        XCTAssertTrue(written.contains("group:b"), "valid edits are written back")
        XCTAssertTrue(written.contains("from git"))

        store.text = "{ broken"
        try await Task.sleep(nanoseconds: 400_000_000)  // typing debounce
        XCTAssertFalse(store.isValid)
        XCTAssertEqual(try String(contentsOf: file, encoding: .utf8), written, "invalid text is not written")

        // Reopening the workspace re-reads the file rather than overwriting it.
        try "{\"groups\": {\"group:c\": []}}\n".write(to: file, atomically: true, encoding: .utf8)
        let reopened = PolicyStore()
        XCTAssertEqual(reopened.model.groupOrder, ["group:c"])
        store.setLinkedFile(nil)
        reopened.setLinkedFile(nil)
    }
}

final class CommandLineTests: XCTestCase {
    func run(_ args: [String]) -> (code: Int32?, out: String) {
        var lines: [String] = []
        let code = runCommandLine(args) { lines.append($0) }
        return (code, lines.joined(separator: "\n"))
    }

    func testStartsAppForOtherArguments() {
        XCTAssertNil(run([]).code)
        XCTAssertNil(run(["-NSDocumentRevisionsDebugMode", "YES"]).code)
    }

    func testLintAndTest() throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("\(UUID().uuidString).hujson")
        defer { try? FileManager.default.removeItem(at: file) }
        try """
        {"grants": [{"src": ["group:eng"], "dst": ["tag:db"], "ip": ["5432"]}],
         "groups": {"group:eng": ["amy@x.com"]}, "tagOwners": {"tag:db": []},
         "tests": [{"src": "amy@x.com", "accept": ["tag:db:5432"], "deny": ["tag:db:22"]}]}
        """.write(to: file, atomically: true, encoding: .utf8)
        XCTAssertEqual(run(["lint", file.path]).code, 0)
        let ok = run(["test", file.path])
        XCTAssertEqual(ok.code, 0)
        XCTAssertTrue(ok.out.contains("1 test, 0 failed"))

        try #"{"tests": [{"src": "amy@x.com", "accept": ["tag:db:5432"]}]}"#.write(to: file, atomically: true, encoding: .utf8)
        let failing = run(["test", file.path])
        XCTAssertEqual(failing.code, 1)
        XCTAssertTrue(failing.out.contains("FAIL tests[0] amy@x.com should reach tag:db:5432"))

        try "{ nope".write(to: file, atomically: true, encoding: .utf8)
        XCTAssertEqual(run(["lint", file.path]).code, 1)
        XCTAssertEqual(run(["lint", "/no/such/file"]).code, 2)
        XCTAssertEqual(run(["lint"]).code, 2)
        XCTAssertEqual(run(["help"]).code, 0)
    }
}

final class DeviceMaintenanceTests: XCTestCase {
    override func setUp() {
        StubProtocol.requests = []
        StubProtocol.handler = { _, _ in .init(body: Data("{}".utf8)) }
    }

    func testHeadscaleEndpoints() async throws {
        let c = makeServer(kind: .headscale, serverURL: "https://hs.example", tailnet: "", credential: "k",
                           session: StubProtocol.session())!
        try await c.expireNode(nodeID: "7")
        try await c.renameNode(nodeID: "7", name: "nas-2")
        try await c.deleteNode(nodeID: "7")
        XCTAssertEqual(StubProtocol.requests.map { "\($0.request.httpMethod!) \($0.request.url!.path)" }, [
            "POST /api/v1/node/7/expire", "POST /api/v1/node/7/rename/nas-2", "DELETE /api/v1/node/7",
        ])
    }

    func testTailscaleEndpointsAndDeviceFields() async throws {
        let c = makeServer(kind: .tailscale, serverURL: "", tailnet: "-", credential: "tskey-api-x",
                           session: StubProtocol.session())!
        try await c.expireNode(nodeID: "n1")
        try await c.renameNode(nodeID: "n1", name: "nas")
        try await c.deleteNode(nodeID: "n1")
        XCTAssertEqual(StubProtocol.requests.map { "\($0.request.httpMethod!) \($0.request.url!.path)" }, [
            "POST /api/v2/device/n1/expire", "POST /api/v2/device/n1/name", "DELETE /api/v2/device/n1",
        ])
        XCTAssertEqual(try JSONSerialization.jsonObject(with: StubProtocol.requests[1].body) as? [String: String], ["name": "nas"])

        StubProtocol.handler = { _, _ in .init(body: Data("""
        {"devices": [
          {"id": "1", "nodeId": "n1", "os": "macOS", "clientVersion": "v1.76.1-t1234abcd",
           "expires": "2026-10-05T00:00:00Z", "keyExpiryDisabled": false},
          {"id": "2", "nodeId": "n2", "expires": "2026-10-05T00:00:00Z", "keyExpiryDisabled": true}
        ]}
        """.utf8)) }
        let nodes = try await c.listNodes()
        XCTAssertEqual(nodes[0].postureAttributes, ["node:os": "macos", "node:tsVersion": "1.76.1"])
        let now = ISO8601DateFormatter().date(from: "2026-10-03T00:00:00Z")!
        XCTAssertEqual(nodes[0].keyDaysLeft(now: now), 2)
        XCTAssertNil(nodes[1].keyDaysLeft(now: now), "expiry disabled")
    }

    func testStaleness() {
        let now = ISO8601DateFormatter().date(from: "2026-10-03T00:00:00Z")!
        var n = HeadscaleNode(id: "1", lastSeen: "2026-08-01T10:00:00.123456789Z")
        XCTAssertTrue(n.isStale(now: now))
        n.online = true
        XCTAssertFalse(n.isStale(now: now))
        XCTAssertNil(HeadscaleNode(id: "2", expiry: "0001-01-01T00:00:00Z").expiryDate, "zero time means never")
    }
}
