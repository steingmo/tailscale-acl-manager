import XCTest
@testable import TailscaleACL

final class ExplainFailureTests: XCTestCase {
    let m = model(SamplePolicy.text)

    func testMissingAllowOnWrongPort() {
        let e = explainFailure(m, src: "alice@example.com", entry: "tag:db:5432", expectAllowed: true)
        XCTAssertTrue(e.summary.contains("but not on port 5432"), e.summary)
        XCTAssertEqual(e.rules.first?.kind, .grant)
    }

    func testUnexpectedAllowNamesTheRule() {
        let e = explainFailure(m, src: "alice@example.com", entry: "tag:server:22", expectAllowed: false)
        XCTAssertTrue(e.summary.hasPrefix("Allowed by Engineers reach"), e.summary)
    }

    func testNothingReaches() {
        // (The sample's "*:*" rule reaches everything, so use a policy without wildcards.)
        let narrow = model(#"{"grants": [{"src": ["group:a"], "dst": ["tag:x"], "ip": ["*"]}]}"#)
        let e = explainFailure(narrow, src: "alice@example.com", entry: "tag:nowhere:22", expectAllowed: true)
        XCTAssertEqual(e.summary, "No rule reaches tag:nowhere at all.")
    }
}

final class TemplateTests: XCTestCase {
    func apply(_ id: String, to text: String = "{}", _ values: [String: String] = [:]) -> PolicyModel {
        var tree = try! HuJSONParser.parse(text)
        let t = policyTemplates.first { $0.id == id }!
        var v = Dictionary(uniqueKeysWithValues: t.fields.map { ($0.key, $0.defaultValue) })
        v.merge(values) { $1 }
        t.apply(&tree, v)
        return model(HuJSONSerializer.serialize(tree)) // must serialize and reparse
    }

    func testEveryTemplateProducesErrorFreePolicy() {
        for t in policyTemplates {
            let errors = lintPolicy(apply(t.id)).filter { $0.severity == .error }
            XCTAssertTrue(errors.isEmpty, "\(t.id): \(errors.map(\.detail))")
        }
    }

    func testSubnetRouterTemplate() {
        let m = apply("subnet", ["route": "10.5.0.0/16"])
        XCTAssertEqual(m.tagOwners["tag:router"], [])
        XCTAssertEqual(m.routeApprovers.first?.route, "10.5.0.0/16")
        XCTAssertEqual(m.grants.first?.dst, ["10.5.0.0/16"])
        XCTAssertEqual(m.grants.first?.comments, ["Subnet router: 10.5.0.0/16"])
    }

    func testTemplatesKeepExistingDefinitions() {
        let m = apply("admins", to: #"{"groups": {"group:admins": ["boss@x"]}}"#, ["members": "other@x"])
        XCTAssertEqual(m.groups["group:admins"], ["boss@x"])
        let twice = apply("exit", to: HuJSONSerializer.serialize(try! HuJSONParser.parse(#"{"autoApprovers": {"exitNode": ["tag:exit"]}}"#)))
        XCTAssertEqual(twice.exitNodeApprovers, ["tag:exit"]) // no duplicate approver
    }

    func testSSHTemplateGivesNetworkAndSSHAccess() {
        let m = apply("ssh")
        let ev = Evaluator(model: m)
        XCTAssertTrue(ev.sshNetworkAllowed(sourceIDs: ["group:admins"], destIDs: ["tag:server"]))
        XCTAssertFalse(ev.evaluateSSH(sourceIDs: ["group:admins"], destIDs: ["tag:server"], login: "root").isEmpty)
    }
}

@MainActor
final class FixAndSnapshotStoreTests: XCTestCase {
    var dir: URL!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        setenv("TAILSCALE_ACL_DATA_DIR", dir.path, 1)
        try WorkspaceStore.save([Workspace(name: "T", serverURL: "", policy: "{\"groups\": {}}\n")])
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        unsetenv("TAILSCALE_ACL_DATA_DIR")
    }

    func testFixesClearTheirProblems() {
        let store = PolicyStore()
        store.loadPolicy("""
        {"groups": {"group:unused": ["a@x"]},
         "acls": [{"action": "accept", "src": ["group:ghost"], "dst": ["tag:noowner:22"]},
                  {"action": "accept", "src": ["group:ghost"], "dst": ["tag:noowner:22"]}]}
        """)
        func fix(_ title: String, _ label: String? = nil) {
            let issue = store.lintIssues.first { $0.title == title }!
            store.apply((label.flatMap { l in issue.fixes.first { $0.label == l } } ?? issue.fixes[0]).action)
        }
        fix("Tag without owner")
        XCTAssertNotNil(store.model.tagOwners["tag:noowner"])
        fix("Undefined group", "Define empty group")
        XCTAssertNotNil(store.model.groups["group:ghost"])
        fix("Shadowed rule")
        XCTAssertEqual(store.model.rules.count, 1)
        fix("Unused group")
        XCTAssertNil(store.model.groups["group:unused"])
        XCTAssertFalse(store.lintIssues.contains { $0.severity == .error }, "\(store.lintIssues.map(\.title))")
    }

    func testSnapshotsOnOpenAndReplace() {
        let store = PolicyStore()
        let id = store.currentWorkspaceID
        XCTAssertEqual(SnapshotStore.load(id).first?.reason, "opened")
        store.loadPolicy("{\"groups\": {\"group:a\": []}}\n", reason: "pulled")
        let reasons = SnapshotStore.load(id).map(\.reason)
        XCTAssertEqual(reasons.first, "pulled")
        XCTAssertEqual(SnapshotStore.load(id).first?.text, store.text)
        store.snapshot(reason: "manual") // unchanged text → skipped
        XCTAssertEqual(SnapshotStore.load(id).count, reasons.count)
        for i in 0..<120 { SnapshotStore.record(id, text: "\(i)", reason: "x") }
        XCTAssertEqual(SnapshotStore.load(id).count, 100)
    }

    func testMapImageRendersAndReportLinksIt() {
        let store = PolicyStore()
        store.loadPolicy(SamplePolicy.text)
        let png = renderPNG(AccessMapScreen(focus: .group, "group:eng").environmentObject(store))
        XCTAssertGreaterThan(png?.count ?? 0, 10_000)
        let report = policyReport(workspace: "T", model: store.model, nodes: [], problems: [],
                                  mapImages: [("group:eng", "T images/group-eng.png")])
        XCTAssertTrue(report.contains("![group:eng](<T images/group-eng.png>)"))
    }
}
