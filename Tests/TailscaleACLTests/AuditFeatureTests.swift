import XCTest
@testable import TailscaleACL

final class PortIntervalTests: XCTestCase {
    let devices = nodes("""
    {"nodes": [
      {"id": "1", "givenName": "laptop", "user": {"name": "sos"}},
      {"id": "2", "givenName": "server", "user": {"name": "sos"}, "tags": ["tag:server"]}
    ]}
    """)

    func change(_ oldIP: String, _ newIP: String) -> AccessChange? {
        func policy(_ ip: String) -> PolicyModel {
            model(#"{"groups": {"group:a": ["sos@"]}, "grants": [{"src": ["group:a"], "dst": ["tag:server"], "ip": [\#(ip)]}]}"#)
        }
        return accessChanges(from: policy(oldIP), to: policy(newIP), nodes: devices).first
    }

    func testWidenedRangeShowsExactNewPorts() {
        XCTAssertEqual(change(#""tcp:8000-8100""#, #""tcp:8000-8200""#)?.gained, ["8101-8200"])
    }

    func testChangeInsideRangeIsDetected() {
        // The old review only probed range endpoints and missed this.
        XCTAssertEqual(change(#""tcp:8000-8100""#, #""tcp:8050-8100""#)?.lost, ["8000-8049"])
    }

    func testWildcardShowsNamedPortsAndOtherPorts() {
        XCTAssertEqual(change(#""tcp:22""#, #""*""#)?.gained, [otherPortsLabel])
        XCTAssertNil(change(#""tcp:22""#, #""tcp:22""#))
    }

    func testLabelsMergeAdjacentNamedIntervals() {
        let ivs = [PortInterval(range: 22...22, named: true), PortInterval(range: 23...79, named: false),
                   PortInterval(range: 8000...8049, named: true), PortInterval(range: 8050...8100, named: true)]
        XCTAssertEqual(portLabels(ivs), ["22", "8000-8100", otherPortsLabel])
    }
}

final class ReachabilityTests: XCTestCase {
    func testWhoCanReachTag() {
        let m = model(SamplePolicy.text)
        let rules = ruleSummaries(m, sourceIDs: nil, destIDs: ["tag:db"])
        XCTAssertTrue(rules.contains { $0.kind == .grant && $0.sources == ["group:eng"] })  // tcp:6379 grant
        XCTAssertTrue(rules.contains { $0.sources == ["group:ops"] })                     // ops *:*
        XCTAssertFalse(rules.contains { $0.name.hasPrefix("Engineers reach") })           // only server + ci
        XCTAssertFalse(rules.contains { $0.kind == .ssh })                                // no SSH to tag:db
    }
}

final class GeneratedTestTests: XCTestCase {
    func testGeneratedTestsPassAndCarryMeaningfulDenies() {
        let m = model(SamplePolicy.text)
        let tests = generateTests(m, sources: m.allUsers + m.tagOrder)
        XCTAssertFalse(tests.isEmpty)
        let ev = Evaluator(model: m)
        for t in tests {
            for e in t.accept {
                let d = DestSpec(e)
                XCTAssertTrue(ev.evaluate(sourceID: t.src, destID: d.target, port: Int(d.ports)!).allowed, "\(t.src) \(e)")
            }
            for e in t.deny {
                let d = DestSpec(e)
                XCTAssertFalse(ev.evaluate(sourceID: t.src, destID: d.target, port: Int(d.ports)!).allowed, "\(t.src) \(e)")
            }
        }
        let dave = tests.first { $0.src == "dave@partner.com" }
        XCTAssertEqual(dave?.accept.contains("tag:server:443"), true)
        XCTAssertEqual(dave?.deny.contains("tag:server:22"), true) // others reach :22, dave doesn't
    }
}

final class RouteTests: XCTestCase {
    let m = model("""
    {"groups": {"group:netadmins": ["sos@"]},
     "tagOwners": {"tag:router": ["group:netadmins"], "tag:exit": ["group:netadmins"]},
     "autoApprovers": {"routes": {"192.168.0.0/16": ["tag:router"]}, "exitNode": ["tag:exit"]},
     "nodeAttrs": [{"target": ["*"], "app": {"tailscale.com/app-connectors": []}}]}
    """)
    let devs = nodes("""
    {"nodes": [
      {"id": "1", "givenName": "router", "tags": ["tag:router"], "availableRoutes": ["192.168.1.0/24", "10.0.0.0/8"]},
      {"id": "2", "givenName": "exit", "tags": ["tag:exit"], "availableRoutes": ["0.0.0.0/0", "::/0"]},
      {"id": "3", "givenName": "laptop", "user": {"name": "sos"}}
    ]}
    """)

    func testParsesAutoApproversAndNodeAttrs() {
        XCTAssertEqual(m.routeApprovers.first?.route, "192.168.0.0/16")
        XCTAssertEqual(m.exitNodeApprovers, ["tag:exit"])
        XCTAssertEqual(m.nodeAttrs.first?.hasApp, true)
        XCTAssertEqual(devs[0].availableRoutes, ["192.168.1.0/24", "10.0.0.0/8"])
        XCTAssertEqual(devs[2].policyName, "sos@")
    }

    func testAutoApproval() {
        let ev = Evaluator(model: m)
        XCTAssertTrue(ev.autoApproves(route: "192.168.1.0/24", node: devs[0]))  // inside 192.168.0.0/16
        XCTAssertFalse(ev.autoApproves(route: "10.0.0.0/8", node: devs[0]))     // no approver entry
        XCTAssertTrue(ev.autoApproves(route: "0.0.0.0/0", node: devs[1]))       // exit node
        XCTAssertFalse(ev.autoApproves(route: "192.168.1.0/24", node: devs[2])) // wrong identity
    }

    func testApproverOnlyEntitiesAreNotUnused() {
        let titles = lintPolicy(m).map(\.title)
        XCTAssertFalse(titles.contains("Unused tag"), "\(titles)")
    }
}

@MainActor
final class RouteStoreTests: XCTestCase {
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

    func testRouteApproverEditing() {
        let store = PolicyStore()
        store.setRouteApprovers(route: "10.0.0.0/8", approvers: ["tag:router"])
        XCTAssertEqual(store.model.routeApprovers.map(\.route), ["10.0.0.0/8"])
        store.setRouteApprovers(route: "10.1.0.0/16", approvers: ["tag:router"], replacing: "10.0.0.0/8")
        XCTAssertEqual(store.model.routeApprovers.map(\.route), ["10.1.0.0/16"])
        store.setExitNodeApprovers(["tag:exit"])
        store.setRouteApprovers(route: "10.1.0.0/16", approvers: [])
        XCTAssertTrue(store.model.routeApprovers.isEmpty)
        store.setExitNodeApprovers([])
        XCTAssertFalse(store.text.contains("autoApprovers"), "empty section removed")
    }

    func testGeneratedTestsWrittenAndPass() {
        let store = PolicyStore()
        store.loadPolicy(SamplePolicy.text)
        let generated = generateTests(store.model, sources: store.model.allUsers)
        store.setGeneratedTests(generated, replacingExisting: true)
        XCTAssertEqual(store.model.tests.count, generated.count)
        XCTAssertTrue(store.testResults.allSatisfy(\.passed))
    }
}
