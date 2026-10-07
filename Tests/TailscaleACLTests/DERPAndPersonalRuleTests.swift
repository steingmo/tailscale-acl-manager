import XCTest
@testable import TailscaleACL

final class DERPTests: XCTestCase {
    func testParsesAnyKeyCase() {
        let regions = model("""
        {"derpMap": {"omitDefaultRegions": false, "regions": {
           "900": {"RegionID": 900, "RegionCode": "fo", "Nodes": [
             {"Name": "900a", "RegionID": 900, "HostName": "derp.example.com", "IPv4": "203.0.113.5", "IPv6": "none", "STUNPort": -1}]},
           "1": null}}}
        """).derpRegions
        XCTAssertEqual(regions.map(\.key), ["900", "1"])
        XCTAssertTrue(regions[1].removed)
        let n = regions[0].nodes[0]
        XCTAssertEqual(n.hostName, "derp.example.com")
        XCTAssertEqual(n.fixedIPv4, "203.0.113.5")
        XCTAssertEqual(n.httpsPort, 443)
        XCTAssertNil(n.stunPortUsed)
        XCTAssertEqual(n.path, "derpMap.regions[900].Nodes[0]")
        XCTAssertTrue(lintDERP(regions).isEmpty, lintDERP(regions).map(\.title).joined(separator: "; "))
    }

    func testMistakes() {
        let issues = lintDERP(model("""
        {"derpMap": {"Regions": {
           "901": {"RegionID": 900, "Nodes": [
             {"Name": "a", "RegionID": 902, "HostName": "", "IPv4": "10.0.0.5", "IPv6": "nope", "DERPPort": 70000}]},
           "5": {"RegionID": 5, "RegionCode": "x", "Nodes": []}}}}
        """).derpRegions)
        let titles = Set(issues.map(\.title))
        for t in ["DERP region 901 has RegionID 900", "DERP region 901 has no RegionCode", "DERP server a has no HostName",
                  "DERP server a is in the wrong region", "DERP server a has a private IPv4", "DERP server a has an invalid IPv6",
                  "DERP server a has an invalid DERPPort", "DERP region 5 uses Tailscale's region ID", "DERP region 5 has no servers"] {
            XCTAssertTrue(titles.contains(t), t)
        }
        let p = try! HuJSONParser.parse(#"{"derpMap": {"Regions": {"901": {"RegionID": 900}}}}"#)
        XCTAssertEqual(p.line(at: "derpMap.Regions[901]"), 1)
    }

    func testSTUNMessages() {
        let tx: [UInt8] = Array(1...12)
        let req = stunBindingRequest(transactionID: tx)
        XCTAssertEqual(req.count, 40)
        XCTAssertEqual(Array(req.prefix(8)), [0, 1, 0, 20, 0x21, 0x12, 0xA4, 0x42])
        XCTAssertEqual(crc32(Array("123456789".utf8)), 0xCBF4_3926, "standard CRC-32 check value")
        var reply = req.prefix(20)
        reply[0] = 0x01; reply[1] = 0x01
        XCTAssertTrue(isSTUNBindingSuccess(reply, transactionID: tx))
        XCTAssertFalse(isSTUNBindingSuccess(reply, transactionID: Array(repeating: 0, count: 12)))
        XCTAssertFalse(isSTUNBindingSuccess(req, transactionID: tx), "a request isn't a response")
    }
}

final class PersonalRuleTests: XCTestCase {
    func testFindsAndMergesSameAccess() {
        let m = model("""
        {"hosts": {"dc01": "10.0.0.11"}, "groups": {"group:windmill-users": []},
         "grants": [
           {"src": ["ben@x.com"], "dst": ["ipset:windmill"], "ip": ["*"], "via": ["tag:r"]},
           {"src": ["stian@x.com"], "dst": ["ipset:windmill"], "ip": ["*"], "via": ["tag:r"]},
           {"src": ["tbo@x.com"], "dst": ["10.0.0.11"], "ip": ["tcp:8093"]},
           // expires: 2099-01-01
           {"src": ["temp@x.com"], "dst": ["10.0.0.11"], "ip": ["tcp:22"]},
           {"src": ["group:eng", "amy@x.com"], "dst": ["tag:db"], "ip": ["*"]},
         ],
         "acls": [{"action": "accept", "src": ["eve@x.com", "bob@x.com"], "dst": ["tag:web:443"]}]}
        """)
        let all = lintPersonalRules(m)
        XCTAssertEqual(all.count, 3, all.map(\.detail).joined(separator: "\\n"))
        let issues = ["grants[0].src", "grants[2].src", "acls[0].src"].compactMap { p in all.first { $0.path == p } }
        XCTAssertEqual(issues.count, 3)
        guard case .moveToGroup(let section, let indices, let group, let members)? = issues[0].fixes.first?.action else {
            return XCTFail("expected a fix")
        }
        XCTAssertEqual(section, "grants")
        XCTAssertEqual(indices, [0, 1])
        XCTAssertEqual(group, "group:windmill-users-2", "never an existing group")
        XCTAssertEqual(members, ["ben@x.com", "stian@x.com"])
        XCTAssertEqual(issues[0].title, "Access given to people one by one")
        XCTAssertEqual(issues[1].title, "Access given to one person")
        XCTAssertTrue(issues[1].fixes[0].label.hasSuffix("group:dc01-users"), "IPs use their host name")
        XCTAssertEqual(issues[2].path, "acls[0].src")
        XCTAssertEqual(suggestedGroupName(["10.1.2.3"], m), "group:access-10-1-2-3-users")
        XCTAssertEqual(suggestedGroupName(["tag:web:443"], m), "group:web-users")
    }
}

@MainActor
final class PersonalRuleFixTests: XCTestCase {
    var dir: URL!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        setenv("TAILSCALE_ACL_DATA_DIR", dir.path, 1)
        let ws = Workspace(name: "Home", serverURL: "", policy: """
        {"grants": [
           // Windmill
           {"src": ["ben@x.com"], "dst": ["ipset:windmill"], "ip": ["*"]},
           {"src": ["group:eng"], "dst": ["tag:db"], "ip": ["*"]},
           {"src": ["stian@x.com"], "dst": ["ipset:windmill"], "ip": ["*"]},
         ],
         "ipsets": {"ipset:windmill": ["10.0.0.45"]}, "groups": {"group:eng": ["amy@x.com"]}, "tagOwners": {"tag:db": []}}
        """)
        try WorkspaceStore.save([ws])
        UserDefaults.standard.set(ws.id.uuidString, forKey: "currentWorkspaceID")
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        unsetenv("TAILSCALE_ACL_DATA_DIR")
    }

    func testMoveToGroup() {
        let store = PolicyStore()
        let before = Evaluator(model: store.model)
        let issue = store.lintIssues.first { $0.title == "Access given to people one by one" }
        XCTAssertNotNil(issue)
        store.apply(issue!.fixes[0].action)
        XCTAssertEqual(store.model.groups["group:windmill-users"], ["ben@x.com", "stian@x.com"])
        XCTAssertEqual(store.model.grants.map(\.src), [["group:windmill-users"], ["group:eng"]])
        XCTAssertEqual(store.model.grants[0].comments, ["Windmill"])
        let after = Evaluator(model: store.model)
        for who in ["ben@x.com", "stian@x.com", "amy@x.com", "eve@x.com"] {
            XCTAssertEqual(before.evaluate(sourceID: who, destID: "10.0.0.45", port: 443).allowed,
                           after.evaluate(sourceID: who, destID: "10.0.0.45", port: 443).allowed, who)
        }
        XCTAssertFalse(store.lintIssues.contains { $0.title.hasPrefix("Access given to") })
    }
}
