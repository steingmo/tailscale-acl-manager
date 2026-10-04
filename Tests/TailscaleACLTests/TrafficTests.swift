import XCTest
@testable import TailscaleACL

final class TrafficTests: XCTestCase {
    let laptop = HeadscaleNode(id: "1", name: "amy-laptop", ipAddresses: ["100.64.0.1"],
                               user: .init(name: "amy@x.com", email: "amy@x.com"))
    let router = HeadscaleNode(id: "2", name: "router", ipAddresses: ["100.64.0.2"], tags: ["tag:router"])
    let db = HeadscaleNode(id: "3", name: "db", ipAddresses: ["100.64.0.3"], tags: ["tag:db"])

    func testHostPortParsing() {
        XCTAssertEqual(splitHostPort("100.64.0.1:52343")?.ip, "100.64.0.1")
        XCTAssertEqual(splitHostPort("[fd7a:115c:a1e0::1]:443")?.ip, "fd7a:115c:a1e0::1")
        XCTAssertEqual(splitHostPort("[fd7a:115c:a1e0::1]:443")?.port, 443)
        XCTAssertNil(splitHostPort("nonsense"))
    }

    func testBothEndsBecomeOneConnection() {
        var acc = TrafficAccumulator()
        acc.add([
            // The laptop's view, then the database's view of the same connection.
            FlowRecord(kind: .virtual, proto: 6, src: "100.64.0.1:52343", dst: "100.64.0.3:5432", txBytes: 100, rxBytes: 900),
            FlowRecord(kind: .virtual, proto: 6, src: "100.64.0.3:5432", dst: "100.64.0.1:52343", txBytes: 900, rxBytes: 100),
            FlowRecord(kind: .virtual, proto: 6, src: "100.64.0.1:52344", dst: "100.64.0.3:5432", txBytes: 10, rxBytes: 10),
            // Subnet traffic, logged by the client and (reversed) by the router.
            FlowRecord(kind: .subnet, proto: 17, src: "100.64.0.1:60000", dst: "10.114.32.11:88", txBytes: 50, rxBytes: 50),
            FlowRecord(kind: .subnet, proto: 17, src: "10.114.32.11:88", dst: "100.64.0.1:60000", txBytes: 50, rxBytes: 50),
        ])
        let rows = acc.connections
        XCTAssertEqual(rows.count, 2)
        let pg = rows.first { $0.port == 5432 }!
        XCTAssertEqual(pg.client, "100.64.0.1")
        XCTAssertEqual(pg.server, "100.64.0.3")
        XCTAssertEqual(pg.connections, 2, "two client ports")
        XCTAssertEqual(pg.bytes, 1020, "bytes counted once, from the client's side")
        let kerberos = rows.first { $0.port == 88 }!
        XCTAssertEqual(kerberos.kind, .subnet)
        XCTAssertEqual(kerberos.server, "10.114.32.11")
        XCTAssertEqual(kerberos.ipSpec, "udp:88")
    }

    func testFetchParsesFlowLogs() async throws {
        StubProtocol.requests = []
        StubProtocol.handler = { _, _ in .init(body: Data("""
        {"logs": [{"nodeId": "n1", "logged": "2026-10-03T10:00:05.5Z", "end": "2026-10-03T10:00:05Z",
          "virtualTraffic": [{"proto": 6, "src": "100.64.0.1:52343", "dst": "100.64.0.3:5432", "txBytes": 10, "rxBytes": 20}],
          "subnetTraffic": [{"proto": 17, "src": "100.64.0.1:60000", "dst": "10.114.32.11:88"}],
          "physicalTraffic": [{"proto": 17, "src": "192.168.1.5:41641", "dst": "1.2.3.4:41641"}]}]}
        """.utf8)) }
        let c = makeServer(kind: .tailscale, serverURL: "", tailnet: "-", credential: "tskey-api-x",
                           session: StubProtocol.session())!
        let from = ISO8601DateFormatter().date(from: "2026-10-03T00:00:00Z")!
        let records = try await c.flowRecords(from: from, to: from.addingTimeInterval(86_400))
        XCTAssertEqual(records?.map(\.kind), [.virtual, .subnet], "physical (underlay) traffic is left out")
        XCTAssertEqual(records?.first?.proto, 6)
        XCTAssertNotNil(records?.first?.end)
        let url = StubProtocol.requests[0].request.url!
        XCTAssertEqual(url.path, "/api/v2/tailnet/-/logging/network")
        XCTAssertTrue(url.query!.contains("start=2026-10-03T00:00:00Z"))

        let hs = makeServer(kind: .headscale, serverURL: "https://hs.example", tailnet: "", credential: "k",
                            session: StubProtocol.session())!
        let none = try await hs.flowRecords(from: from, to: from)
        XCTAssertNil(none, "Headscale keeps no flow logs")
    }

    let policy = """
    {"tagOwners": {"tag:db": [], "tag:router": []},
     "ipsets": {"ipset:dcs": ["add 10.114.32.0/24"]},
     "grants": [
       {"src": ["amy@x.com"], "dst": ["tag:db"], "ip": ["*"]},
       {"src": ["amy@x.com"], "dst": ["ipset:dcs"], "ip": ["udp:88", "tcp:88", "tcp:389"]},
       {"src": ["amy@x.com"], "dst": ["tag:router"], "ip": ["22"]},
     ]}
    """

    var traffic: [TrafficConnection] {
        var acc = TrafficAccumulator()
        acc.add([
            FlowRecord(kind: .virtual, proto: 6, src: "100.64.0.1:52343", dst: "100.64.0.3:5432"),
            FlowRecord(kind: .virtual, proto: 6, src: "100.64.0.1:52344", dst: "100.64.0.3:5432"),
            FlowRecord(kind: .subnet, proto: 17, src: "100.64.0.1:60000", dst: "10.114.32.11:88"),
        ])
        return acc.connections
    }

    func testRuleUsage() {
        let usage = ruleUsage(traffic, model(policy), nodes: [laptop, router, db])
        XCTAssertEqual(usage["grant-0"]?.ports, ["tcp:5432": 2], "the * grant only used 5432")
        XCTAssertEqual(usage["grant-1"]?.ports, ["udp:88": 1])
        XCTAssertNil(usage["grant-2"], "no traffic to the router")
    }

    func testPushWouldBlockRealTraffic() {
        let old = model(policy)
        let new = model(policy.replacingOccurrences(of: #""udp:88", "#, with: ""))
        let blocked = trafficBlocked(by: new, was: old, traffic: traffic, nodes: [laptop, router, db])
        XCTAssertEqual(blocked.map(\.port), [88])
        XCTAssertTrue(trafficBlocked(by: old, was: old, traffic: traffic, nodes: [laptop, router, db]).isEmpty)

        let md = pushReviewMarkdown(PushReview(workspace: "W", host: "Tailscale", serverText: "a", candidate: "b",
                                               blockedTraffic: ["amy-laptop → 10.114.32.11 UDP 88 (1 connections)"]))
        XCTAssertTrue(md.contains("- ❌ 1 kind of recent real traffic would be blocked."))
        XCTAssertTrue(md.contains("## Real traffic this would block\n\n- amy-laptop → 10.114.32.11 UDP 88"))
    }
}
