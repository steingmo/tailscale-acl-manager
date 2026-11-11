import XCTest
@testable import TailscaleACL

/// Just-in-time access: a posture on one custom attribute, set on a device
/// with an expiry.
final class JITTests: XCTestCase {
    let policy = model("""
    {
      "postures": {
        "posture:jit-prod": ["custom:jitProd == true"],
        "posture:env": ["custom:env == 'prod'"],
        "posture:managed": ["custom:jitProd == true", "node:os == 'macos'"],
        "posture:not": ["custom:blocked != true"],
        "posture:os": ["node:os == 'macos'"],
      },
      "grants": [
        {"src": ["group:eng"], "dst": ["tag:prod"], "ip": ["tcp:22"], "srcPosture": ["posture:jit-prod"]},
        {"src": ["group:eng"], "dst": ["tag:web"], "ip": ["tcp:443"]},
      ],
      "groups": {"group:eng": ["alice@example.com"]},
    }
    """)

    func testOnlyOneAttributePosturesAreJIT() {
        let found = jitPostures(policy)
        XCTAssertEqual(found.map(\.name), ["posture:jit-prod", "posture:env"])
        XCTAssertEqual(found[0].key, "custom:jitProd")
        XCTAssertEqual(found[0].value, .bool(true))
        XCTAssertEqual(found[1].value, .string("prod"))
        XCTAssertEqual(found[0].shortName, "jit-prod")
        XCTAssertEqual(jitUnlocks(policy, found[0]),
                       ["Everyone in eng can reach devices tagged prod on SSH, only from devices that pass the jit-prod posture check."])
        XCTAssertEqual(jitUnlocks(policy, found[1]), [])
    }

    func testAttributeNames() {
        XCTAssertTrue(isCustomAttributeKey("custom:jit_Prod:2"))
        for bad in ["custom:", "node:os", "custom:a/b", "custom:a b", "custom:../x", "custom:é", "custom:" + String(repeating: "a", count: 130)] {
            XCTAssertFalse(isCustomAttributeKey(bad), bad)
        }
    }

    func testAccessExistsOnlyWhileTheAttributeIsSet() {
        func reaches(_ attributes: [String: String]) -> Bool {
            var laptop = HeadscaleNode(id: "1", name: "laptop")
            laptop.attributes = attributes
            return laptop.evaluator(policy).evaluate(sourceIDs: ["alice@example.com", "group:eng"], destIDs: ["tag:prod"], port: 22).allowed
        }
        XCTAssertTrue(reaches(["custom:jitProd": "true"]))
        XCTAssertFalse(reaches([:]), "attributes loaded and the attribute isn't there: no access")
    }

    func testActiveGrants() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        func iso(_ offset: TimeInterval) -> String { ISO8601DateFormatter().string(from: now.addingTimeInterval(offset)) }
        var held = HeadscaleNode(id: "1", name: "held")
        held.attributes = ["custom:jitProd": "true"]
        held.attributeExpiries = ["custom:jitProd": iso(2 * 3_600 + 5 * 60)]
        var over = HeadscaleNode(id: "2", name: "over")
        over.attributes = ["custom:jitProd": "true"]
        over.attributeExpiries = ["custom:jitProd": iso(-60)]
        var forever = HeadscaleNode(id: "3", name: "forever")
        forever.attributes = ["custom:env": "prod"]
        var other = HeadscaleNode(id: "4", name: "other")
        other.attributes = ["custom:env": "test"]
        let grants = activeJIT([forever, over, held, other, HeadscaleNode(id: "5", name: "unknown")], jitPostures(policy), now: now)
        XCTAssertEqual(grants.map(\.node.displayName), ["held", "forever"], "soonest to end first; expired and other values left out")
        XCTAssertEqual(grants[0].expires.map { jitTimeLeft($0, now: now) }, "2 h 5 min")
        XCTAssertNil(grants[1].expires)
        XCTAssertEqual(jitTimeLeft(now.addingTimeInterval(45 * 60), now: now), "45 min")
        XCTAssertEqual(jitTimeLeft(now.addingTimeInterval(7 * 86_400), now: now), "7 days")
    }

    func testTailscaleSetsAndRemovesTheAttribute() async throws {
        StubProtocol.requests = []
        StubProtocol.handler = { request, _ in
            request.httpMethod == "DELETE" ? .init() : .init(body: Data("""
            {"attributes": {"custom:jitProd": true, "node:os": "macos"}, "expiries": {"custom:jitProd": "2027-01-15T10:00:00Z"}}
            """.utf8))
        }
        let client = makeServer(kind: .tailscale, serverURL: "", tailnet: "-", credential: "tskey-api-x", session: StubProtocol.session())!
        let server = GuardedServer(client, workspace: "t", requireAuth: false)
        let until = ISO8601DateFormatter().date(from: "2027-01-15T10:00:00Z")!
        let posture = try await server.setPostureAttribute(nodeID: "n1", key: "custom:jitProd", value: .bool(true), expiry: until,
                                                           comment: "TICKET-1")
        XCTAssertEqual(posture, DevicePosture(attributes: ["custom:jitProd": "true", "node:os": "macos"],
                                              expiries: ["custom:jitProd": "2027-01-15T10:00:00Z"]))
        let sent = try XCTUnwrap(StubProtocol.requests.last)
        XCTAssertEqual(sent.request.httpMethod, "POST")
        XCTAssertEqual(sent.request.url?.path, "/api/v2/device/n1/attributes/custom:jitProd")
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: sent.body) as? [String: Any])
        XCTAssertEqual(body["value"] as? Bool, true)
        XCTAssertEqual(body["expiry"] as? String, "2027-01-15T10:00:00Z")
        XCTAssertEqual(body["comment"] as? String, "TICKET-1")

        try await server.removePostureAttribute(nodeID: "n1", key: "custom:jitProd")
        XCTAssertEqual(StubProtocol.requests.last?.request.httpMethod, "DELETE")
        XCTAssertEqual(StubProtocol.requests.last?.request.url?.path, "/api/v2/device/n1/attributes/custom:jitProd")

        // A name that isn't a custom attribute never reaches the request path.
        let before = StubProtocol.requests.count
        do {
            _ = try await server.setPostureAttribute(nodeID: "n1", key: "custom:x/../../acl", value: .bool(true), expiry: nil, comment: "")
            XCTFail("an invalid attribute name must be refused")
        } catch {}
        XCTAssertEqual(StubProtocol.requests.count, before)

        let headscale = makeServer(kind: .headscale, serverURL: "https://hs.example", tailnet: "", credential: "k", session: StubProtocol.session())!
        do {
            _ = try await headscale.setPostureAttribute(nodeID: "1", key: "custom:jitProd", value: .bool(true), expiry: until, comment: "")
            XCTFail("Headscale has no posture attributes")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("doesn't support"), error.localizedDescription)
        }
    }

    func testTemplateRequiresThePostureForDestinations() throws {
        var tree = try HuJSONParser.parse(#"{"grants": [{"src": ["group:eng"], "dst": ["tag:prod"], "ip": ["tcp:22"]}, {"src": ["group:eng"], "dst": ["tag:web"], "ip": ["*"]}]}"#)
        policyTemplates.first { $0.id == "jit" }!.apply(&tree, ["posture": "jit-prod", "attribute": "custom:jitProd", "destinations": "tag:prod"])
        let m = PolicyModel(tree: tree)
        XCTAssertEqual(jitPostures(m), [JITPosture(name: "posture:jit-prod", key: "custom:jitProd", value: .bool(true))])
        XCTAssertEqual(m.grants.map(\.srcPosture), [["posture:jit-prod"], []])
    }
}
