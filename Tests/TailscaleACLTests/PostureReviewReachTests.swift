import XCTest
@testable import TailscaleACL

final class HuntressPostureTests: XCTestCase {
    func testImpossibleValuesAndTypos() {
        let issues = lintPostureValues("posture:trusted", [
            "huntress:defenderStatus == 'Healthy'",            // Tailscale's own example
            "huntress:firewallStatus == 'enabled'",            // wrong case
            "huntress:defenderPolicyStatus IN ['Compliant', 'NonCompliant']",
            "huntress:defenderstatus == 'Protected'",          // attribute typo
            "node:os == 'windows'",                            // not an integration attribute
        ])
        XCTAssertEqual(issues.count, 4, issues.map(\.detail).joined(separator: "\n"))
        func fix(_ i: Int) -> String? {
            if case .replacePostureCondition(_, _, let text)? = issues[i].fixes.first?.action { return text }
            return nil
        }
        XCTAssertEqual(issues[0].severity, .error)
        XCTAssertEqual(issues[0].title, "Posture no device can meet")
        XCTAssertEqual(fix(0), "huntress:defenderStatus == 'Protected'")
        XCTAssertEqual(fix(1), "huntress:firewallStatus == 'Enabled'")
        XCTAssertEqual(issues[2].severity, .warning, "one IN value is still reachable")
        XCTAssertEqual(fix(2), "huntress:defenderPolicyStatus IN ['Compliant', 'Non Compliant']")
        XCTAssertEqual(issues[3].title, "Unknown huntress attribute")
        XCTAssertEqual(fix(3), "huntress:defenderStatus == 'Protected'")
    }

    func testTailscaleAttributesAreStrings() async throws {
        StubProtocol.requests = []
        StubProtocol.handler = { _, _ in .init(body: Data("""
        {"attributes": {"huntress:defenderStatus": "Protected", "custom:score": 80, "custom:encrypted": true, "node:os": "windows"}}
        """.utf8)) }
        let c = makeServer(kind: .tailscale, serverURL: "", tailnet: "-", credential: "tskey-api-x", session: StubProtocol.session())!
        let attrs = try await GuardedServer(c, workspace: "t", requireAuth: false).postureAttributes(nodeID: "n1")
        XCTAssertEqual(StubProtocol.requests.first?.request.url?.path, "/api/v2/device/n1/attributes")
        XCTAssertEqual(attrs, ["huntress:defenderStatus": "Protected", "custom:score": "80", "custom:encrypted": "true", "node:os": "windows"])
        let headscale = makeServer(kind: .headscale, serverURL: "https://hs.example", tailnet: "", credential: "k", session: StubProtocol.session())!
        let none = try await headscale.postureAttributes(nodeID: "1")
        XCTAssertNil(none)
    }

    func testDryRunShowsWhoLosesAccess() {
        let old = model(#"{"grants": [{"src": ["autogroup:member"], "dst": ["tag:rds"], "ip": ["3389"]}]}"#)
        let new = model("""
        {"postures": {"posture:huntress": ["huntress:firewallStatus == 'Enabled'", "huntress:defenderStatus IN ['Protected', 'Incompatible']"]},
         "grants": [{"src": ["autogroup:member"], "dst": ["tag:rds"], "ip": ["3389"], "srcPosture": ["posture:huntress"]}]}
        """)
        let rds = HeadscaleNode(id: "1", name: "rds", ipAddresses: ["100.64.0.1"], tags: ["tag:rds"])
        var good = HeadscaleNode(id: "2", name: "good-pc", ipAddresses: ["100.64.0.2"], user: .init(name: "a@x.com", email: "a@x.com"))
        good.attributes = ["huntress:firewallStatus": "Enabled", "huntress:defenderStatus": "Protected"]
        var mac = HeadscaleNode(id: "3", name: "mac", ipAddresses: ["100.64.0.3"], user: .init(name: "b@x.com", email: "b@x.com"))
        mac.attributes = ["huntress:firewallStatus": "Enabled", "huntress:defenderStatus": "Incompatible"]
        var bad = HeadscaleNode(id: "4", name: "no-firewall", ipAddresses: ["100.64.0.4"], user: .init(name: "c@x.com", email: "c@x.com"))
        bad.attributes = ["huntress:defenderStatus": "Protected"]
        let unknown = HeadscaleNode(id: "5", name: "not-loaded", ipAddresses: ["100.64.0.5"], user: .init(name: "d@x.com", email: "d@x.com"))
        let changes = accessChanges(from: old, to: new, nodes: [rds, good, mac, bad, unknown])
        XCTAssertEqual(changes.map(\.src), ["no-firewall"], "only the device that fails the posture loses access")
        XCTAssertEqual(changes.first?.lost, ["3389"])
        XCTAssertTrue(new.usesPostures)
        XCTAssertEqual(bad.meets(new.postures["posture:huntress"]!), false)
        XCTAssertNil(unknown.meets(new.postures["posture:huntress"]!))
    }

    func testRequireHuntressTemplate() {
        var tree = try! HuJSONParser.parse("""
        {"grants": [{"src": ["group:mgmt"], "dst": ["10.0.0.0/8"], "ip": ["*"]},
                    {"src": ["group:mgmt"], "dst": ["tag:a"], "ip": ["*"], "srcPosture": ["posture:other"]},
                    {"src": ["group:rds"], "dst": ["tag:b"], "ip": ["*"]}],
         "postures": {"posture:other": ["node:os == 'macos'"]}, "tagOwners": {"tag:a": [], "tag:b": []},
         "groups": {"group:mgmt": ["amy@x.com"], "group:rds": ["bob@x.com"]}}
        """)
        policyTemplates.first { $0.id == "huntress" }!.apply(&tree, ["posture": "posture:huntress-protected", "sources": "group:mgmt"])
        let m = model(HuJSONSerializer.serialize(tree))
        XCTAssertEqual(m.grants.map(\.srcPosture), [["posture:huntress-protected"], ["posture:other"], []])
        XCTAssertEqual(lintPolicy(m).filter { $0.severity == .error }.map(\.detail), [])
    }
}

final class WhoCanReachTests: XCTestCase {
    func testPeopleMachinesAndCoveringRanges() {
        let m = model("""
        {"groups": {"group:rds": ["amy@x.com", "bob@x.com"]},
         "ipsets": {"ipset:RDS": ["10.114.32.20", "10.114.15.4"]},
         "grants": [
           {"src": ["group:rds"], "dst": ["ipset:RDS"], "ip": ["tcp:3389"], "via": ["tag:client-vpn"]},
           {"src": ["eve@x.com"], "dst": ["10.114.32.0/24"], "ip": ["*"]},
           {"src": ["tag:pos"], "dst": ["ipset:RDS"], "ip": ["tcp:3389"]},
           {"src": ["autogroup:member"], "dst": ["tag:web"], "ip": ["443"]},
         ],
         "acls": [{"action": "accept", "src": ["amy@x.com"], "dst": ["10.114.15.4:22", "tag:web:80"]}]}
        """)
        let entries = whoCanReach("ipset:RDS", m, nodes: [], accounts: [])
        XCTAssertEqual(entries.map(\.who), ["amy@x.com", "bob@x.com", "eve@x.com", "tag:pos"])
        XCTAssertFalse(entries[3].isPerson)
        let amy = entries[0].access
        XCTAssertEqual(amy.map(\.ports), ["22", "TCP:3389"], "only the ACL destination that reaches it")
        XCTAssertEqual(amy[1].through, "group:rds")
        XCTAssertEqual(amy[1].notes, ["via tag:client-vpn"])
        XCTAssertEqual(entries[2].access.first?.ports, "All", "a covering range counts")

        let web = whoCanReach("tag:web", m, nodes: [], accounts: [ServerAccount(id: "1", login: "zoe@x.com", displayName: "Zoe", policyNames: ["zoe@x.com"])])
        XCTAssertEqual(web.map(\.who), ["amy@x.com", "bob@x.com", "eve@x.com", "zoe@x.com"], "autogroup:member is everyone known")
        let csv = whoCanReachCSV("tag:web", web)
        XCTAssertTrue(csv.hasPrefix("who,kind,through,rule,access,conditions\n"))
        XCTAssertTrue(csv.contains("\"zoe@x.com\",\"person\",\"autogroup:member\""))
    }
}

final class AccessReviewTests: XCTestCase {
    func testKeysFollowContentAndReport() {
        let a = model(#"{"groups": {"group:eng": ["amy@x.com"]}, "grants": [{"src": ["group:eng"], "dst": ["tag:db"], "ip": ["5432"]}]}"#)
        let b = model(#"{"groups": {"group:eng": ["amy@x.com", "bob@x.com"]}, "grants": [{"src": ["group:eng"], "dst": ["tag:db"], "ip": ["5432"]}]}"#)
        let ia = reviewItems(a), ib = reviewItems(b)
        XCTAssertEqual(ia.map(\.title), ["group:eng", "Grant #1"])
        XCTAssertNotEqual(ia[0].key, ib[0].key, "a membership change needs a new decision")
        XCTAssertEqual(ia[1].key, ib[1].key)
        XCTAssertEqual(ia[1].path, "grants[0]")

        var review = AccessReview(started: Date(timeIntervalSince1970: 1_790_000_000))
        review.decisions[ia[0].key] = ReviewDecision(keep: true, by: "Sos", at: review.started!, note: "core team", title: ia[0].title, detail: ia[0].detail)
        review.decisions[ia[1].key] = ReviewDecision(keep: false, by: "Sos", at: review.started!, title: ia[1].title, detail: ia[1].detail)
        let report = accessReviewReport(workspace: "Office", review: review, items: ib)
        XCTAssertTrue(report.contains("2 items: 0 kept, 1 to remove, 1 not reviewed"), report)
        XCTAssertTrue(report.contains("## No longer in the policy"))
        XCTAssertTrue(report.contains("core team (was kept)"))
        XCTAssertTrue(report.contains("Reviewed by Sos."))
    }
}

@MainActor
final class CacheAndReviewStoreTests: XCTestCase {
    var dir: URL!
    var ws: Workspace!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        setenv("TAILSCALE_ACL_DATA_DIR", dir.path, 1)
        ws = Workspace(name: "Home", serverURL: "", policy: """
        {"groups": {"group:old": ["amy@x.com"], "group:eng": ["bob@x.com"]},
         "grants": [{"src": ["group:old"], "dst": ["tag:a"], "ip": ["*"]},
                    {"src": ["group:eng"], "dst": ["tag:b"], "ip": ["*"]},
                    {"src": ["eve@x.com"], "dst": ["tag:c"], "ip": ["*"]}],
         "tagOwners": {"tag:a": [], "tag:b": [], "tag:c": []}}
        """)
        try WorkspaceStore.save([ws])
        UserDefaults.standard.set(ws.id.uuidString, forKey: "currentWorkspaceID")
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        unsetenv("TAILSCALE_ACL_DATA_DIR")
    }

    func testCacheShowsLastServerDataOnOpen() {
        var node = HeadscaleNode(id: "1", name: "pc", ipAddresses: ["100.64.0.1"])
        node.attributes = ["huntress:firewallStatus": "Enabled"]
        ServerCache(saved: Date(timeIntervalSinceNow: -600), nodes: [node],
                    accounts: [ServerAccount(id: "u", login: "amy@x.com", displayName: "Amy", policyNames: ["amy@x.com"])],
                    policyChanges: [PolicyChange(date: Date(), who: "Amy", origin: "API")]).save(ws.id)
        let store = PolicyStore()
        XCTAssertEqual(store.headscaleNodes.first?.attributes, ["huntress:firewallStatus": "Enabled"])
        XCTAssertEqual(store.serverLogins, ["amy@x.com"])
        XCTAssertEqual(store.policyChanges?.first?.who, "Amy")
        XCTAssertNotNil(store.serverDataSaved)
        XCTAssertTrue(DataEncryption.dataFiles.contains { $0.path.contains("server-cache") })
        XCTAssertTrue(Backup.isAllowedPath("server-cache/\(ws.id.uuidString).json"))
        XCTAssertTrue(Backup.isAllowedPath("reviews/\(ws.id.uuidString).json"))
    }

    func testReviewDecisionsPersistAndRemovalsApply() {
        let store = PolicyStore()
        store.startNewReview()
        let items = reviewItems(store.model)
        let oldGroup = items.first { $0.title == "group:old" }!
        let eveRule = items.first { $0.detail.hasPrefix("eve@x.com") }!
        store.decide(oldGroup, keep: false, by: "Sos")
        store.decide(eveRule, keep: false, by: "Sos")
        store.decide(items.first { $0.title == "group:eng" }!, keep: true, by: "Sos")
        store.setReviewNote(oldGroup, "team disbanded")
        XCTAssertEqual(AccessReview.load(ws.id).decisions[oldGroup.key]?.note, "team disbanded")

        store.applyReviewRemovals(items)
        XCTAssertNil(store.model.groups["group:old"])
        XCTAssertEqual(store.model.grants.map(\.src), [["group:eng"]], "eve's rule is deleted, and so is the rule left without sources")
    }
}
