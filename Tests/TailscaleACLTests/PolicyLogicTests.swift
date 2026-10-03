import XCTest
@testable import TailscaleACL

func model(_ text: String) -> PolicyModel { PolicyModel(tree: try! HuJSONParser.parse(text)) }

func nodes(_ json: String) -> [HeadscaleNode] {
    struct R: Decodable { var nodes: [HeadscaleNode] }
    return try! JSONDecoder().decode(R.self, from: Data(json.utf8)).nodes
}

final class HuJSONTests: XCTestCase {
    func testParsesCommentsAndTrailingCommas() throws {
        let t = try HuJSONParser.parse("{ /* block */ \"a\": [1, 2,], // line\n \"b\": true, }")
        XCTAssertEqual(t["a"]?.elements?.count, 2)
    }

    func testRoundTripKeepsComments() throws {
        let text = HuJSONSerializer.serialize(try HuJSONParser.parse(SamplePolicy.text))
        XCTAssertTrue(text.contains("// Engineers reach app + CI servers over SSH and web ports."))
        XCTAssertEqual(model(text).rules.count, model(SamplePolicy.text).rules.count)
    }

    func testRejectsBrokenPolicy() {
        XCTAssertThrowsError(try HuJSONParser.parse("{ \"groups\": {"))
    }
}

final class EvaluatorTests: XCTestCase {
    let ev = Evaluator(model: model(SamplePolicy.text))

    func testSamplePolicyTestsPass() {
        XCTAssertTrue(ev.runTests().allSatisfy(\.passed))
    }

    func testACLPortsAndGroups() {
        XCTAssertTrue(ev.evaluate(sourceID: "alice@example.com", destID: "tag:server", port: 22).allowed)
        XCTAssertFalse(ev.evaluate(sourceID: "alice@example.com", destID: "tag:db", port: 5432).allowed)
        XCTAssertTrue(ev.portMatches(spec: "8000-8100", port: 8050))
        XCTAssertFalse(ev.portMatches(spec: "8000-8100", port: 8101))
    }

    func testGrantIPGrammar() {
        XCTAssertTrue(ev.ipSpecMatches(spec: "tcp:80-443", port: 90))
        XCTAssertTrue(ev.ipSpecMatches(spec: "443", port: 443))
        XCTAssertFalse(ev.ipSpecMatches(spec: "icmp:*", port: 443))
    }

    func testCIDR() {
        XCTAssertTrue(cidrContains(cidr: "10.0.0.0/16", ip: "10.0.42.7"))
        XCTAssertFalse(cidrContains(cidr: "10.0.0.0/16", ip: "10.1.0.1"))
        XCTAssertTrue(cidrContains(cidr: "10.0.0.5", ip: "10.0.0.5"))
    }

    func testHostPrefixAndIPSets() {
        let e = Evaluator(model: model("""
        {"groups": {"group:rds": ["a@x"]},
         "hosts": {"dc01": "10.1.0.11", "gw": "10.1.0.20"},
         "ipsets": {"ipset:RDS": ["10.1.0.20"]},
         "grants": [{"src": ["group:rds"], "dst": ["host:dc01"], "ip": ["tcp:53"]},
                    {"src": ["group:rds"], "dst": ["ipset:RDS"], "ip": ["tcp:3389"]}]}
        """))
        XCTAssertTrue(e.evaluate(sourceID: "a@x", destID: "dc01", port: 53).allowed)
        XCTAssertTrue(e.evaluate(sourceID: "a@x", destID: "gw", port: 3389).allowed) // gw is inside the IP set
        XCTAssertFalse(e.evaluate(sourceID: "a@x", destID: "dc01", port: 3389).allowed)
    }
}

final class NodeTests: XCTestCase {
    let n = nodes("""
    {"nodes": [
      {"id": "1", "givenName": "laptop", "user": {"name": "sos"}, "ipAddresses": ["100.64.0.1"], "online": true},
      {"id": "2", "givenName": "server", "user": {"name": "sos"}, "ipAddresses": ["100.64.0.2"], "tags": ["tag:server"],
       "lastSeen": "2026-09-30T08:15:02.123456789Z"},
      {"id": "3", "name": "old", "forcedTags": ["tag:legacy"]}
    ]}
    """)

    func testIdentities() {
        XCTAssertEqual(n[0].identities, ["sos", "sos@", "100.64.0.1"])
        XCTAssertEqual(n[1].identities, ["tag:server", "100.64.0.2"]) // tagged nodes drop their user
        XCTAssertEqual(n[2].allTags, ["tag:legacy"])
    }

    func testTaggedNodeLosesUserAccess() {
        let e = Evaluator(model: model("""
        {"groups": {"group:admins": ["sos@"]}, "tagOwners": {"tag:server": ["group:admins"]},
         "grants": [{"src": ["group:admins"], "dst": ["tag:server"], "ip": ["tcp:22"]}]}
        """))
        XCTAssertTrue(e.evaluate(sourceIDs: n[0].identities, destIDs: n[1].identities, port: 22).allowed)
        XCTAssertFalse(e.evaluate(sourceIDs: n[1].identities, destIDs: n[1].identities, port: 22).allowed)
    }

    func testStatus() {
        XCTAssertEqual(n[0].statusText, "online")
        XCTAssertNotNil(n[1].lastSeenDate) // nanosecond timestamp parses
        XCTAssertTrue(n[1].statusText.hasPrefix("last seen"))
        XCTAssertEqual(n[2].statusText, "offline")
    }
}

final class LintTests: XCTestCase {
    func testSamplePolicyIsClean() {
        XCTAssertEqual(lintPolicy(model(SamplePolicy.text)).map(\.title), [])
    }

    func testDetectsStructuralProblems() {
        let titles = Set(lintPolicy(model("""
        {"groups": {"group:used": ["a@x"], "group:unused": ["b@x"], "group:empty": []},
         "hosts": {"bad": "not-an-ip"},
         "acls": [{"action": "accept", "src": ["group:used"], "dst": ["tag:noowner:22"]},
                  {"action": "accept", "src": ["group:ghost"], "dst": ["tag:noowner:22"]}],
         "grants": [{"src": ["group:empty"], "dst": ["ipset:nope"], "ip": ["banana"]}],
         "ssh": [{"action": "check", "src": ["tag:noowner"], "dst": ["tag:noowner"], "users": ["root"]}]}
        """)).map(\.title))
        for t in ["Undefined group", "Tag without owner", "Undefined IP set", "Unused group", "Empty group",
                  "Invalid host address", "Invalid grant ip entry", "Check mode from tagged source"] {
            XCTAssertTrue(titles.contains(t), t)
        }
    }

    func testDeviceChecks() {
        let devices = nodes("""
        {"nodes": [{"id": "1", "givenName": "a", "user": {"name": "sos"}, "tags": ["tag:server", "tag:stray"]}]}
        """)
        let titles = lintNodes(model("""
        {"groups": {"group:ghosts": ["nobody@"]},
         "tagOwners": {"tag:server": [], "tag:retired": []},
         "grants": [{"src": ["group:ghosts"], "dst": ["tag:server"], "ip": ["*"]}]}
        """), nodes: devices).map(\.title)
        XCTAssertTrue(titles.contains("Tag not on any device"))
        XCTAssertTrue(titles.contains("Undeclared device tag"))
        XCTAssertTrue(titles.contains("Rule matches no device"))
    }
}

final class SSHTests: XCTestCase {
    func testSSHNeedsRuleAndNetworkAccess() {
        let e = Evaluator(model: model("""
        {"groups": {"group:ops": ["bob@"]}, "tagOwners": {"tag:server": [], "tag:ci": []},
         "grants": [{"src": ["group:ops"], "dst": ["tag:server"], "ip": ["tcp:22"]}],
         "ssh": [{"action": "accept", "src": ["group:ops"], "dst": ["tag:server", "tag:ci"], "users": ["root"]}]}
        """))
        XCTAssertFalse(e.evaluateSSH(sourceIDs: ["bob@"], destIDs: ["tag:server"], login: "root").isEmpty)
        XCTAssertTrue(e.evaluateSSH(sourceIDs: ["bob@"], destIDs: ["tag:server"], login: "ubuntu").isEmpty)
        XCTAssertTrue(e.sshNetworkAllowed(sourceIDs: ["bob@"], destIDs: ["tag:server"]))
        XCTAssertFalse(e.sshNetworkAllowed(sourceIDs: ["bob@"], destIDs: ["tag:ci"]))
    }

    func testAutogroupSelf() {
        let e = Evaluator(model: model("""
        {"ssh": [{"action": "check", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["autogroup:nonroot"]}]}
        """))
        XCTAssertFalse(e.evaluateSSH(sourceIDs: ["sos@"], destIDs: ["sos@"], login: "ubuntu").isEmpty)
        XCTAssertTrue(e.evaluateSSH(sourceIDs: ["sos@"], destIDs: ["sos@"], login: "root").isEmpty)
        XCTAssertTrue(e.evaluateSSH(sourceIDs: ["sos@"], destIDs: ["bob@"], login: "ubuntu").isEmpty)
    }
}

final class ImpactTests: XCTestCase {
    let devices = nodes("""
    {"nodes": [
      {"id": "1", "givenName": "laptop", "user": {"name": "sos"}},
      {"id": "2", "givenName": "server", "user": {"name": "sos"}, "tags": ["tag:server"]}
    ]}
    """)

    func testAccessChanges() {
        let old = model("""
        {"groups": {"group:a": ["sos@"]}, "grants": [{"src": ["group:a"], "dst": ["tag:server"], "ip": ["tcp:22", "tcp:443"]}]}
        """)
        let new = model("""
        {"groups": {"group:a": ["sos@"]}, "grants": [{"src": ["group:a"], "dst": ["tag:server"], "ip": ["tcp:443"]}],
         "ssh": [{"action": "accept", "src": ["group:a"], "dst": ["tag:server"], "users": ["root"]}]}
        """)
        let c = accessChanges(from: old, to: new, nodes: devices)
        XCTAssertEqual(c.count, 1)
        XCTAssertEqual(c.first?.lost, ["22"])
        XCTAssertEqual(c.first?.sshGained, []) // SSH rule added but port 22 was removed
        XCTAssertTrue(accessChanges(from: old, to: old, nodes: devices).isEmpty)
    }

    func testLineDiff() {
        let old = (1...20).map { "line \($0)" }.joined(separator: "\n")
        let new = old.replacingOccurrences(of: "line 10", with: "line ten")
        let d = lineDiff(old: old, new: new)
        XCTAssertEqual(d.filter { $0.kind == .removed }.map(\.text), ["line 10"])
        XCTAssertEqual(d.filter { $0.kind == .added }.map(\.text), ["line ten"])
        XCTAssertEqual(d.filter { $0.kind == .same }.count, 6) // 3 lines of context each side
        XCTAssertEqual(d.filter { $0.kind == .skipped }.map(\.text), ["6", "7"]) // lines 1-6 and 14-20 hidden
        XCTAssertTrue(lineDiff(old: old, new: old).allSatisfy { $0.kind == .skipped })
    }

    func testRuleSummariesAndReport() {
        let m = model(SamplePolicy.text)
        let all = ruleSummaries(m, sourceIDs: nil)
        XCTAssertEqual(all.count, m.rules.count + m.grants.count + m.sshRules.count)
        let eng = ruleSummaries(m, sourceIDs: ["group:eng"])
        XCTAssertTrue(eng.contains { $0.name.hasPrefix("Engineers reach") && $0.destinations.contains("tag:server") })
        XCTAssertFalse(eng.contains { $0.name.hasPrefix("Ops can reach everything") })

        let report = policyReport(workspace: "Test", model: m, nodes: devices, problems: [])
        for heading in ["# Access report — Test", "## Groups", "## Tags", "## Devices", "## Rules",
                        "## Who can reach what", "### group:eng", "### laptop (device)", "No problems found."] {
            XCTAssertTrue(report.contains(heading), heading)
        }
    }
}
