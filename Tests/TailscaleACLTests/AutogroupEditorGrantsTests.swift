import XCTest
import AppKit
@testable import TailscaleACL

final class AddressAndAutogroupTests: XCTestCase {
    func testIPv6Addresses() {
        XCTAssertTrue(isAddressLike("fd7a:115c:a1e0::/48"))
        XCTAssertTrue(isAddressLike("fd7a:115c:a1e0:ab12:4843:cd96:6258:b240"))
        XCTAssertFalse(isAddressLike("fd7a::/129"))
        XCTAssertFalse(isAddressLike("10.0.0.256"))
        XCTAssertTrue(cidrContains(cidr: "fd7a:115c:a1e0::/48", ip: "fd7a:115c:a1e0:ab12::5"))
        XCTAssertFalse(cidrContains(cidr: "fd7a:115c:a1e0::/48", ip: "fd7a:115c:a1e1::5"))
        XCTAssertFalse(cidrContains(cidr: "10.0.0.0/8", ip: "fd7a::1"), "families don't mix")
        XCTAssertTrue(cidrContains(cidr: "10.0.0.0/8", ip: "10.1.2.3"))

        let d = DestSpec("[fd7a:115c:a1e0::1]:22,443")
        XCTAssertEqual(d.target, "fd7a:115c:a1e0::1")
        XCTAssertEqual(d.ports, "22,443")
        XCTAssertEqual(d.spec, "[fd7a:115c:a1e0::1]:22,443")
        XCTAssertEqual(DestSpec("fd7a:115c:a1e0::/48").target, "fd7a:115c:a1e0::/48")
        XCTAssertEqual(DestSpec("tag:web:80").target, "tag:web")

        let m = model("""
        {"hosts": {"v6box": "fd7a:115c:a1e0::5"},
         "acls": [{"action": "accept", "src": ["a@x.com"], "dst": ["[fd7a:115c:a1e0::/48]:22"]}]}
        """)
        XCTAssertTrue(Evaluator(model: m).evaluate(sourceID: "a@x.com", destID: "v6box", port: 22).allowed)
        XCTAssertFalse(lintPolicy(m).contains { $0.title == "Invalid host address" })
    }

    func testPublicAddresses() {
        XCTAssertTrue(isPublicAddress("8.8.8.8"))
        XCTAssertTrue(isPublicAddress("2606:4700::1111"))
        for a in ["10.1.1.1", "100.100.1.1", "192.168.1.1", "172.20.0.1", "127.0.0.1", "fd7a::1", "fe80::1"] {
            XCTAssertFalse(isPublicAddress(a), a)
        }
    }

    func testAutogroups() {
        let m = model("""
        {"grants": [
          {"src": ["autogroup:tagged"], "dst": ["autogroup:tagged"], "ip": ["443"]},
          {"src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["*"]},
          {"src": ["autogroup:admin"], "dst": ["tag:db"], "ip": ["5432"]},
          {"src": ["group:eng"], "dst": ["autogroup:internet"], "ip": ["*"]},
          {"src": ["autogroup:danger-all"], "dst": ["tag:pub"], "ip": ["80"]},
        ], "groups": {"group:eng": ["amy@x.com"]}, "tagOwners": {"tag:db": [], "tag:pub": [], "tag:ci": []}}
        """)
        let ev = Evaluator(model: m)
        XCTAssertTrue(ev.evaluate(sourceID: "tag:ci", destID: "tag:db", port: 443).allowed, "tagged → tagged")
        XCTAssertFalse(ev.evaluate(sourceID: "amy@x.com", destID: "tag:db", port: 443).allowed)
        XCTAssertTrue(ev.evaluate(sourceID: "amy@x.com", destID: "amy@x.com", port: 22).allowed, "own devices")
        XCTAssertFalse(ev.evaluate(sourceID: "amy@x.com", destID: "bob@x.com", port: 22).allowed, "not someone else's")
        XCTAssertTrue(ev.evaluate(sourceID: "autogroup:admin", destID: "tag:db", port: 5432).allowed, "simulating the role")
        XCTAssertTrue(ev.sourceMatches(spec: "autogroup:member", sourceID: "autogroup:admin"), "an admin is a member")
        XCTAssertFalse(ev.evaluate(sourceID: "amy@x.com", destID: "tag:db", port: 5432).allowed, "roles unknown for real users")
        XCTAssertTrue(ev.evaluate(sourceID: "amy@x.com", destID: "1.1.1.1", port: 443).allowed, "internet")
        XCTAssertFalse(ev.evaluate(sourceID: "amy@x.com", destID: "10.0.0.5", port: 443).allowed, "not a private address")
        XCTAssertTrue(ev.evaluate(sourceID: "anyone@else.com", destID: "tag:pub", port: 80).allowed)
        XCTAssertTrue(lintPolicy(m).filter { $0.severity == .error }.isEmpty)
    }

    func testMisplacedAndUnknownAutogroupsAreErrors() {
        let titles = lintPolicy(model("""
        {"grants": [
          {"src": ["autogroup:self"], "dst": ["autogroup:shared"], "ip": ["*"]},
          {"src": ["autogroup:admins"], "dst": ["autogroup:nonroot"], "ip": ["*"]},
        ]}
        """)).map(\.title)
        XCTAssertEqual(titles.filter { $0 == "Misplaced autogroup" }.count, 3)
        XCTAssertEqual(titles.filter { $0 == "Unknown autogroup" }.count, 1)
    }

    func testACLProtoLimitsPortQueries() {
        let m = model(#"{"acls": [{"action": "accept", "src": ["*"], "proto": "icmp", "dst": ["*:*"]}]}"#)
        XCTAssertFalse(Evaluator(model: m).evaluate(sourceID: "a@x.com", destID: "1.2.3.4", port: 22).allowed)
    }

    func testIPv6RouteAutoApproval() {
        let m = model(#"{"autoApprovers": {"routes": {"fd00:1::/48": ["tag:router"]}}, "tagOwners": {"tag:router": []}}"#)
        let node = HeadscaleNode(id: "1", tags: ["tag:router"])
        XCTAssertTrue(Evaluator(model: m).autoApproves(route: "fd00:1:0:5::/64", node: node))
        XCTAssertFalse(Evaluator(model: m).autoApproves(route: "fd00:2::/64", node: node))
    }
}

final class ProblemLocationTests: XCTestCase {
    let text = """
    {
      "groups": {
        "group:empty": [],
      },
      "autoApprovers": {"routes": {
        "10.0.0.0/8": ["tag:gone"],
      }},
      "grants": [
        {"src": ["*"], "dst": ["tag:a"], "ip": ["22"]},
        {"src": ["group:nope"], "dst": ["tag:a"], "ip": ["bogus"]},
      ],
      "tagOwners": {"tag:a": []},
    }
    """

    func testLinesForPaths() throws {
        let tree = try HuJSONParser.parse(text)
        XCTAssertEqual(tree.line(at: "groups[group:empty]"), 3)
        XCTAssertEqual(tree.line(at: "autoApprovers.routes[10.0.0.0/8]"), 6)
        XCTAssertEqual(tree.line(at: "grants[1]"), 10)
        XCTAssertEqual(tree.line(at: "grants[1].ip"), 10)
        XCTAssertEqual(tree.line(at: "grants[7]"), 8, "falls back to the deepest part that exists")
        XCTAssertNil(tree.line(at: "nothing"))
    }

    func testEveryIssueHereHasALine() throws {
        let tree = try HuJSONParser.parse(text)
        let issues = lintPolicy(PolicyModel(tree: tree))
        XCTAssertFalse(issues.isEmpty)
        for issue in issues {
            XCTAssertNotNil(issue.path.flatMap(tree.line(at:)), issue.title)
        }
        XCTAssertEqual(issues.first { $0.title == "Undefined group" }.flatMap { $0.path.flatMap(tree.line(at:)) }, 10)
    }

    func testWindowsLineEndingsParse() throws {
        let tree = try HuJSONParser.parse("{\r\n  // note\r\n  \"groups\": {\"group:a\": []},\r\n}\r\n")
        XCTAssertEqual(tree.members?.first?.comments, ["note"])
        XCTAssertEqual(tree.line(at: "groups"), 3)
    }

    func testCommandLineReportsLines() throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("\(UUID().uuidString).hujson")
        defer { try? FileManager.default.removeItem(at: file) }
        try text.write(to: file, atomically: true, encoding: .utf8)
        var lines: [String] = []
        _ = runCommandLine(["lint", file.path]) { lines.append($0) }
        XCTAssertTrue(lines.contains { $0.hasPrefix("\(file.path):10: error: Undefined group") }, lines.joined(separator: "\n"))
    }
}

final class ConvertToGrantsTests: XCTestCase {
    func convert(_ text: String) throws -> (before: PolicyModel, after: PolicyModel, text: String) {
        var tree = try HuJSONParser.parse(text)
        let before = PolicyModel(tree: tree)
        convertACLsToGrants(&tree)
        let out = HuJSONSerializer.serialize(tree)
        return (before, PolicyModel(tree: try HuJSONParser.parse(out)), out)
    }

    func testConversionDetails() throws {
        let r = try convert("""
        {
          // Who reaches what
          "acls": [
            // Contractor
            // expires: 2030-01-01
            {"action": "accept", "src": ["a@x.com"], "proto": "tcp",
             "dst": ["tag:web:80,443", "host:nas:22", "tag:db:22", "[fd7a::1]:8080"], "srcPosture": ["posture:mac"]},
            {"action": "accept", "src": ["*"], "dst": ["autogroup:internet:*"]},
          ],
          "hosts": {"nas": "10.0.0.5"},
          "postures": {"posture:mac": ["node:os == 'macos'"]},
          "tagOwners": {"tag:web": [], "tag:db": []},
        }
        """)
        XCTAssertTrue(r.after.rules.isEmpty)
        XCTAssertFalse(r.text.contains("\"acls\""))
        XCTAssertTrue(r.text.contains("// Who reaches what\n  \"grants\""), "takes the ACLs' place")
        let g = r.after.grants
        XCTAssertEqual(g.map(\.dst), [["tag:web"], ["nas", "tag:db"], ["fd7a::1"], ["autogroup:internet"]])
        XCTAssertEqual(g.map(\.ip), [["tcp:80", "tcp:443"], ["tcp:22"], ["tcp:8080"], ["*"]])
        XCTAssertEqual(g[0].comments, ["Contractor"])
        XCTAssertEqual(g.prefix(3).map(\.expires), ["2030-01-01", "2030-01-01", "2030-01-01"])
        XCTAssertEqual(g[2].srcPosture, ["posture:mac"])
        XCTAssertEqual(entityAccessDifferences(r.before, r.after), [])
    }

    func testSamplePolicyConvertsWithoutAccessChanges() throws {
        let r = try convert(SamplePolicy.text)
        XCTAssertFalse(r.before.rules.isEmpty, "the sample has ACLs to convert")
        XCTAssertTrue(r.after.rules.isEmpty)
        XCTAssertEqual(entityAccessDifferences(r.before, r.after), [])
        XCTAssertTrue(lintPolicy(r.after).filter { $0.severity == .error }.isEmpty)
    }

    func testDifferencesAreReported() {
        let a = model(#"{"grants": [{"src": ["a@x.com"], "dst": ["tag:x"], "ip": ["22"]}], "tagOwners": {"tag:x": []}}"#)
        let b = model(#"{"grants": [{"src": ["a@x.com"], "dst": ["tag:x"], "ip": ["23"]}], "tagOwners": {"tag:x": []}}"#)
        XCTAssertFalse(entityAccessDifferences(a, b).isEmpty)
    }
}

@MainActor
final class EditorAssistTests: XCTestCase {
    let m = model("""
    {"groups": {"group:eng": ["amy@x.com"], "group:ops": []}, "tagOwners": {"tag:db": ["group:ops"]},
     "hosts": {"nas": "10.0.0.5"}, "postures": {"posture:mac": ["node:os == 'macos'"]}}
    """)

    func testVocabulary() {
        let v = EditorVocabulary(m)
        XCTAssertEqual(v.completions(for: "group:"), ["group:eng", "group:ops"])
        XCTAssertEqual(v.completions(for: "GROUP:E"), ["group:eng"])
        XCTAssertEqual(v.completions(for: "group:eng"), [], "nothing left to complete")
        XCTAssertTrue(v.completions(for: "autogroup:t").contains("autogroup:tagged"))
        XCTAssertEqual(v.definition(of: "tag:db:5432"), "tag:db — owners: group:ops")
        XCTAssertEqual(v.definition(of: "host:nas"), "nas = 10.0.0.5")
        XCTAssertEqual(v.definition(of: "amy@x.com"), "amy@x.com — in group:eng")
        XCTAssertNotNil(v.definition(of: "autogroup:self"))
    }

    func testTextViewCompletionRangeAndReveal() {
        let tv = PolicyTextView(frame: NSRect(x: 0, y: 0, width: 400, height: 300))
        tv.vocabulary = EditorVocabulary(m)
        tv.string = "{\n  \"src\": [\"group:e"
        tv.setSelectedRange(NSRange(location: (tv.string as NSString).length, length: 0))
        XCTAssertEqual((tv.string as NSString).substring(with: tv.rangeForUserCompletion), "group:e")
        XCTAssertTrue(tv.hasSuggestions)
        tv.string = "{\n  src group:e"
        tv.setSelectedRange(NSRange(location: (tv.string as NSString).length, length: 0))
        XCTAssertFalse(tv.hasSuggestions, "only inside strings")

        tv.string = "one\ntwo\nthree\n"
        tv.reveal(line: 2)
        XCTAssertEqual((tv.string as NSString).substring(with: tv.selectedRange()), "two")
    }
}

final class AuditLogTests: XCTestCase {
    override func setUp() {
        StubProtocol.requests = []
    }

    func testTailscalePolicyChanges() async throws {
        StubProtocol.handler = { _, _ in .init(body: Data("""
        {"logs": [
          {"eventTime": "2026-10-01T10:00:00.123Z", "origin": "ADMIN_CONSOLE",
           "actor": {"displayName": "Amy Lee", "loginName": "amy@x.com"}, "target": {"property": "ACL"}},
          {"eventTime": "2026-10-02T10:00:00Z", "origin": "CONFIG_API",
           "actor": {"loginName": "ci@x.com"}, "target": {"property": "ACL"}},
          {"eventTime": "2026-10-02T11:00:00Z", "target": {"property": "DNS_CONFIG"}}
        ]}
        """.utf8)) }
        let c = makeServer(kind: .tailscale, serverURL: "", tailnet: "-", credential: "tskey-api-x",
                           session: StubProtocol.session())!
        let changes = try await c.policyChanges(days: 30)
        XCTAssertEqual(changes?.map(\.who), ["ci@x.com", "Amy Lee"], "newest first, ACL changes only")
        XCTAssertEqual(changes?.map(\.origin), ["API", "admin console"])
        let url = StubProtocol.requests[0].request.url!
        XCTAssertEqual(url.path, "/api/v2/tailnet/-/logging/configuration")
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        XCTAssertEqual(items.first { $0.name == "event" }?.value, "TAILNET.UPDATE.ACL")
        XCTAssertNotNil(items.first { $0.name == "start" })

        StubProtocol.handler = { _, _ in .init(status: 403, body: Data(#"{"message": "forbidden"}"#.utf8)) }
        do {
            _ = try await c.policyChanges(days: 30)
            XCTFail("expected a 403")
        } catch let e as ServerError {
            XCTAssertEqual(e.status, 403)
        }
    }

    func testHeadscaleHasNoAuditLog() async throws {
        let c = makeServer(kind: .headscale, serverURL: "https://hs.example", tailnet: "", credential: "k",
                           session: StubProtocol.session())!
        let changes = try await c.policyChanges(days: 30)
        XCTAssertNil(changes)
        XCTAssertTrue(StubProtocol.requests.isEmpty)
    }
}

final class IPSetSyntaxTests: XCTestCase {
    let m = model("""
    {"hosts": {"db": "10.9.0.5"},
     "ipsets": {
       "ipset:mgmt": ["add 10.114.16.88/29", "add 172.16.50.0/24", "remove 172.16.50.7"],
       "ipset:plain": ["10.1.0.0/16", "10.2.0.1-10.2.0.9"],
       "ipset:nested": ["add ipset:plain", "add host:db", "remove 10.1.5.0/24"],
       "ipset:web": ["add autogroup:internet"],
       "ipset:loop": ["add ipset:loop2"], "ipset:loop2": ["add ipset:loop"],
     },
     "grants": [{"src": ["*"], "dst": ["ipset:mgmt", "ipset:nested", "ipset:web", "ipset:loop"], "ip": ["22"]}]}
    """)

    func testEntriesParseAndLintClean() {
        XCTAssertNotNil(IPSetEntry("add 10.114.16.88/29"))
        XCTAssertEqual(IPSetEntry("remove 172.16.50.7")?.remove, true)
        XCTAssertNotNil(IPSetEntry("10.2.0.1-10.2.0.9"))
        XCTAssertNil(IPSetEntry("delete 10.0.0.0/8"))
        XCTAssertNil(IPSetEntry("add nonsense"))
        let issues = lintPolicy(m)
        XCTAssertFalse(issues.contains { $0.title == "Invalid IP set entry" }, issues.map(\.detail).joined(separator: "\n"))
        XCTAssertFalse(issues.contains { $0.title == "Unused host" }, "host:db is used by an IP set")
        XCTAssertTrue(lintPolicy(model(#"{"ipsets": {"ipset:x": ["add host:nope"]}}"#)).contains { $0.title == "Unknown host" })
    }

    func testMembershipAppliesAddAndRemoveInOrder() {
        let ev = Evaluator(model: m)
        func reach(_ ip: String) -> Bool { ev.evaluate(sourceID: "a@x.com", destID: ip, port: 22).allowed }
        XCTAssertTrue(reach("10.114.16.90"))
        XCTAssertFalse(reach("10.114.16.96"))
        XCTAssertTrue(reach("172.16.50.6"))
        XCTAssertFalse(reach("172.16.50.7"), "removed")
        XCTAssertTrue(reach("10.2.0.5"), "range via nested set")
        XCTAssertFalse(reach("10.2.0.10"))
        XCTAssertTrue(reach("10.9.0.5"), "host via nested set")
        XCTAssertFalse(reach("10.1.5.9"), "removed from nested set")
        XCTAssertTrue(reach("10.1.6.9"))
        XCTAssertTrue(reach("8.8.8.8"), "autogroup:internet")
        XCTAssertFalse(ev.ipsetContains("ipset:loop", ip: "10.0.0.1"), "cycles end")
    }
}
