import XCTest
@testable import TailscaleACL

@MainActor
final class MCPTests: XCTestCase {
    var dir: URL!

    override func setUp() async throws {
        dir = URL(fileURLWithPath: "/tmp").appendingPathComponent("mcp-\(UUID().uuidString.prefix(8))")
        setenv("TAILSCALE_ACL_DATA_DIR", dir.path, 1)
        let ws = Workspace(name: "Office", serverURL: "", policy: """
        {"groups": {"group:eng": ["amy@x.com"]},
         "tagOwners": {"tag:db": []},
         "hosts": {"db1": "10.0.0.5", "old": "10.0.0.9"},
         "grants": [
           // Engineers to the database
           {"src": ["group:eng"], "dst": ["db1"], "ip": ["tcp:5432"]},
         ],
         "tests": [{"src": "amy@x.com", "accept": ["db1:5432"]}]}
        """)
        try WorkspaceStore.save([ws])
        UserDefaults.standard.set(ws.id.uuidString, forKey: "currentWorkspaceID")
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        unsetenv("TAILSCALE_ACL_DATA_DIR")
    }

    func call(_ store: PolicyStore?, _ name: String, _ args: [String: Any] = [:]) -> [String: Any] {
        let reply = MCPProtocol.reply(to: ["jsonrpc": "2.0", "id": 7, "method": "tools/call",
                                           "params": ["name": name, "arguments": args]], tools: MCPTools(store: store))!
        return reply["result"] as! [String: Any]
    }

    func text(_ result: [String: Any]) -> String {
        ((result["content"] as! [[String: Any]])[0]["text"] as! String)
    }

    func testHandshakeAndToolList() {
        let tools = MCPTools(store: nil)
        let initReply = MCPProtocol.reply(to: ["jsonrpc": "2.0", "id": 1, "method": "initialize",
                                               "params": ["protocolVersion": "2025-06-18"]], tools: tools)!
        let result = initReply["result"] as! [String: Any]
        XCTAssertEqual(result["protocolVersion"] as? String, "2025-06-18")
        XCTAssertNotNil((result["capabilities"] as? [String: Any])?["tools"])
        XCTAssertNil(MCPProtocol.reply(to: ["jsonrpc": "2.0", "method": "notifications/initialized"], tools: tools), "no reply to notifications")
        let list = (MCPProtocol.reply(to: ["jsonrpc": "2.0", "id": 2, "method": "tools/list"], tools: tools)!["result"] as! [String: Any])["tools"] as! [[String: Any]]
        XCTAssertEqual(Set(list.map { $0["name"] as! String }), ["get_policy", "list_problems", "run_tests", "simulate_access", "who_can_reach",
                                                                "list_devices", "traffic_summary", "rule_usage", "propose_change",
                                                                "posture_report", "access_review_status", "apply_fix", "history"])
        let prompts = (MCPProtocol.reply(to: ["jsonrpc": "2.0", "id": 4, "method": "prompts/list"], tools: tools)!["result"] as! [String: Any])["prompts"] as! [[String: Any]]
        XCTAssertEqual(prompts.map { $0["name"] as! String }, ["security-review", "offboard-person", "unused-access"])
        let offboard = MCPProtocol.reply(to: ["jsonrpc": "2.0", "id": 5, "method": "prompts/get",
                                              "params": ["name": "offboard-person", "arguments": ["person": "bob@x.com"]]], tools: tools)!
        let message = (((offboard["result"] as! [String: Any])["messages"] as! [[String: Any]])[0]["content"] as! [String: Any])["text"] as! String
        XCTAssertTrue(message.hasPrefix("Offboard bob@x.com from my tailnet policy"))
        XCTAssertTrue(MCPProtocol.localReply(to: ["jsonrpc": "2.0", "id": 6, "method": "prompts/list"]).handled, "answered without the app")
        let unknown = MCPProtocol.reply(to: ["jsonrpc": "2.0", "id": 3, "method": "resources/list"], tools: tools)!
        XCTAssertEqual((unknown["error"] as? [String: Any])?["code"] as? Int, -32601)
        XCTAssertEqual(call(nil, "get_policy")["isError"] as? Bool, true, "locked: no data")
        XCTAssertTrue(text(call(nil, "get_policy")).contains("locked"))
    }

    func testToolsUseThePolicyEngine() throws {
        let store = PolicyStore()
        let sim = try JSONSerialization.jsonObject(with: Data(text(call(store, "simulate_access",
            ["source": "amy@x.com", "destination": "db1", "port": 5432])).utf8)) as! [String: Any]
        XCTAssertEqual(sim["allowed"] as? Bool, true)
        XCTAssertEqual((sim["rules"] as? [[String: Any]])?.first?["rule"] as? String, "Engineers to the database")
        let denied = try JSONSerialization.jsonObject(with: Data(text(call(store, "simulate_access",
            ["source": "eve@x.com", "destination": "db1", "port": 5432])).utf8)) as! [String: Any]
        XCTAssertEqual(denied["allowed"] as? Bool, false)
        XCTAssertNotNil(denied["why_not"])
        XCTAssertTrue(text(call(store, "who_can_reach", ["target": "db1"])).contains("amy@x.com"))
        XCTAssertTrue(text(call(store, "run_tests")).contains("\"failing\" : ["))
        XCTAssertEqual(call(store, "traffic_summary")["isError"] as? Bool, true, "no flow logs loaded")
    }

    func testProposeChangeOnlyEditsTheEditor() throws {
        let store = PolicyStore()
        let before = store.text
        let bad = call(store, "propose_change", ["policy": "{ nope", "summary": "x"])
        XCTAssertEqual(bad["isError"] as? Bool, true)
        XCTAssertEqual(store.text, before, "an unparsable proposal changes nothing")

        let newPolicy = before.replacingOccurrences(of: "\"tcp:5432\"", with: "\"tcp:5433\"")
        let result = try JSONSerialization.jsonObject(with: Data(text(call(store, "propose_change",
            ["policy": newPolicy, "summary": "Move the database port"])).utf8)) as! [String: Any]
        XCTAssertEqual(result["applied_in_editor"] as? Bool, true)
        XCTAssertEqual(result["failing_tests"] as? Int, 1, "the policy's own test catches it")
        XCTAssertFalse((result["access_differences"] as? [String] ?? []).isEmpty)
        XCTAssertEqual(store.text, newPolicy)
        XCTAssertEqual(store.aiProposal?.summary, "Move the database port")
        XCTAssertEqual(store.aiProposal?.before, before)
        XCTAssertEqual(SnapshotStore.load(store.currentWorkspaceID).first?.reason, "AI tool change")
    }

    func testFixesHistoryReviewAndPosture() throws {
        let store = PolicyStore()
        let problems = try JSONSerialization.jsonObject(with: Data(text(call(store, "list_problems")).utf8)) as! [[String: Any]]
        let unused = try XCTUnwrap(problems.first { ($0["title"] as? String) == "Unused host" })
        let before = store.text
        let fixed = try JSONSerialization.jsonObject(with: Data(text(call(store, "apply_fix", ["problem_id": unused["id"]!])).utf8)) as! [String: Any]
        XCTAssertEqual(fixed["fix"] as? String, "Delete old")
        XCTAssertNil(store.model.hosts["old"])
        XCTAssertEqual(store.aiProposal?.before, before, "the banner can undo it")
        XCTAssertEqual(call(store, "apply_fix", ["problem_id": unused["id"]!])["isError"] as? Bool, true, "stale ids are refused")

        let history = try JSONSerialization.jsonObject(with: Data(text(call(store, "history")).utf8)) as! [String: Any]
        let snapshots = history["snapshots"] as! [[String: Any]]
        XCTAssertTrue(snapshots.contains { ($0["reason"] as? String) == "opened" })
        let opened = snapshots.first { ($0["reason"] as? String) == "opened" }!["id"] as! String
        let old = try JSONSerialization.jsonObject(with: Data(text(call(store, "history", ["snapshot": opened])).utf8)) as! [String: Any]
        XCTAssertTrue((old["policy"] as? String ?? "").contains("\"old\""))

        let review = try JSONSerialization.jsonObject(with: Data(text(call(store, "access_review_status")).utf8)) as! [String: Any]
        XCTAssertEqual(review["started"] as? Bool, false)
        XCTAssertEqual(call(store, "posture_report")["isError"] as? Bool, true, "no postures in this policy")
    }

    func testSocketRoundTripAndPeerCheck() async throws {
        let store = PolicyStore()
        let path = dir.appendingPathComponent("mcp.sock").path
        let server = MCPSocketServer(path: path) { store }   // checks the peer is this same signed binary
        try server.start()
        defer { server.stop() }
        let reply = try await Task.detached { try Self.roundTrip(path, #"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#) }.value
        XCTAssertTrue(reply.contains("simulate_access"), reply)
        XCTAssertEqual(Int(try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as! NSNumber), 0o600)

        let strict = MCPSocketServer(path: path + "2", checkPeer: { _ in false }) { store }
        try strict.start()
        defer { strict.stop() }
        let refused = try await Task.detached { try Self.roundTrip(path + "2", #"{"jsonrpc":"2.0","id":1,"method":"ping"}"#) }.value
        XCTAssertEqual(refused, "", "a process that isn't this app is disconnected")

        // A client that hangs up before the reply doesn't crash the app.
        try await Task.detached {
            for _ in 0..<20 {
                let fd = socket(AF_UNIX, SOCK_STREAM, 0)
                var on: Int32 = 1
                setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
                var addr = sockaddr_un()
                addr.sun_family = sa_family_t(AF_UNIX)
                withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: Array(path.utf8)) }
                _ = withUnsafePointer(to: &addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
                }
                let msg = Array(#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.utf8) + [0x0A]
                _ = msg.withUnsafeBytes { send(fd, $0.baseAddress, $0.count, 0) }
                close(fd)
            }
        }.value
        try await Task.sleep(nanoseconds: 500_000_000)
        let still = try await Task.detached { try Self.roundTrip(path, #"{"jsonrpc":"2.0","id":9,"method":"ping"}"#) }.value
        XCTAssertTrue(still.contains("\"id\":9"), "still answering after clients hung up")
    }

    nonisolated static func roundTrip(_ path: String, _ line: String) throws -> String {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: Array(path.utf8)) }
        let ok = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard ok == 0 else { throw POSIXError(.ECONNREFUSED) }
        defer { close(fd) }
        guard writeAll(fd, Data((line + "\n").utf8)) else { return "" }   // refused: the server hung up
        var out = Data()
        while !out.contains(0x0A), let chunk = readSome(fd) {
            out.append(chunk)
        }
        return String(decoding: out, as: UTF8.self)
    }
}
