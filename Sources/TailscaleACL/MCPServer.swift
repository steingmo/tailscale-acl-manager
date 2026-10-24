import Foundation
import Security

// AI tools over MCP (Model Context Protocol). The running app listens on a
// Unix socket in its data folder — only while Settings ▸ AI tools is on —
// and `tailscale-acl mcp` relays an AI app's stdio to it. Only this app's
// own signed binary may connect. The tools read and simulate; the only
// write is propose_change, which edits the editor (undoable, with a banner).
// Nothing reaches a server: pushing stays in the app, behind the push
// review and Touch ID.

enum MCPSocket {
    static let settingKey = "mcpEnabled"
    static let bundleID = "com.local.tailscale-acl-manager"
    static var path: String { appDataDirectory.appendingPathComponent("mcp.sock").path }

    /// The `tailscale-acl` command AI apps should run: Homebrew's link, or this binary.
    static var commandPath: String {
        ["/opt/homebrew/bin/tailscale-acl", "/usr/local/bin/tailscale-acl"]
            .first { FileManager.default.isExecutableFile(atPath: $0) } ?? (Bundle.main.executablePath ?? "tailscale-acl")
    }

    /// Is the process on the other end of `fd` this same app (by code signature)?
    static func peerIsThisApp(_ fd: Int32) -> Bool {
        var token = audit_token_t()
        var length = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length) == 0 else { return false }
        let tokenData = withUnsafeBytes(of: &token) { Data($0) }
        var peer: SecCode?, me: SecCode?, staticMe: SecStaticCode?, requirement: SecRequirement?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: tokenData] as CFDictionary, [], &peer) == errSecSuccess,
              let peer, SecCodeCopySelf([], &me) == errSecSuccess, let me,
              SecCodeCopyStaticCode(me, [], &staticMe) == errSecSuccess, let staticMe,
              SecCodeCopyDesignatedRequirement(staticMe, [], &requirement) == errSecSuccess else { return false }
        return SecCodeCheckValidity(peer, [], requirement) == errSecSuccess
    }
}

/// What the app tells the AI app about itself, and each tool.
@MainActor
struct MCPTools {
    /// nil while the app is locked.
    var store: PolicyStore?

    static let definitions: [[String: Any]] = [
        tool("get_policy", "The current workspace's tailnet policy (HuJSON) as in the editor, with the workspace and server."),
        tool("list_problems", "Problems and security findings in the policy, with line numbers and the one-click fixes the app offers."),
        tool("run_tests", "The policy's own tests (tests and sshTests) and which assertions fail."),
        tool("simulate_access", "Whether a source can reach a destination on a port, and through which rules — evaluated by the app's policy engine.",
             ["source": "User email, group:, tag:, device name, or IP",
              "destination": "Device name, host, IP, tag:, or ipset:",
              "port": "Port number, e.g. 443"], required: ["source", "destination", "port"], numbers: ["port"]),
        tool("who_can_reach", "Everyone (people and machine sources) who can reach a device, host, IP, IP set, or tag, with the rule, group, ports, and conditions.",
             ["target": "Device name, host, IP, ipset:, or tag:"], required: ["target"]),
        tool("list_devices", "Devices from the server (as last loaded in the app): user, tags, addresses, status, key expiry, and pass/fail for each posture."),
        tool("traffic_summary", "Real connections from Tailscale's flow logs, as loaded in the app's Traffic screen, with the rule that allows each.",
             ["filter": "Optional text to match device, user, IP, or port",
              "not_allowed_only": "Only connections no rule in the editor allows (true/false)",
              "limit": "Maximum rows (default 100)"], numbers: ["limit"], booleans: ["not_allowed_only"]),
        tool("rule_usage", "How much real traffic each rule carried in the loaded flow logs, and which rules carried none."),
        tool("propose_change", "Replace the policy in the editor with a full new HuJSON policy. It's only an undoable edit in the app: the user sees a banner to review or undo, and must push it themselves. Returns problems, failing tests, and how access changes.",
             ["policy": "The complete new policy (HuJSON)", "summary": "One sentence the user sees: what changed and why"],
             required: ["policy", "summary"]),
    ]

    private static func tool(_ name: String, _ description: String, _ properties: [String: String] = [:],
                             required: [String] = [], numbers: [String] = [], booleans: [String] = []) -> [String: Any] {
        var props: [String: Any] = [:]
        for (key, text) in properties {
            props[key] = ["type": numbers.contains(key) ? "integer" : booleans.contains(key) ? "boolean" : "string", "description": text]
        }
        return ["name": name, "description": description,
                "inputSchema": ["type": "object", "properties": props, "required": required] as [String: Any]]
    }

    /// The tool's answer as JSON text, or an error message.
    func call(_ name: String, _ args: [String: Any]) -> (text: String, isError: Bool) {
        guard let store else {
            return ("Tailscale ACL is locked. Unlock it (Touch ID) and try again.", true)
        }
        func json(_ value: Any) -> (String, Bool) {
            let data = (try? JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])) ?? Data()
            return (String(decoding: data, as: UTF8.self), false)
        }
        func string(_ key: String) -> String? { (args[key] as? String)?.trimmingCharacters(in: .whitespaces) }
        let m = store.model
        switch name {
        case "get_policy":
            return json(["workspace": store.currentWorkspace.name, "server": store.serverClient() == nil ? "none" : store.serverDisplayName,
                         "valid": store.isValid, "policy": store.text])
        case "list_problems":
            return json(store.lintIssues.map { i -> [String: Any] in
                ["severity": i.severity == .error ? "error" : "warning", "security": i.security, "title": i.title,
                 "detail": i.detail, "line": store.line(of: i) as Any, "fixes": i.fixes.map(\.label)]
            })
        case "run_tests":
            let failing = store.testResults.filter { !$0.passed }.map { t -> [String: Any] in
                ["test": t.testIndex, "src": t.src,
                 "failing": t.assertions.filter { !$0.passed }.map { "\($0.kind == .accept ? "should reach" : "should not reach") \($0.dst)" }]
            }
            let sshFailing = store.sshTestResults.filter { !$0.passed }.map { ["sshTest": $0.testIndex, "src": $0.src] as [String: Any] }
            return json(["tests": store.testResults.count, "sshTests": store.sshTestResults.count, "failing": failing, "sshFailing": sshFailing])
        case "simulate_access":
            guard let src = string("source"), let dst = string("destination"),
                  let port = (args["port"] as? Int) ?? string("port").flatMap(Int.init) else {
                return ("source, destination, and port are required.", true)
            }
            let ids = { (name: String) in store.headscaleNodes.first { $0.displayName == name || $0.name == name }?.identities ?? [name] }
            let source = store.headscaleNodes.first { $0.displayName == src || $0.name == src }
            let ev = source?.evaluator(m) ?? Evaluator(model: m)
            let result = ev.evaluate(sourceIDs: ids(src), destIDs: ids(dst), port: port)
            let rules = ruleSummaries(m, sourceIDs: nil)
            var out: [String: Any] = [
                "allowed": result.allowed,
                "conditional_on_posture": result.conditional ? result.postures : [],
                "rules": result.matches.map { match -> [String: Any] in
                    let section = match.kind == .grant ? "grants" : "acls"
                    return ["rule": rules.first { $0.section == section && $0.index == match.ruleIndex }?.name ?? "\(section)[\(match.ruleIndex)]",
                            "path": "\(section)[\(match.ruleIndex)]", "source": match.srcSpec, "destination": match.dstSpec,
                            "ports": match.ipSpec ?? DestSpec(match.dstSpec).ports, "via": match.via]
                },
            ]
            if !result.allowed { out["why_not"] = explainFailure(m, src: src, entry: "\(dst):\(port)", expectAllowed: true).summary }
            return json(out)
        case "who_can_reach":
            guard let target = string("target") else { return ("target is required.", true) }
            return json(whoCanReach(target, m, nodes: store.headscaleNodes, accounts: store.serverAccounts).map { e -> [String: Any] in
                ["who": e.who, "kind": e.isPerson ? "person" : "machine",
                 "access": e.access.map { ["rule": $0.rule, "through": $0.through, "ports": $0.ports, "conditions": $0.notes] }]
            })
        case "list_devices":
            guard !store.headscaleNodes.isEmpty else { return ("No devices loaded: connect the workspace to its server in the app.", true) }
            return json(store.headscaleNodes.map { n -> [String: Any] in
                var d: [String: Any] = ["name": n.displayName, "user": n.user?.email ?? n.user?.name ?? "", "tags": n.allTags,
                                        "addresses": n.ipAddresses ?? [], "status": n.statusText, "os": n.os ?? ""]
                if let days = n.keyDaysLeft() { d["key_expires_in_days"] = days } else { d["key_expires"] = "never" }
                if !m.postureOrder.isEmpty {
                    d["postures"] = Dictionary(uniqueKeysWithValues: m.postureOrder.map { p in
                        (p, n.meets(m.postures[p] ?? []).map { $0 ? "pass" : "fail" } ?? "unknown")
                    })
                }
                return d
            })
        case "traffic_summary":
            guard let traffic = store.traffic else {
                return ("No flow logs loaded. Ask the user to load them on the app's Traffic screen.", true)
            }
            let byIP = nodesByAddress(store.headscaleNodes)
            let q = (string("filter") ?? "").lowercased()
            let notAllowedOnly = args["not_allowed_only"] as? Bool ?? false
            let blocked = notAllowedOnly ? trafficNotAllowed(traffic.connections, m, nodes: store.headscaleNodes) : []
            let rules = ruleSummaries(m, sourceIDs: nil)
            let rows = traffic.connections.filter { c in
                (!notAllowedOnly || blocked.contains(c.id)) && (q.isEmpty
                    || [c.client, c.server, String(c.port), trafficName(c.client, nodes: byIP), trafficName(c.server, nodes: byIP),
                        byIP[c.client]?.policyName ?? "", byIP[c.server]?.policyName ?? ""].contains { $0.lowercased().contains(q) })
            }
            let limit = (args["limit"] as? Int) ?? 100
            return json(["period": "\(traffic.start.formatted()) – \(traffic.end.formatted())", "matching": rows.count,
                         "connections": rows.prefix(limit).map { c -> [String: Any] in
                let names = rulesAllowing(c, m, nodes: byIP).compactMap { match in
                    rules.first { $0.section == (match.kind == .grant ? "grants" : "acls") && $0.index == match.ruleIndex }?.name
                }.uniqued()
                let verdict: Any = !names.isEmpty ? names
                    : isExitNodeDNS(c, m, nodes: byIP, allNodes: store.headscaleNodes) ? "Tailscale's own exit-node DNS (peer API)"
                    : c.isPortTraffic ? "no rule in the editor allows this" : "not port traffic"
                return ["client": trafficName(c.client, nodes: byIP), "client_user": byIP[c.client]?.policyName ?? c.client,
                        "server": trafficName(c.server, nodes: byIP), "server_identity": byIP[c.server]?.policyName ?? c.server,
                        "protocol": c.protoName, "port": c.port, "kind": c.kind.rawValue, "connections": c.connections,
                        "bytes": c.bytes, "allowed_by": verdict]
            }])
        case "rule_usage":
            guard let traffic = store.traffic else {
                return ("No flow logs loaded. Ask the user to load them on the app's Traffic screen.", true)
            }
            let usage = ruleUsage(traffic.connections, m, nodes: store.headscaleNodes)
            return json(ruleSummaries(m, sourceIDs: nil).filter { $0.kind != .ssh }.map { r -> [String: Any] in
                let u = usage["\(r.kind == .grant ? RuleMatch.Kind.grant : .acl)-\(r.index)"]
                return ["rule": r.name, "path": "\(r.section)[\(r.index)]", "connections": u?.connections ?? 0,
                        "ports_used": u?.ports ?? [:]]
            })
        case "propose_change":
            guard let policy = args["policy"] as? String, let summary = string("summary"), !summary.isEmpty else {
                return ("policy and summary are required.", true)
            }
            let tree: JSON
            do { tree = try HuJSONParser.parse(policy) } catch {
                return ("The policy doesn't parse: \(error.localizedDescription). Nothing was changed.", true)
            }
            var new = PolicyModel(tree: tree)
            new.userAutogroups = m.userAutogroups
            let ev = Evaluator(model: new)
            let failing = ev.runTests().filter { !$0.passed }.count + ev.runSSHTests().filter { !$0.passed }.count
            let differences = entityAccessDifferences(m, new, limit: 30)
            store.proposeAIChange(policy, summary: summary)
            return json(["applied_in_editor": true,
                         "note": "Only the editor changed. The user reviews it (banner: Show changes / Undo) and pushes it themselves; nothing changed on the server.",
                         "errors": lintPolicy(new).filter { $0.severity == .error }.map { "\($0.title): \($0.detail)" },
                         "failing_tests": failing, "access_differences": differences])
        default:
            return ("Unknown tool \(name).", true)
        }
    }
}

/// JSON-RPC 2.0 for MCP: initialize, tools/list, tools/call, ping.
enum MCPProtocol {
    static let versions = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]

    /// The reply to one message, or nil for notifications.
    @MainActor
    static func reply(to message: [String: Any], tools: MCPTools) -> [String: Any]? {
        guard let id = message["id"] else { return nil }   // notifications get no reply
        let params = message["params"] as? [String: Any] ?? [:]
        func result(_ r: Any) -> [String: Any] { ["jsonrpc": "2.0", "id": id, "result": r] }
        switch message["method"] as? String ?? "" {
        case "initialize":
            let asked = params["protocolVersion"] as? String ?? versions[0]
            return result([
                "protocolVersion": versions.contains(asked) ? asked : versions[0],
                "capabilities": ["tools": [String: Any]()],
                "serverInfo": ["name": "tailscale-acl", "version": Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "dev"],
                "instructions": "Tools for the tailnet policy open in the Tailscale ACL app. Prefer simulate_access and who_can_reach over reading the policy yourself; they use the app's exact policy engine. propose_change only edits the user's editor — the user reviews and pushes.",
            ] as [String: Any])
        case "ping":
            return result([String: Any]())
        case "tools/list":
            return result(["tools": MCPTools.definitions])
        case "tools/call":
            let (text, isError) = tools.call(params["name"] as? String ?? "", params["arguments"] as? [String: Any] ?? [:])
            return result(["content": [["type": "text", "text": text]], "isError": isError] as [String: Any])
        default:
            return ["jsonrpc": "2.0", "id": id, "error": ["code": -32601, "message": "Method not found"]]
        }
    }
}

/// What has arrived on `fd`, waiting for at least one byte; nil at the end or
/// on an error. (FileHandle.availableData raises on a reset socket, and
/// read(upToCount:) waits for the whole count.)
func readSome(_ fd: Int32) -> Data? {
    var buffer = [UInt8](repeating: 0, count: 65_536)
    while true {
        let n = read(fd, &buffer, buffer.count)
        if n > 0 { return Data(buffer[0..<n]) }
        if n < 0 && errno == EINTR { continue }
        return nil
    }
}

/// Writes all of `data`; false if the other end is gone.
func writeAll(_ fd: Int32, _ data: Data) -> Bool {
    data.withUnsafeBytes { raw in
        var offset = 0
        while offset < raw.count {
            let n = write(fd, raw.baseAddress! + offset, raw.count - offset)
            if n > 0 { offset += n } else if n < 0 && errno == EINTR { continue } else { return false }
        }
        return true
    }
}

/// The Unix socket the `tailscale-acl mcp` relay connects to. Messages are
/// newline-delimited JSON, like MCP's stdio transport.
final class MCPSocketServer {
    private let path: String
    private let store: @MainActor () -> PolicyStore?
    private let checkPeer: (Int32) -> Bool
    private var listenFD: Int32 = -1
    private var acceptSource: DispatchSourceRead?
    private let queue = DispatchQueue(label: "mcp-socket")

    init(path: String = MCPSocket.path, checkPeer: @escaping (Int32) -> Bool = MCPSocket.peerIsThisApp,
         store: @escaping @MainActor () -> PolicyStore?) {
        self.path = path
        self.checkPeer = checkPeer
        self.store = store
    }

    func start() throws {
        // A client hanging up mid-reply must be an error, not SIGPIPE ending the app.
        signal(SIGPIPE, SIG_IGN)
        try FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.EIO) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { close(fd); throw POSIXError(.ENAMETOOLONG) }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in raw.copyBytes(from: bytes) }
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard bound == 0, chmod(path, 0o600) == 0, listen(fd, 4) == 0 else { close(fd); throw POSIXError(.EADDRINUSE) }
        listenFD = fd
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [weak self] in self?.acceptOne() }
        source.setCancelHandler { close(fd) }
        source.resume()
        acceptSource = source
    }

    func stop() {
        acceptSource?.cancel()
        acceptSource = nil
        unlink(path)
    }

    deinit { stop() }

    private func acceptOne() {
        let client = accept(listenFD, nil, nil)
        guard client >= 0 else { return }
        guard checkPeer(client) else { close(client); return }
        // A client that disconnects mid-reply must not take the app down with
        // SIGPIPE; reads and writes below use the throwing APIs for the same reason
        // (availableData and write(_:) raise exceptions on a closed socket).
        var on: Int32 = 1
        setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        let store = self.store
        Thread {
            defer { close(client) }
            var buffer = Data()
            while let chunk = readSome(client) {
                buffer.append(chunk)
                while let newline = buffer.firstIndex(of: 0x0A) {
                    let line = buffer[buffer.startIndex..<newline]
                    buffer = Data(buffer[buffer.index(after: newline)...])
                    guard !line.isEmpty, let message = try? JSONSerialization.jsonObject(with: line) as? [String: Any] else { continue }
                    let semaphore = DispatchSemaphore(value: 0)
                    var reply: [String: Any]?
                    DispatchQueue.main.async {
                        MainActor.assumeIsolated { reply = MCPProtocol.reply(to: message, tools: MCPTools(store: store())) }
                        semaphore.signal()
                    }
                    semaphore.wait()
                    if let reply, let data = try? JSONSerialization.data(withJSONObject: reply, options: [.withoutEscapingSlashes]) {
                        guard writeAll(client, data + Data([0x0A])) else { return }
                    }
                }
            }
        }.start()
    }
}

/// `tailscale-acl mcp`: relays stdio to the running app (starting it if
/// needed), so AI apps can use it as an MCP server.
func runMCPBridge(path: String = MCPSocket.path) -> Int32 {
    signal(SIGPIPE, SIG_IGN)   // the AI app closing its end ends the relay, quietly
    func connectSocket() -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return -1 }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in raw.copyBytes(from: Array(path.utf8).prefix(raw.count - 1)) }
        let ok = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        } == 0
        if !ok { close(fd) }
        return ok ? fd : -1
    }
    var fd = connectSocket()
    if fd < 0 {
        // Start the app in the background and give it a moment.
        let open = Process()
        open.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        open.arguments = ["-g", "-b", MCPSocket.bundleID]
        try? open.run()
        open.waitUntilExit()
        for _ in 0..<40 where fd < 0 {
            Thread.sleep(forTimeInterval: 0.5)
            fd = connectSocket()
        }
    }
    guard fd >= 0 else {
        FileHandle.standardError.write(Data("tailscale-acl mcp: can't reach Tailscale ACL. Open the app and turn on Settings ▸ AI tools (MCP).\n".utf8))
        return 1
    }
    var on: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
    Thread {
        while let data = readSome(STDIN_FILENO), writeAll(fd, data) {}
        shutdown(fd, SHUT_WR)
    }.start()
    while let data = readSome(fd), writeAll(STDOUT_FILENO, data) {}
    return 0
}
