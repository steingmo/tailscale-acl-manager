import XCTest
@testable import TailscaleACL

/// Answers requests from a handler and records them; no network involved.
final class StubProtocol: URLProtocol {
    struct Reply { var status = 200; var headers: [String: String] = [:]; var body = Data() }
    nonisolated(unsafe) static var handler: (URLRequest, Data) -> Reply = { _, _ in Reply() }
    nonisolated(unsafe) static var requests: [(request: URLRequest, body: Data)] = []

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        // URLSession moves httpBody into a stream before it reaches a URLProtocol.
        var body = request.httpBody ?? Data()
        if let stream = request.httpBodyStream {
            stream.open()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let n = stream.read(&buffer, maxLength: buffer.count)
                if n <= 0 { break }
                body.append(buffer, count: n)
            }
            stream.close()
        }
        Self.requests.append((request, body))
        let reply = Self.handler(request, body)
        let response = HTTPURLResponse(url: request.url!, statusCode: reply.status,
                                       httpVersion: "HTTP/1.1", headerFields: reply.headers)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: reply.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    static func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubProtocol.self]
        return URLSession(configuration: config)
    }
}

final class TailscaleClientTests: XCTestCase {
    override func setUp() {
        StubProtocol.requests = []
        StubProtocol.handler = { _, _ in .init() }
    }

    func client(_ credential: String = "tskey-api-abc", tailnet: String = "-") -> PolicyServer {
        makeServer(kind: .tailscale, serverURL: "", tailnet: tailnet, credential: credential,
                   session: StubProtocol.session())!
    }

    func testPullAndPushUseHuJSONAndIfMatch() async throws {
        let policy = "{\n  // keep me\n  \"groups\": {},\n}\n"
        StubProtocol.handler = { req, _ in
            req.httpMethod == "GET"
                ? .init(headers: ["ETag": "\"abc123\""], body: Data(policy.utf8))
                : .init(headers: ["ETag": "\"def456\""], body: Data(policy.utf8))
        }
        let c = client()
        let pulled = try await c.getPolicy()
        XCTAssertEqual(pulled, policy, "comments survive")
        let get = StubProtocol.requests[0].request
        XCTAssertEqual(get.url?.absoluteString, "https://api.tailscale.com/api/v2/tailnet/-/acl")
        XCTAssertEqual(get.value(forHTTPHeaderField: "Authorization"), "Bearer tskey-api-abc")
        XCTAssertEqual(get.value(forHTTPHeaderField: "Accept"), "application/hujson")

        try await c.setPolicy(pulled)
        let post = StubProtocol.requests[1]
        XCTAssertEqual(post.request.httpMethod, "POST")
        XCTAssertEqual(post.request.value(forHTTPHeaderField: "If-Match"), "\"abc123\"")
        XCTAssertEqual(post.request.value(forHTTPHeaderField: "Content-Type"), "application/hujson")
        XCTAssertEqual(String(decoding: post.body, as: UTF8.self), policy)
    }

    func testConcurrentChangeIsRefusedClearly() async throws {
        StubProtocol.handler = { req, _ in
            req.httpMethod == "GET" ? .init(headers: ["ETag": "\"old\""], body: Data("{}".utf8))
                : .init(status: 412, body: Data(#"{"message": "precondition failed"}"#.utf8))
        }
        let c = client()
        _ = try await c.getPolicy()
        do {
            try await c.setPolicy("{}")
            XCTFail("expected 412")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("changed on Tailscale"), error.localizedDescription)
        }
    }

    func testOAuthClientSecretIsExchangedOnce() async throws {
        StubProtocol.handler = { req, _ in
            req.url?.path.hasSuffix("/oauth/token") == true
                ? .init(body: Data(#"{"access_token": "short-lived", "expires_in": 3600}"#.utf8))
                : .init(body: Data("{}".utf8))
        }
        // Fake secret, assembled at runtime so secret scanners don't mistake it for a real key.
        let fakeSecret = "tskey-" + "client-" + "kTEST123-not-a-real-secret"
        let c = client(fakeSecret)
        _ = try await c.getPolicy()
        _ = try await c.getPolicy()
        let tokenRequests = StubProtocol.requests.filter { $0.request.url?.path.hasSuffix("/oauth/token") == true }
        XCTAssertEqual(tokenRequests.count, 1, "token is cached")
        let form = String(decoding: tokenRequests[0].body, as: UTF8.self)
        XCTAssertTrue(form.contains("client_id=kTEST123&"), form)
        XCTAssertTrue(form.contains("client_secret=" + fakeSecret), form)
        let api = StubProtocol.requests.last!.request
        XCTAssertEqual(api.value(forHTTPHeaderField: "Authorization"), "Bearer short-lived")
    }

    func testDevicesMapToPolicyIdentities() async throws {
        StubProtocol.handler = { _, _ in .init(body: Data("""
        {"devices": [
          {"id": "1", "nodeId": "nA", "hostname": "laptop", "user": "amelie@example.com",
           "addresses": ["100.64.0.1"], "connectedToControl": true},
          {"id": "2", "nodeId": "nB", "hostname": "router", "user": "amelie@example.com", "tags": ["tag:router"],
           "addresses": ["100.64.0.2"], "lastSeen": "2026-10-01T10:00:00Z",
           "advertisedRoutes": ["10.0.0.0/24"], "enabledRoutes": []}
        ]}
        """.utf8)) }
        let nodes = try await client().listNodes()
        XCTAssertEqual(StubProtocol.requests[0].request.url?.query, "fields=all")
        XCTAssertEqual(nodes.map(\.id), ["nA", "nB"])
        XCTAssertEqual(nodes[0].identities, ["amelie@example.com", "100.64.0.1"])
        XCTAssertEqual(nodes[0].statusText, "online")
        XCTAssertEqual(nodes[1].identities, ["tag:router", "100.64.0.2"]) // tagged: no user identity
        XCTAssertEqual(nodes[1].availableRoutes, ["10.0.0.0/24"])
        XCTAssertTrue(nodes[1].statusText.hasPrefix("last seen"))
    }

    func testValidateAndDeviceWrites() async throws {
        let c = client(tailnet: "example.com")
        StubProtocol.handler = { _, _ in .init() }
        let ok = try await c.validate("{}")
        XCTAssertEqual(ok?.passed, true)
        XCTAssertEqual(StubProtocol.requests[0].request.url?.absoluteString,
                       "https://api.tailscale.com/api/v2/tailnet/example.com/acl/validate")
        StubProtocol.handler = { _, _ in .init(body: Data(#"{"message": "test(s) failed", "data": [{"user": "a@x", "errors": ["want Drop, got Accept"]}]}"#.utf8)) }
        let failed = try await c.validate("{}")
        XCTAssertEqual(failed?.summary, "test(s) failed · a@x: want Drop, got Accept")
        XCTAssertEqual(failed?.failures.first?.user, "a@x")

        StubProtocol.handler = { _, _ in .init(body: Data("{}".utf8)) }
        try await c.setTags(nodeID: "nB", tags: ["tag:x"])
        try await c.setApprovedRoutes(nodeID: "nB", routes: ["10.0.0.0/24"])
        let writes = StubProtocol.requests.suffix(2)
        XCTAssertEqual(writes.map { $0.request.url!.path },
                       ["/api/v2/device/nB/tags", "/api/v2/device/nB/routes"])
        XCTAssertEqual(try JSONSerialization.jsonObject(with: writes.last!.body) as? [String: [String]],
                       ["routes": ["10.0.0.0/24"]])
    }

    func testDisplayNamesMatchHistoryFilter() {
        XCTAssertEqual(client().displayHost, serverName(kind: .tailscale, serverURL: "", tailnet: "-"))
        XCTAssertEqual(client(tailnet: "corp.com").displayHost, "Tailscale (corp.com)")
        let hs = makeServer(kind: .headscale, serverURL: "https://hs.example.com", tailnet: "", credential: "k")!
        XCTAssertEqual(hs.displayHost, "hs.example.com")
        XCTAssertNil(makeServer(kind: .tailscale, serverURL: "", tailnet: "-", credential: ""))
    }
}

final class HeadscaleClientTests: XCTestCase {
    override func setUp() { StubProtocol.requests = [] }

    func testPushAndErrors() async throws {
        let c = makeServer(kind: .headscale, serverURL: "https://hs.example.com", tailnet: "",
                           credential: "hskey", session: StubProtocol.session())!
        StubProtocol.handler = { _, _ in .init(body: Data("{}".utf8)) }
        try await c.setPolicy("{\"groups\": {}}")
        let put = StubProtocol.requests[0]
        XCTAssertEqual(put.request.url?.absoluteString, "https://hs.example.com/api/v1/policy")
        XCTAssertEqual(put.request.httpMethod, "PUT")
        XCTAssertEqual(try JSONSerialization.jsonObject(with: put.body) as? [String: String], ["policy": "{\"groups\": {}}"])
        let skipped = try await c.validate("{}")
        XCTAssertNil(skipped, "Headscale has no validate endpoint")

        StubProtocol.handler = { _, _ in .init(status: 401, body: Data("Unauthorized".utf8)) }
        do {
            _ = try await c.listNodes()
            XCTFail("expected 401")
        } catch {
            XCTAssertEqual(error.localizedDescription, "HTTP 401: Unauthorized")
        }
    }

    func testOldWorkspacesDefaultToHeadscale() throws {
        let ws = try JSONDecoder().decode(Workspace.self, from: Data(
            #"{"id": "\#(UUID().uuidString)", "name": "Old", "serverURL": "https://hs", "policy": "{}"}"#.utf8))
        XCTAssertEqual(ws.kind, .headscale)
    }
}
