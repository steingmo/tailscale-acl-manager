import XCTest
@testable import TailscaleACL

final class SecurityTests: XCTestCase {
    var dir: URL!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        setenv("TAILSCALE_ACL_DATA_DIR", dir.path, 1)
        StubProtocol.requests = []
        StubProtocol.handler = { _, _ in .init(body: Data("{}".utf8)) }
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        unsetenv("TAILSCALE_ACL_DATA_DIR")
    }

    func testUnencryptedRemoteServers() {
        XCTAssertTrue(isUnencryptedRemote("http://headscale.lan:8080"))
        XCTAssertTrue(isUnencryptedRemote("http://10.0.0.5"))
        XCTAssertFalse(isUnencryptedRemote("https://headscale.example.com"))
        XCTAssertFalse(isUnencryptedRemote("http://localhost:8080"))
        XCTAssertFalse(isUnencryptedRemote("http://127.0.0.1:8080"))
    }

    func testScopeAdvice() {
        let full = CredentialInfo(kind: "Personal API access token", scopes: ["all"])
        XCTAssertTrue(full.isFullAccess)
        XCTAssertEqual(full.missingFeatures, [])
        let narrow = CredentialInfo(kind: "OAuth client", scopes: ["policy_file", "devices:core", "users"])
        XCTAssertFalse(narrow.isFullAccess)
        XCTAssertFalse(narrow.missingFeatures.contains("listing users and roles"), "users covers users:read")
        XCTAssertTrue(narrow.missingFeatures.contains("traffic (flow logs)"))
        XCTAssertTrue(narrow.missingFeatures.contains("auth keys"))
    }

    func testTailscaleCredentialInfo() async throws {
        StubProtocol.handler = { req, _ in
            req.url!.path.hasSuffix("oauth/token")
                ? .init(body: Data(#"{"access_token": "t", "expires_in": 3600, "scope": "policy_file devices:core"}"#.utf8))
                : .init(body: Data(#"{"id": "kABC", "expires": "2026-12-31T10:00:00Z"}"#.utf8))
        }
        let oauth = makeServer(kind: .tailscale, serverURL: "", tailnet: "-",
                               credential: "tskey-" + "client-" + "kTEST-not-a-real-secret", session: StubProtocol.session())!
        let oauthInfo = try await oauth.credentialInfo()
        XCTAssertEqual(oauthInfo?.scopes, ["policy_file", "devices:core"])
        XCTAssertNil(oauthInfo?.expires)

        StubProtocol.requests = []
        let token = makeServer(kind: .tailscale, serverURL: "", tailnet: "-",
                               credential: "tskey-" + "api-" + "kABC-not-a-real-secret", session: StubProtocol.session())!
        let tokenInfo = try await token.credentialInfo()
        XCTAssertTrue(tokenInfo?.isFullAccess == true)
        XCTAssertEqual(tokenInfo?.expires, ISO8601DateFormatter().date(from: "2026-12-31T10:00:00Z"))
        XCTAssertEqual(StubProtocol.requests.last?.request.url?.path, "/api/v2/tailnet/-/keys/kABC")
    }

    func testHeadscaleCredentialExpiryByPrefix() async throws {
        StubProtocol.handler = { _, _ in .init(body: Data("""
        {"apiKeys": [{"id": "1", "prefix": "aaaaaaaaaaaa", "expiration": "2027-01-01T00:00:00Z"},
                     {"id": "2", "prefix": "oldkey1", "expiration": "2026-11-01T00:00:00Z"}]}
        """.utf8)) }
        let new = makeServer(kind: .headscale, serverURL: "https://hs.example", tailnet: "",
                             credential: "hskey-" + "api-" + "aaaaaaaaaaaa-secretpart", session: StubProtocol.session())!
        let newInfo = try await new.credentialInfo()
        XCTAssertEqual(newInfo?.expires, ISO8601DateFormatter().date(from: "2027-01-01T00:00:00Z"))
        let old = makeServer(kind: .headscale, serverURL: "https://hs.example", tailnet: "",
                             credential: "oldkey1.secretpart", session: StubProtocol.session())!
        let oldInfo = try await old.credentialInfo()
        XCTAssertEqual(oldInfo?.expires, ISO8601DateFormatter().date(from: "2026-11-01T00:00:00Z"))
    }

    func testGuardedServerLogsChangesNotReads() async throws {
        let inner = makeServer(kind: .headscale, serverURL: "https://hs.example", tailnet: "", credential: "k",
                               session: StubProtocol.session())!
        let guarded = GuardedServer(inner, workspace: "Office", requireAuth: false)
        StubProtocol.handler = { _, _ in .init(body: Data(#"{"nodes": []}"#.utf8)) }
        _ = try await guarded.listNodes()
        try await guarded.expireNode(nodeID: "7")
        StubProtocol.handler = { _, _ in .init(status: 500, body: Data(#"{"message": "boom"}"#.utf8)) }
        do {
            try await guarded.deleteNode(nodeID: "8")
            XCTFail("expected failure")
        } catch {}

        let entries = ActivityLog.recent()
        XCTAssertEqual(entries.map(\.action), ["Delete a device", "Expire a device key"], "newest first; reads aren't logged")
        XCTAssertEqual(entries[1].workspace, "Office")
        XCTAssertEqual(entries[1].server, "hs.example")
        XCTAssertNil(entries[1].error)
        XCTAssertTrue(entries[0].error?.contains("boom") == true)
        XCTAssertEqual(ActivityLog.recent(server: "other").count, 0)
        let raw = try String(contentsOf: ActivityLog.fileURL, encoding: .utf8)
        XCTAssertFalse(raw.contains("Bearer"), "no secrets in the log")
    }
}
