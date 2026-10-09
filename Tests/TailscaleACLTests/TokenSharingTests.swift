import XCTest
@testable import TailscaleACL
/// Regression: parallel posture requests raced on the OAuth token and crashed 1.26.0.
final class TokenSharingTests: XCTestCase {
    func testConcurrentRequestsShareOneToken() async throws {
        StubProtocol.requests = []
        StubProtocol.handler = { req, _ in
            req.url!.path.hasSuffix("oauth/token")
                ? .init(body: Data(#"{"access_token": "tok", "expires_in": 3600, "scope": "devices:core"}"#.utf8))
                : .init(body: Data(#"{"attributes": {"node:os": "linux"}}"#.utf8))
        }
        let c = makeServer(kind: .tailscale, serverURL: "", tailnet: "-", credential: "tskey-client-abc-secret", session: StubProtocol.session())!
        await withTaskGroup(of: Void.self) { group in
            for i in 0..<40 { group.addTask { _ = try? await c.postureAttributes(nodeID: "n\(i)") } }
        }
        XCTAssertEqual(StubProtocol.requests.filter { $0.request.url!.path.hasSuffix("oauth/token") }.count, 1)
    }
}
