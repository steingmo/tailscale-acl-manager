import XCTest
@testable import TailscaleACL
@MainActor
/// Regression: loading posture attributes aborted release builds (1.26.0–1.26.1) when a
/// request outlived its task group. Reproduces with `swift test -c release -Xswiftc -enable-testing`.
final class PostureLoadingTests: XCTestCase {
    func testManyLoads() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        setenv("TAILSCALE_ACL_DATA_DIR", dir.path, 1)
        defer { try? FileManager.default.removeItem(at: dir); unsetenv("TAILSCALE_ACL_DATA_DIR") }
        let ws = Workspace(name: "T", serverURL: "", policy: #"{"ipsets": {"ipset:a": ["add 10.0.0.0/8", "remove 10.1.0.0/16"]}, "grants": [{"src": ["*"], "dst": ["ipset:a"], "ip": ["*"]}]}"#)
        try WorkspaceStore.save([ws])
        UserDefaults.standard.set(ws.id.uuidString, forKey: "currentWorkspaceID")
        let store = PolicyStore()
        StubProtocol.handler = { req, _ in
            usleep(UInt32.random(in: 0...3000))
            return req.url!.path.hasSuffix("oauth/token")
                ? .init(body: Data(#"{"access_token": "t", "expires_in": 3600}"#.utf8))
                : .init(body: Data(#"{"attributes": {"node:os": "linux", "huntress:firewallStatus": "Enabled"}}"#.utf8))
        }
        let nodes = (0..<60).map { HeadscaleNode(id: "n\($0)", name: "d\($0)", ipAddresses: ["100.64.0.\($0)"]) }
        store.headscaleNodes = nodes
        for _ in 0..<20 {
            StubProtocol.requests = []
            let c = makeServer(kind: .tailscale, serverURL: "", tailnet: "-", credential: ["tskey", "api", "x"].joined(separator: "-"), session: StubProtocol.session())!
            await store.loadPostureAttributes(GuardedServer(c, workspace: "T", requireAuth: false), nodes: nodes, workspace: ws.id)
        }
        XCTAssertEqual(store.headscaleNodes.first?.attributes?["node:os"], "linux")
    }
}
