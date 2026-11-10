import XCTest
import SwiftUI
@testable import TailscaleACL

/// Lays out and draws every screen offscreen with a normal, an empty, and a
/// broken policy — a screen that crashes or can't lay out fails here.
/// Set SCREENSHOT_DIR to also write each one as a PNG, to look at UI changes:
///   SCREENSHOT_DIR=/some/folder swift test --filter ScreenSmokeTests
@MainActor
final class ScreenSmokeTests: XCTestCase {
    static let sample = """
    {
      "groups": {
        "group:admins": ["alice@example.com"],
        "group:eng": ["alice@example.com", "bob@example.com"],
        "group:support": ["dave@example.com"],
      },
      "tagOwners": {"tag:prod": ["group:admins"], "tag:db": ["group:admins"], "tag:web": ["group:eng"], "tag:exit": ["group:admins"]},
      "hosts": {"nas": "10.0.0.5", "office": "192.168.10.0/24"},
      "acls": [
        {"action": "accept", "src": ["group:support"], "dst": ["tag:web:443"]},
        {"action": "accept", "src": ["group:eng"], "dst": ["nas:445", "office:*"]},
      ],
      "grants": [
        {"src": ["group:eng"], "dst": ["tag:web"], "ip": ["tcp:22", "tcp:443"]},
        {"src": ["group:admins"], "dst": ["tag:prod", "tag:db"], "ip": ["*"]},
        {"src": ["autogroup:member"], "dst": ["autogroup:internet"], "ip": ["*"], "via": ["tag:exit"]},
        {"src": ["group:ghosts"], "dst": ["tag:prod"], "ip": ["tcp:22"]},
      ],
      "ssh": [
        {"action": "check", "src": ["group:admins"], "dst": ["tag:prod"], "users": ["root", "ubuntu"]},
      ],
      "tests": [
        {"src": "bob@example.com", "accept": ["tag:web:443"], "deny": ["tag:db:5432"]},
        {"src": "dave@example.com", "accept": ["tag:web:22"]},
      ],
    }
    """

    func testEveryScreenDrawsWithAnyPolicy() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        setenv("TAILSCALE_ACL_DATA_DIR", dir.path, 1)
        let defaults = UserDefaults.standard
        defaults.set(true, forKey: "gettingStartedDone")
        defer {
            try? FileManager.default.removeItem(at: dir)
            unsetenv("TAILSCALE_ACL_DATA_DIR")
            defaults.removeObject(forKey: "lastScreen")
            defaults.removeObject(forKey: "gettingStartedDone")
        }
        let devices = nodes("""
        {"nodes": [
          {"id": "1", "givenName": "alice-mbp", "user": {"name": "alice", "email": "alice@example.com"}, "ipAddresses": ["100.64.0.1"], "online": true},
          {"id": "2", "givenName": "web-1", "tags": ["tag:web"], "ipAddresses": ["100.64.0.10"], "online": true},
          {"id": "3", "givenName": "exit-ams", "tags": ["tag:exit"], "ipAddresses": ["100.64.0.12"], "availableRoutes": ["0.0.0.0/0", "::/0"], "approvedRoutes": ["0.0.0.0/0", "::/0"]}
        ]}
        """)
        let out = ProcessInfo.processInfo.environment["SCREENSHOT_DIR"]
        let policies = [("sample", Self.sample, devices), ("empty", "{}", []), ("broken", "{\n  \"groups\": {\n    \"group:eng\": [\"a@example.com\"\n  }\n}", [])]
        for (label, policy, devices) in policies {
            // No server: nothing here touches the network or the Keychain.
            let ws = Workspace(name: "Home lab", serverURL: "", policy: policy)
            try WorkspaceStore.save([ws])
            defaults.set(ws.id.uuidString, forKey: "currentWorkspaceID")
            for screen in Screen.allCases {
                defaults.set(screen.rawValue, forKey: "lastScreen")
                let store = PolicyStore()
                store.headscaleNodes = devices
                // The smallest window the app allows.
                let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 980, height: 620), styleMask: [.titled],
                                      backing: .buffered, defer: false)
                let host = NSHostingView(rootView: RootView().environmentObject(store))
                window.contentView = host
                host.layoutSubtreeIfNeeded()
                RunLoop.main.run(until: Date().addingTimeInterval(out == nil ? 0.02 : 0.6))
                host.layoutSubtreeIfNeeded()
                let rep = try XCTUnwrap(host.bitmapImageRepForCachingDisplay(in: host.bounds), "\(label) \(screen.rawValue)")
                host.cacheDisplay(in: host.bounds, to: rep)
                // The editor takes any height, so anything above the window's
                // minimum here is the sidebar not fitting (it didn't before 1.33).
                if screen == .policyEditor {
                    XCTAssertEqual(host.fittingSize.height, 620, accuracy: 1, "the sidebar needs more height than the smallest window")
                }
                if let out {
                    let name = "\(label)-\(screen.rawValue.replacingOccurrences(of: " ", with: "-")).png"
                    try rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: out).appendingPathComponent(name))
                }
            }
        }
    }
}
