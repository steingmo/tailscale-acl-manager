import XCTest
import SwiftUI
@testable import TailscaleACL

/// Regression: 1.31.0 re-ordered every box for every line on each redraw,
/// so an ACL-heavy policy took minutes to draw (beachball). Now well under a second.
@MainActor
final class VisualBuilderPerformanceTests: XCTestCase {
    func testLargeACLPolicyDrawsQuickly() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        setenv("TAILSCALE_ACL_DATA_DIR", dir.path, 1)
        defer { try? FileManager.default.removeItem(at: dir); unsetenv("TAILSCALE_ACL_DATA_DIR") }
        var acls: [String] = []
        for i in 0..<30 {
            let dsts = (0..<6).map { #""host\#((i + $0) % 40):\#(20 + $0),443""# }.joined(separator: ",")
            acls.append(#"{"action": "accept", "src": ["group:g\#(i % 25)", "tag:t\#(i % 15)"], "dst": [\#(dsts)]}"#)
        }
        let grants = (0..<40).map { #"{"src": ["group:g\#($0 % 25)"], "dst": ["host\#($0 % 40)"], "ip": ["tcp:\#(1000 + $0)"]}"# }
        let groups = (0..<25).map { #""group:g\#($0)": ["u\#($0)@x.com"]"# }.joined(separator: ",")
        let hosts = (0..<40).map { #""host\#($0)": "10.0.\#($0).1""# }.joined(separator: ",")
        let tags = (0..<15).map { #""tag:t\#($0)": []"# }.joined(separator: ",")
        let policy = "{\"groups\": {\(groups)}, \"hosts\": {\(hosts)}, \"tagOwners\": {\(tags)}, \"acls\": [\(acls.joined(separator: ","))], \"grants\": [\(grants.joined(separator: ","))]}"
        let ws = Workspace(name: "Perf", serverURL: "", policy: policy)
        try WorkspaceStore.save([ws])
        UserDefaults.standard.set(ws.id.uuidString, forKey: "currentWorkspaceID")
        let store = PolicyStore()
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1100, height: 900), styleMask: [.titled], backing: .buffered, defer: false)
        let start = Date()
        let host = NSHostingView(rootView: VisualBuilderScreen().environmentObject(store))
        window.contentView = host
        host.layoutSubtreeIfNeeded()
        let rep = try XCTUnwrap(host.bitmapImageRepForCachingDisplay(in: host.bounds))
        host.cacheDisplay(in: host.bounds, to: rep)
        XCTAssertLessThan(Date().timeIntervalSince(start), 5, "drawing 400 lines must not take minutes")
    }
}

final class BuilderBoxTests: XCTestCase {
    func testEveryLineHasBothBoxes() {
        // People and addresses named only in rules aren't "defined" entities, but still get boxes.
        let hidden = builderBoxNames(usedSources: ["group:rds", "hjdj@x.com", "group:rds"], usedDests: ["ipset:db", "10.0.0.5"],
                                     definedSources: ["*", "group:rds", "group:unused"], definedDests: ["*", "ipset:db", "tag:unused"],
                                     includeDefined: false)
        XCTAssertEqual(hidden.sources, ["group:rds", "hjdj@x.com"])
        XCTAssertEqual(hidden.dests, ["ipset:db", "10.0.0.5"])
        XCTAssertEqual(hidden.hidden, 4)
        let shown = builderBoxNames(usedSources: ["hjdj@x.com"], usedDests: ["10.0.0.5"],
                                    definedSources: ["*", "group:unused"], definedDests: ["tag:unused"], includeDefined: true)
        XCTAssertEqual(shown.sources, ["hjdj@x.com", "*", "group:unused"])
        XCTAssertEqual(shown.dests, ["10.0.0.5", "tag:unused"])
        XCTAssertEqual(shown.hidden, 0)
    }
}
