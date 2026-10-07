import XCTest
@testable import TailscaleACL

final class RouteAccessTests: XCTestCase {
    let exitA = HeadscaleNode(id: "1", name: "exit-office", availableRoutes: ["0.0.0.0/0", "::/0"],
                              approvedRoutes: ["0.0.0.0/0", "::/0"], tags: ["tag:client-vpn"])
    let exitB = HeadscaleNode(id: "2", name: "exit-cloud", approvedRoutes: ["0.0.0.0/0", "::/0"], tags: ["tag:cloud"])
    let router = HeadscaleNode(id: "3", name: "router-1", approvedRoutes: ["10.114.32.0/24", "10.187.0.0/16"],
                               tags: ["tag:mgmt-vpn"])
    let policy = """
    {"groups": {"group:mgmt": ["amy@x.com"], "group:all": ["bob@x.com"]},
     "tagOwners": {"tag:client-vpn": [], "tag:cloud": [], "tag:mgmt-vpn": []},
     "ipsets": {"ipset:mgmt-networks": ["add 10.114.32.0/24"]},
     "grants": [
       {"src": ["group:mgmt"], "dst": ["autogroup:internet"], "ip": ["*"], "via": ["tag:client-vpn"]},
       {"src": ["group:mgmt"], "dst": ["ipset:mgmt-networks"], "ip": ["*"], "via": ["tag:mgmt-vpn"]},
       {"src": ["group:all"], "dst": ["*"], "ip": ["*"]},
     ]}
    """

    func testExitNodeViaAndSubnets() {
        let a = routeAccess(model(policy), sourceIDs: ["group:mgmt"], nodes: [exitA, exitB, router])
        XCTAssertTrue(a.exitNode)
        XCTAssertEqual(a.exitVia, ["tag:client-vpn"])
        XCTAssertEqual(a.exitNodes, ["exit-office"], "only exit nodes with the via tag")
        XCTAssertEqual(a.subnets.map(\.route), ["10.114.32.0/24"], "10.187.0.0/16 isn't reached")
        XCTAssertEqual(a.subnets.first?.routers, ["router-1"])
    }

    func testWildcardMeansAnyExitNodeAndEverySubnet() {
        let a = routeAccess(model(policy), sourceIDs: ["bob@x.com"], nodes: [exitA, exitB, router])
        XCTAssertTrue(a.exitNode)
        XCTAssertEqual(a.exitVia, [])
        XCTAssertEqual(a.exitNodes, ["exit-office", "exit-cloud"])
        XCTAssertEqual(a.subnets.map(\.route), ["10.114.32.0/24", "10.187.0.0/16"])
    }

    func testSubnetsInNumericOrder() {
        let r = HeadscaleNode(id: "9", name: "r", approvedRoutes: ["10.114.10.0/24", "10.114.2.0/24", "fd00::/64", "9.0.0.0/8"])
        let a = routeAccess(model(policy), sourceIDs: ["bob@x.com"], nodes: [r])
        XCTAssertEqual(a.subnets.map(\.route), ["9.0.0.0/8", "10.114.2.0/24", "10.114.10.0/24", "fd00::/64"])
    }

    func testInternetInsideAnIPSet() {
        let p = """
        {"ipsets": {"ipset:mgmt-internet": ["add autogroup:internet", "remove 1.2.3.4"],
                    "ipset:outer": ["ipset:mgmt-internet"]},
         "grants": [{"src": ["amy@x.com"], "dst": ["ipset:outer"], "ip": ["*"], "via": ["tag:client-vpn"]}]}
        """
        let a = routeAccess(model(p), sourceIDs: ["amy@x.com"], nodes: [exitA, exitB, router])
        XCTAssertTrue(a.exitNode)
        XCTAssertEqual(a.exitNodes, ["exit-office"])
        XCTAssertTrue(a.subnets.isEmpty, "the internet reaches no subnet route")
    }

    func testZoomClamping() {
        XCTAssertEqual(0.1.clamped(to: 0.3...2.0), 0.3)
        XCTAssertEqual(2.5.clamped(to: 0.3...2.0), 2.0)
        XCTAssertEqual(1.2.clamped(to: 0.3...2.0), 1.2)
    }

    func testNoInternetRule() {
        let a = routeAccess(model(policy), sourceIDs: ["eve@x.com"], nodes: [exitA, router])
        XCTAssertFalse(a.exitNode)
        XCTAssertTrue(a.exitNodes.isEmpty)
        XCTAssertTrue(a.subnets.isEmpty)
    }
}

final class SidebarTests: XCTestCase {
    func testEveryScreenIsInExactlyOneSidebarGroup() {
        let listed = Screen.groups.flatMap(\.screens)
        XCTAssertEqual(listed.count, Set(listed).count, "no duplicates")
        XCTAssertEqual(Set(listed), Set(Screen.allCases), "nothing missing from the sidebar")
    }
}
