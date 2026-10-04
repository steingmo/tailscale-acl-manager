import XCTest
@testable import TailscaleACL

final class UserManagementClientTests: XCTestCase {
    override func setUp() {
        StubProtocol.requests = []
        StubProtocol.handler = { _, _ in .init(body: Data("{}".utf8)) }
    }

    func calls() -> [String] {
        StubProtocol.requests.map { "\($0.request.httpMethod!) \($0.request.url!.path)" }
    }

    func tailscale() -> PolicyServer {
        makeServer(kind: .tailscale, serverURL: "", tailnet: "-", credential: "tskey-api-x", session: StubProtocol.session())!
    }

    func headscale() -> PolicyServer {
        makeServer(kind: .headscale, serverURL: "https://hs.example", tailnet: "", credential: "k", session: StubProtocol.session())!
    }

    func testTailscaleUsersAndInvites() async throws {
        StubProtocol.handler = { req, _ in
            switch req.url!.path {
            case "/api/v2/tailnet/-/users":
                return .init(body: Data("""
                {"users": [{"id": "u1", "loginName": "Amy@x.com", "displayName": "Amy Lee", "role": "admin",
                            "status": "active", "type": "member", "deviceCount": 3, "lastSeen": "2026-10-01T10:00:00Z"}]}
                """.utf8))
            case "/api/v2/tailnet/-/user-invites" where req.httpMethod == "GET":
                return .init(body: Data(#"[{"id": "29214", "role": "member", "email": "new@x.com", "inviteUrl": "https://login.tailscale.com/uinv/abc"}]"#.utf8))
            case "/api/v2/tailnet/-/user-invites":
                return .init(body: Data(#"[{"id": "29215", "role": "admin", "email": "bob@x.com", "inviteUrl": "https://login.tailscale.com/uinv/def"}]"#.utf8))
            default:
                return .init(body: Data("{}".utf8))
            }
        }
        let c = tailscale()
        let users = try await c.serverUsers()
        XCTAssertEqual(users.accounts.first, ServerAccount(id: "u1", login: "Amy@x.com", displayName: "Amy Lee",
                                                           policyNames: ["amy@x.com"], role: "admin", status: "active",
                                                           deviceCount: 3, lastSeen: "2026-10-01T10:00:00Z"))
        XCTAssertEqual(users.autogroups["amy@x.com"], ["autogroup:admin"])

        let invites = try await c.listInvites()
        XCTAssertEqual(invites.map(\.email), ["new@x.com"])
        let sent = try await c.invite(email: "bob@x.com", role: "admin")
        XCTAssertEqual(sent.inviteURL, "https://login.tailscale.com/uinv/def")
        let body = try JSONSerialization.jsonObject(with: StubProtocol.requests[2].body) as? [[String: String]]
        XCTAssertEqual(body, [["email": "bob@x.com", "role": "admin"]], "invites are sent as an array")

        StubProtocol.requests = []
        try await c.resendInvite(id: "29214")
        try await c.cancelInvite(id: "29214")
        try await c.setRole(userID: "u1", role: "auditor")
        try await c.approveUser(id: "u1")
        try await c.suspendUser(id: "u1")
        try await c.restoreUser(id: "u1")
        try await c.deleteUser(id: "u1")
        XCTAssertEqual(calls(), [
            "POST /api/v2/user-invites/29214/resend", "DELETE /api/v2/user-invites/29214",
            "POST /api/v2/users/u1/role", "POST /api/v2/users/u1/approve", "POST /api/v2/users/u1/suspend",
            "POST /api/v2/users/u1/restore", "POST /api/v2/users/u1/delete",
        ])
        XCTAssertEqual(try JSONSerialization.jsonObject(with: StubProtocol.requests[2].body) as? [String: String], ["role": "auditor"])
    }

    func testHeadscaleCreatesAndDeletesUsers() async throws {
        StubProtocol.handler = { req, _ in
            req.httpMethod == "POST"
                ? .init(body: Data(#"{"user": {"id": "9", "name": "amy", "displayName": "Amy", "email": ""}}"#.utf8))
                : .init(body: Data(#"{"users": [{"id": "9", "name": "amy", "email": "Amy@x.com"}, {"id": "10", "name": "carl"}]}"#.utf8))
        }
        let c = headscale()
        let created = try await c.createUser(name: "amy", displayName: "Amy", email: "")
        XCTAssertEqual(created.login, "amy@")
        XCTAssertEqual(created.displayName, "Amy")
        XCTAssertEqual(try JSONSerialization.jsonObject(with: StubProtocol.requests[0].body) as? [String: String],
                       ["name": "amy", "displayName": "Amy"])
        let users = try await c.serverUsers()
        XCTAssertEqual(users.accounts.map(\.login), ["Amy@x.com", "carl@"])
        XCTAssertEqual(users.accounts[0].policyNames, ["amy@x.com", "amy", "amy@"])
        XCTAssertEqual(users.autogroups, [:], "Headscale has no roles")
        try await c.deleteUser(id: "10")
        XCTAssertEqual(calls().last, "DELETE /api/v1/user/10")
    }

    func testUnsupportedActionsSayWhy() async {
        do {
            _ = try await headscale().invite(email: "a@x.com", role: "member")
            XCTFail("Headscale has no invites")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("doesn't support invites"))
        }
        do {
            _ = try await tailscale().createUser(name: "a", displayName: "", email: "")
            XCTFail("Tailscale invites instead")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("invite them instead"))
        }
        XCTAssertTrue(StubProtocol.requests.isEmpty)
    }

    func testPermissionErrorsExplainTheFix() {
        let text = UsersPanel.explain(ServerError(status: 403, message: "HTTP 403: forbidden"), kind: .tailscale)
        XCTAssertTrue(text.contains("users scope"))
        XCTAssertTrue(text.contains("personal API access token"))
    }
}

@MainActor
final class UserPolicyEditTests: XCTestCase {
    var dir: URL!

    override func setUp() async throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        setenv("TAILSCALE_ACL_DATA_DIR", dir.path, 1)
        let ws = Workspace(name: "Home", serverURL: "", policy: """
        {
          // Teams
          "groups": {"group:eng": ["amy@x.com"], "group:ops": ["Amy@X.com", "bob@x.com"]},
          "tagOwners": {"tag:db": ["amy@x.com", "group:ops"]},
        }
        """)
        try WorkspaceStore.save([ws])
        UserDefaults.standard.set(ws.id.uuidString, forKey: "currentWorkspaceID")
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: dir)
        unsetenv("TAILSCALE_ACL_DATA_DIR")
    }

    func testAddToGroupsSkipsExistingAndCreatesMissing() {
        let store = PolicyStore()
        store.addUser("carl@x.com", toGroups: ["group:eng", "group:new"])
        store.addUser("AMY@x.com", toGroups: ["group:eng"])
        XCTAssertEqual(store.model.groups["group:eng"], ["amy@x.com", "carl@x.com"], "case-insensitive duplicate skipped")
        XCTAssertEqual(store.model.groups["group:new"], ["carl@x.com"])
        XCTAssertTrue(store.text.contains("// Teams"), "comments survive")
    }

    func testOffboardingRemovesEverywhere() {
        let store = PolicyStore()
        XCTAssertEqual(store.groups(containing: ["amy@x.com"]), ["group:eng", "group:ops"])
        let um = UndoManager()
        um.groupsByEvent = false
        store.undoManager = um
        um.beginUndoGrouping()
        store.removeUserEverywhere(["amy@x.com", "amy", "amy@"])
        um.endUndoGrouping()
        XCTAssertEqual(store.model.groups["group:eng"], [])
        XCTAssertEqual(store.model.groups["group:ops"], ["bob@x.com"])
        XCTAssertEqual(store.model.tagOwners["tag:db"], ["group:ops"])
        um.undo()
        XCTAssertEqual(store.model.groups["group:ops"], ["Amy@X.com", "bob@x.com"], "one undo step")
    }
}
