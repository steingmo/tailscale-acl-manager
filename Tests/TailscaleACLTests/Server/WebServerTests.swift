import XCTest
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Hummingbird
import HummingbirdTesting
import HTTPTypes
@testable import TailscaleACL

/// The web service: config checks, signing in with Microsoft (stubbed), who
/// gets in, and the read-only API against a stubbed tailnet.
final class WebServerTests: XCTestCase {
    let tenant = "11111111-2222-3333-4444-555555555555"
    let clientID = "app-id"
    var dir: URL!

    override func setUp() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        StubProtocol.requests = []
        StubProtocol.handler = { _, _ in .init(status: 500) }
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: dir)
    }

    func config(_ extra: String = "", publicURL: String = "https://acl.example.ts.net") throws -> ServerConfig {
        try JSONDecoder().decode(ServerConfig.self, from: Data("""
        {
          "publicURL": "\(publicURL)",
          "dataDir": "\(dir.path)",
          "entra": {"tenant": "\(tenant)", "clientID": "\(clientID)", "clientSecret": "s3cret"},
          "roles": {"viewer": ["Viewer"], "approver": ["group-approvers"]},
          "sources": [{"id": "prod", "name": "Production", "kind": "tailscale", "tailnet": "-", "credential": "tskey-api-x"}]
          \(extra)
        }
        """.utf8))
    }

    /// An ID token as Microsoft's token endpoint would return it (the server doesn't check the signature; see EntraLogin.validate).
    func idToken(_ claims: [String: Any]) -> String {
        var all: [String: Any] = [
            "iss": "https://login.microsoftonline.com/\(tenant)/v2.0", "aud": clientID, "tid": tenant,
            "exp": Date().timeIntervalSince1970 + 3_600, "nbf": Date().timeIntervalSince1970 - 10,
            "oid": "user-1", "preferred_username": "Alice@Example.com", "name": "Alice",
        ]
        claims.forEach { all[$0.key] = $0.value }
        return "e30." + base64URL(try! JSONSerialization.data(withJSONObject: all)) + ".sig"
    }

    // MARK: - Config

    func testConfigProblems() throws {
        XCTAssertEqual(try config().problems(devLoginAllowed: false), [])
        XCTAssertEqual(try config().listenAddress?.port, 8_080)

        func problems(_ json: String, dev: Bool = false) throws -> String {
            try JSONDecoder().decode(ServerConfig.self, from: Data(json.utf8)).problems(devLoginAllowed: dev).joined(separator: "\n")
        }
        let source = #""sources": [{"id": "prod", "name": "P", "kind": "tailscale", "credential": "k"}]"#
        let entra = #""entra": {"tenant": "\#(tenant)", "clientID": "a", "clientSecret": "s"}, "roles": {"viewer": ["V"]}"#
        // Plain http away from localhost, a domain as the tenant, nobody able to sign in, a bad source id, no credential.
        let bad = try problems(#"""
        {"publicURL": "http://acl.example.com", "dataDir": "/tmp/x", "listen": "8080",
         "entra": {"tenant": "example.com", "clientID": "a", "clientSecret": "s"},
         "sources": [{"id": "Prod One", "name": "P", "kind": "headscale"}]}
        """#)
        for expected in ["listen:", "must be https", "tenant ID", "nobody could sign in", "lowercase letters", "serverURL", "credentialFile"] {
            XCTAssertTrue(bad.contains(expected), "\(expected) missing in:\n\(bad)")
        }
        // The development login needs the flag and localhost.
        let dev = #""devLogin": {"login": "me@example.com", "roles": ["viewer"]}"#
        XCTAssertTrue(try problems(#"{"publicURL": "http://localhost:8080", "dataDir": "/tmp/x", \#(dev), \#(source)}"#).contains("--insecure-dev-login"))
        XCTAssertEqual(try problems(#"{"publicURL": "http://localhost:8080", "dataDir": "/tmp/x", \#(dev), \#(source)}"#, dev: true), "")
        XCTAssertTrue(try problems(#"{"publicURL": "https://acl.example.com", "dataDir": "/tmp/x", \#(dev), \#(source)}"#, dev: true)
            .contains("localhost"))
        XCTAssertTrue(try problems(#"{"publicURL": "https://acl.example.com/app", "dataDir": "/tmp/x", \#(entra), \#(source)}"#).contains("publicURL"))
    }

    func testSecretsComeFromFilesAndLooseOnesAreNoticed() throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let file = dir.appendingPathComponent("secret")
        try Data("  from-file\n".utf8).write(to: file)
        XCTAssertEqual(try secret("inline", file: file.path), "from-file")
        XCTAssertEqual(try secret("inline", file: nil), "inline")
        XCTAssertThrowsError(try secret(nil, file: dir.appendingPathComponent("missing").path))
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
        XCTAssertEqual(readableByOthers([file.path]), [file.path], "everyone can read it")
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        XCTAssertEqual(readableByOthers([file.path]), [])
        // root:tailscale-acl 0640 is the intended layout; the same mode with another group isn't.
        let group = try XCTUnwrap(FileManager.default.attributesOfItem(atPath: file.path)[.groupOwnerAccountID] as? NSNumber).uint32Value
        try FileManager.default.setAttributes([.posixPermissions: 0o640], ofItemAtPath: file.path)
        XCTAssertEqual(readableByOthers([file.path], ownGroup: group), [])
        XCTAssertEqual(readableByOthers([file.path], ownGroup: group &+ 1), [file.path])
    }

    // MARK: - ID token and roles

    func testIDTokenChecks() throws {
        let login = EntraLogin(tenant: tenant, clientID: clientID, clientSecret: "s", redirectURI: "https://x/auth/callback")
        let ok = try login.validate(idToken: idToken(["nonce": "n1", "roles": ["Viewer"]]), nonce: "n1")
        XCTAssertEqual(ok.oid, "user-1")
        let cases: [(String, [String: Any])] = [
            ("another application", ["nonce": "n1", "aud": "other-app"]),
            ("another tenant", ["nonce": "n1", "iss": "https://login.microsoftonline.com/99999999-2222-3333-4444-555555555555/v2.0"]),
            ("another tenant", ["nonce": "n1", "tid": "99999999-2222-3333-4444-555555555555"]),
            ("expired", ["nonce": "n1", "exp": Date().timeIntervalSince1970 - 3_600]),
            ("isn't valid yet", ["nonce": "n1", "nbf": Date().timeIntervalSince1970 + 3_600]),
            ("this sign-in", ["nonce": "someone-elses"]),
            ("this sign-in", [:]),
        ]
        for (expected, claims) in cases {
            XCTAssertThrowsError(try login.validate(idToken: idToken(claims), nonce: "n1"), expected) {
                XCTAssertTrue($0.localizedDescription.contains(expected), "\($0.localizedDescription) ≠ \(expected)")
            }
        }
        XCTAssertThrowsError(try login.validate(idToken: "not-a-token", nonce: "n1"))
    }

    func testRolesAndReturnPath() throws {
        let mapping = try config().roles
        func held(_ roles: [String], groups: [String] = []) -> Set<Role> {
            TailscaleACL.roles(for: IDTokenClaims(iss: "", aud: "", exp: 0, roles: roles, groups: groups), mapping)
        }
        XCTAssertEqual(held(["Viewer"]), [.viewer])
        XCTAssertEqual(held([], groups: ["group-approvers"]), [.viewer, .approver], "approvers can also view")
        XCTAssertEqual(held(["Something"], groups: ["other"]), [])
        XCTAssertEqual(pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "RFC 7636's example")
        XCTAssertEqual(safeReturnPath("/map?x=1"), "/map?x=1")
        for elsewhere in ["//evil.example", "https://evil.example", "/\\evil.example", "evil", nil] {
            XCTAssertEqual(safeReturnPath(elsewhere), "/", elsewhere ?? "nil")
        }
    }

    func testSessionsExpireAndStatesWorkOnce() async {
        let store = SessionStore()
        let now = Date()
        let state = await store.begin(nonce: "n", verifier: "v", returnTo: "/", now: now)!
        let first = await store.finish(state: state, now: now)
        let again = await store.finish(state: state, now: now)
        XCTAssertEqual(first?.nonce, "n")
        XCTAssertNil(again, "a state is used once")
        let late = await store.begin(nonce: "n", verifier: "v", returnTo: "/", now: now)!
        let expired = await store.finish(state: late, now: now.addingTimeInterval(SessionStore.pendingLifetime + 1))
        XCTAssertNil(expired)

        let user = SignedInUser(id: "1", login: "a@example.com", name: "A", roles: [.viewer])
        let id = await store.signIn(user, now: now)
        let during = await store.user(for: id, now: now.addingTimeInterval(3_600))
        let after = await store.user(for: id, now: now.addingTimeInterval(SessionStore.sessionLifetime + 1))
        XCTAssertEqual(during, user)
        XCTAssertNil(after)
        await store.signOut(id)
        let gone = await store.user(for: id, now: now)
        XCTAssertNil(gone)
    }

    // MARK: - The service

    /// Microsoft's token endpoint and the Tailscale API, both stubbed.
    func stub(claims: [String: Any] = ["roles": ["Viewer"]]) {
        let token = { (nonce: String) in self.idToken(claims.merging(["nonce": nonce]) { a, _ in a }) }
        StubProtocol.handler = { request, body in
            let path = request.url?.path ?? ""
            if request.url?.host == "login.microsoftonline.com" {
                // The nonce isn't in the token request; the test passes it through the code.
                let form = String(data: body, encoding: .utf8) ?? ""
                let code = form.split(separator: "&").first { $0.hasPrefix("code=") }?.dropFirst(5) ?? ""
                return .init(body: Data(#"{"id_token": "\#(token(String(code)))"}"#.utf8))
            }
            if path.hasSuffix("/acl") {
                return .init(body: Data("""
                {
                  // production
                  "groups": {"group:eng": ["alice@example.com"]},
                  "tagOwners": {"tag:web": ["group:eng"]},
                  "grants": [
                    {"src": ["group:eng"], "dst": ["tag:web"], "ip": ["tcp:443"]},
                    {"src": ["group:ghosts"], "dst": ["tag:web"], "ip": ["tcp:22"]},
                  ],
                }
                """.utf8))
            }
            if path.hasSuffix("/devices") {
                return .init(body: Data(#"""
                {"devices": [
                  {"id": "1", "nodeId": "n1", "hostname": "alice-mbp", "name": "alice-mbp.example.ts.net", "user": "alice@example.com", "addresses": ["100.64.0.1"], "os": "macOS"},
                  {"id": "2", "nodeId": "n2", "hostname": "web-1", "name": "web-1.example.ts.net", "user": "", "addresses": ["100.64.0.2"], "tags": ["tag:web"]}
                ]}
                """#.utf8))
            }
            return .init(status: 403, body: Data(#"{"message": "no"}"#.utf8))
        }
    }

    func app(_ config: ServerConfig) throws -> (some ApplicationProtocol, ServerState) {
        let state = try ServerState(config: config, session: StubProtocol.session())
        return (Application(router: buildRouter(state)), state)
    }

    func cookie(_ response: TestResponse, _ name: String) -> String? {
        response.headers[values: .setCookie].first { $0.hasPrefix(name + "=") }
            .map { String($0.dropFirst(name.count + 1).prefix { $0 != ";" }) }
    }

    /// Goes through /login and the callback; returns the session cookie header, or the callback's status when refused.
    func signIn(_ client: any TestClientProtocol, _ state: ServerState, returnTo: String = "") async throws -> (cookie: String?, status: Int, location: String?) {
        let start = try await client.execute(uri: "/login" + returnTo, method: .get)
        XCTAssertEqual(start.status, .found)
        let authorize = try XCTUnwrap(URLComponents(string: try XCTUnwrap(start.headers[.location])))
        let query = Dictionary(uniqueKeysWithValues: (authorize.queryItems ?? []).map { ($0.name, $0.value ?? "") })
        XCTAssertEqual(authorize.host, "login.microsoftonline.com")
        XCTAssertEqual(authorize.path, "/\(tenant)/oauth2/v2.0/authorize")
        XCTAssertEqual(query["redirect_uri"], "https://acl.example.ts.net/auth/callback")
        XCTAssertEqual(query["code_challenge_method"], "S256")
        XCTAssertEqual(query["response_type"], "code")
        let loginState = try XCTUnwrap(query["state"]), nonce = try XCTUnwrap(query["nonce"])
        XCTAssertEqual(cookie(start, state.loginCookie), loginState)
        // The stub hands the "code" back as the token's nonce.
        let done = try await client.execute(uri: "/auth/callback?code=\(nonce)&state=\(loginState)", method: .get,
                                            headers: [.cookie: "\(state.loginCookie)=\(loginState)"])
        return (cookie(done, state.sessionCookie).map { "\(state.sessionCookie)=\($0)" }, Int(done.status.code), done.headers[.location])
    }

    func testSigningInAndTheAPI() async throws {
        stub()
        let (app, state) = try app(config())
        try await app.test(.router) { client in
            // Nothing without signing in.
            for path in ["/api/me", "/api/sources", "/api/sources/prod/policy"] {
                let response = try await client.execute(uri: path, method: .get)
                XCTAssertEqual(response.status, .unauthorized, path)
                XCTAssertEqual(response.headers[.xContentTypeOptions], "nosniff", "security headers on errors too")
            }
            let home = try await client.execute(uri: "/", method: .get)
            XCTAssertEqual(home.headers[.location], "/login?return=%2F")

            let signedIn = try await self.signIn(client, state, returnTo: "?return=/map")
            XCTAssertEqual(signedIn.status, 302)
            XCTAssertEqual(signedIn.location, "/map")
            let session = try XCTUnwrap(signedIn.cookie)
            XCTAssertTrue(session.hasPrefix("__Host-tsacl_session="), "https: the cookie is host-bound")

            // The code went to Microsoft with the secret and the PKCE verifier, server to server.
            let exchange = try XCTUnwrap(StubProtocol.requests.first { $0.request.url?.host == "login.microsoftonline.com" })
            let form = String(data: exchange.body, encoding: .utf8) ?? ""
            XCTAssertEqual(exchange.request.url?.path, "/\(self.tenant)/oauth2/v2.0/token")
            for part in ["client_secret=s3cret", "grant_type=authorization_code", "code_verifier=", "client_id=app-id"] {
                XCTAssertTrue(form.contains(part), part)
            }

            func json(_ path: String) async throws -> [String: Any] {
                let response = try await client.execute(uri: path, method: .get, headers: [.cookie: session])
                XCTAssertEqual(response.status, .ok, path)
                XCTAssertEqual(response.headers[.cacheControl], "no-store")
                return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(buffer: response.body)) as? [String: Any])
            }
            let me = try await json("/api/me")
            XCTAssertEqual(me["login"] as? String, "alice@example.com")
            XCTAssertEqual(me["roles"] as? [String], ["viewer"])
            let sources = try await json("/api/sources")
            XCTAssertEqual((sources["sources"] as? [[String: Any]])?.first?["id"] as? String, "prod")

            let policy = try await json("/api/sources/prod/policy")
            XCTAssertEqual(policy["valid"] as? Bool, true)
            XCTAssertTrue((policy["text"] as? String ?? "").contains("// production"), "comments and all")

            let problemsReply = try await json("/api/sources/prod/problems")
            let problems = try XCTUnwrap(problemsReply["problems"] as? [[String: Any]])
            let undefined = try XCTUnwrap(problems.first { $0["title"] as? String == "Undefined group" })
            XCTAssertEqual(undefined["severity"] as? String, "error")
            XCTAssertEqual(undefined["line"] as? Int, 7)

            let devicesReply = try await json("/api/sources/prod/devices")
            let devices = try XCTUnwrap(devicesReply["devices"] as? [[String: Any]])
            XCTAssertEqual(devices.map { $0["id"] as? String }, ["n1", "n2"])

            // A person, by name: allowed on 443, not on 22.
            let yes = try await json("/api/sources/prod/simulate?src=alice@example.com&dst=tag:web&port=443")
            XCTAssertEqual(yes["allowed"] as? Bool, true)
            let rule = try XCTUnwrap((yes["rules"] as? [[String: Any]])?.first)
            XCTAssertEqual(rule["kind"] as? String, "grant")
            XCTAssertEqual(rule["explanation"] as? String, "Everyone in eng can reach devices tagged web on HTTPS.")
            let no = try await json("/api/sources/prod/simulate?src=alice@example.com&dst=tag:web&port=22")
            XCTAssertEqual(no["allowed"] as? Bool, false)
            // Device to device.
            let byDevice = try await json("/api/sources/prod/simulate?src=node:n1&dst=node:n2&port=443")
            XCTAssertEqual(byDevice["allowed"] as? Bool, true)
            // One fetch of the policy for all of that.
            XCTAssertEqual(StubProtocol.requests.filter { $0.request.url?.path.hasSuffix("/acl") == true }.count, 1)

            for (path, status) in [("/api/sources/other/policy", HTTPResponse.Status.notFound),
                                   ("/api/sources/prod/simulate?src=a", .badRequest),
                                   ("/api/sources/prod/simulate?src=a&dst=b&port=99999", .badRequest),
                                   ("/api/sources/prod/simulate?src=node:nope&dst=b", .badRequest)] {
                let response = try await client.execute(uri: path, method: .get, headers: [.cookie: session])
                XCTAssertEqual(response.status, status, path)
            }

            // Signing out ends the session on the server, not just in the browser.
            let out = try await client.execute(uri: "/logout", method: .post, headers: [.cookie: session])
            XCTAssertEqual(out.status, .seeOther)
            let after = try await client.execute(uri: "/api/me", method: .get, headers: [.cookie: session])
            XCTAssertEqual(after.status, .unauthorized)
        }

        // Who did what is on file, and no secret or token is.
        let log = state.audit.entries()
        XCTAssertEqual(log.first?.event, "login")
        XCTAssertEqual(log.first?.user, "alice@example.com")
        XCTAssertTrue(log.contains { $0.event == "request" && $0.detail.contains("/simulate?src=alice@example.com&dst=tag:web&port=22 → 200") })
        XCTAssertEqual(log.last?.event, "logout")
        let raw = try String(contentsOf: state.audit.url, encoding: .utf8)
        XCTAssertFalse(raw.contains("s3cret") || raw.contains("tskey") || raw.contains("tsacl_session"))
        let mode = try XCTUnwrap(FileManager.default.attributesOfItem(atPath: state.audit.url.path)[.posixPermissions] as? NSNumber)
        XCTAssertEqual(mode.intValue & 0o077, 0, "the audit log is for the server's account only")
    }

    func testTheWebInterface() async throws {
        stub()
        let (app, state) = try app(config())
        try await app.test(.router) { client in
            // Signed out, a page sends you to sign in and back to it.
            let away = try await client.execute(uri: "/s/prod/map?focus=group:eng", method: .get)
            XCTAssertEqual(away.status, .found)
            XCTAssertEqual(away.headers[.location], "/login?return=%2Fs%2Fprod%2Fmap%3Ffocus%3Dgroup%3Aeng")
            let start = try await client.execute(uri: "/login?return=%2Fs%2Fprod%2Fmap%3Ffocus%3Dgroup%3Aeng", method: .get)
            let authorize = try XCTUnwrap(URLComponents(string: try XCTUnwrap(start.headers[.location])))
            XCTAssertNotNil(authorize.queryItems?.first { $0.name == "state" })

            // The files hold no data, so they're served to anyone.
            for (path, type) in [("/app.js", "text/javascript"), ("/style.css", "text/css"), ("/favicon.svg", "image/svg+xml")] {
                let response = try await client.execute(uri: path, method: .get)
                XCTAssertEqual(response.status, .ok, path)
                XCTAssertTrue(response.headers[.contentType]?.hasPrefix(type) == true, path)
                XCTAssertGreaterThan(response.body.readableBytes, 100, path)
            }

            let signedIn = try await self.signIn(client, state)
            let session = try XCTUnwrap(signedIn.cookie)
            for path in ["/", "/s/prod/map", "/s/prod/policy"] {
                let page = try await client.execute(uri: path, method: .get, headers: [.cookie: session])
                XCTAssertEqual(page.status, .ok, path)
                XCTAssertEqual(page.headers[.contentType], "text/html; charset=utf-8")
                let html = String(buffer: page.body)
                XCTAssertTrue(html.contains(#"<script src="/app.js" defer></script>"#))
                XCTAssertFalse(html.contains("<script>"), "the CSP allows no inline script")
                XCTAssertTrue(page.headers[.contentSecurityPolicy]?.contains("default-src 'self'") == true)
            }
            let missing = try await client.execute(uri: "/s/prod/map/extra", method: .get, headers: [.cookie: session])
            XCTAssertEqual(missing.status, .notFound)

            func json(_ path: String) async throws -> [String: Any] {
                let response = try await client.execute(uri: path, method: .get, headers: [.cookie: session])
                XCTAssertEqual(response.status, .ok, path)
                return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(buffer: response.body)) as? [String: Any])
            }

            let entities = try await json("/api/sources/prod/entities")
            XCTAssertEqual((entities["groups"] as? [[String: Any]])?.map { $0["name"] as? String }, ["group:eng"])
            XCTAssertEqual((entities["tags"] as? [[String: Any]])?.first?["detail"] as? [String], ["group:eng"])
            XCTAssertTrue((entities["autogroups"] as? [String] ?? []).contains("autogroup:member"))

            // What group:eng reaches, as on the Mac's Access Map.
            let reaches = try await json("/api/sources/prod/map?focus=group:eng")
            XCTAssertEqual((reaches["focus"] as? [String: Any])?["subtitle"] as? String, "1 member")
            let rule = try XCTUnwrap((reaches["rules"] as? [[String: Any]])?.first)
            XCTAssertEqual(rule["kind"] as? String, "grant")
            XCTAssertEqual(rule["badge"] as? String, "TCP:443")
            XCTAssertEqual(rule["line"] as? Int, 6)
            XCTAssertEqual(rule["explanation"] as? String, "Everyone in eng can reach devices tagged web on HTTPS.")
            XCTAssertEqual((reaches["endpoints"] as? [[String: Any]])?.map { $0["name"] as? String }, ["tag:web"])
            XCTAssertEqual((reaches["endpoints"] as? [[String: Any]])?.first?["subtitle"] as? String, "0 of 1 device online")
            XCTAssertNotNil(reaches["routes"], "devices are loaded, so exit nodes and subnets are summarised")

            // Who reaches the web server, by device.
            let reachedBy = try await json("/api/sources/prod/map?focus=node:n2&direction=reachedBy")
            XCTAssertEqual((reachedBy["focus"] as? [String: Any])?["label"] as? String, "web-1")
            XCTAssertEqual((reachedBy["endpoints"] as? [[String: Any]])?.compactMap { $0["name"] as? String }.sorted(),
                           ["group:eng", "group:ghosts"])
            XCTAssertNil(reachedBy["routes"])
            let noFocus = try await client.execute(uri: "/api/sources/prod/map", method: .get, headers: [.cookie: session])
            XCTAssertEqual(noFocus.status, .badRequest)

            // Problems include the device checks the Mac app runs once devices are loaded.
            let problems = try await json("/api/sources/prod/problems")
            let titles = (problems["problems"] as? [[String: Any]] ?? []).compactMap { $0["title"] as? String }
            XCTAssertTrue(titles.contains("Undefined group"))
            XCTAssertTrue(titles.contains("Rule matches no device"), "\(titles)")
        }
    }

    func testWhoIsKeptOut() async throws {
        // Signed in to Microsoft, but with no role here.
        stub(claims: ["roles": ["SomethingElse"]])
        let (app, state) = try app(config())
        try await app.test(.router) { client in
            let refused = try await self.signIn(client, state)
            XCTAssertEqual(refused.status, 403)
            XCTAssertNil(refused.cookie)

            // A callback that wasn't started in this browser: no cookie, or another state.
            let start = try await client.execute(uri: "/login", method: .get)
            let loginState = try XCTUnwrap(self.cookie(start, state.loginCookie))
            let noCookie = try await client.execute(uri: "/auth/callback?code=x&state=\(loginState)", method: .get)
            XCTAssertEqual(noCookie.status, .badRequest)
            let other = try await client.execute(uri: "/auth/callback?code=x&state=\(loginState)", method: .get,
                                                 headers: [.cookie: "\(state.loginCookie)=something-else"])
            XCTAssertEqual(other.status, .badRequest)
            // The right browser with a made-up code gets as far as Microsoft, which refuses it…
            let madeUp = try await client.execute(uri: "/auth/callback?code=x&state=\(loginState)", method: .get,
                                                  headers: [.cookie: "\(state.loginCookie)=\(loginState)"])
            XCTAssertEqual(madeUp.status, .badGateway)
            XCTAssertNil(self.cookie(madeUp, state.sessionCookie))
            // …and that used the state up.
            let replay = try await client.execute(uri: "/auth/callback?code=x&state=\(loginState)", method: .get,
                                                  headers: [.cookie: "\(state.loginCookie)=\(loginState)"])
            XCTAssertEqual(replay.status, .badRequest)

            // A made-up session cookie.
            let forged = try await client.execute(uri: "/api/me", method: .get, headers: [.cookie: "\(state.sessionCookie)=\(randomToken())"])
            XCTAssertEqual(forged.status, .unauthorized)
            // Signing in can't be used to send people to another site.
            let elsewhere = try await client.execute(uri: "/login?return=//evil.example/x", method: .get)
            XCTAssertNotNil(elsewhere.headers[.location])
            XCTAssertFalse(elsewhere.headers[.location]?.contains("evil.example") == true)
        }
        let events = state.audit.entries().map(\.event)
        XCTAssertEqual(events.filter { $0 == "login-failed" }.count, 5)
        XCTAssertFalse(events.contains("login"))
    }

    func testMicrosoftRefusingOrTheTailnetBeingDown() async throws {
        // Microsoft answers with an error (e.g. a wrong client secret).
        StubProtocol.handler = { request, _ in
            request.url?.host == "login.microsoftonline.com"
                ? .init(status: 401, body: Data(#"{"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided."}"#.utf8))
                : .init(status: 500)
        }
        let (app, state) = try app(config())
        try await app.test(.router) { client in
            let refused = try await self.signIn(client, state)
            XCTAssertEqual(refused.status, 502)
            XCTAssertNil(refused.cookie)
        }
        XCTAssertTrue(state.audit.entries().contains { $0.event == "login-failed" && $0.detail.contains("AADSTS7000215") },
                      "the operator can see why; the browser only gets a general message")

        // A tailnet that can't be read is a 502 without the server's own words.
        stub()
        let (second, secondState) = try self.app(config())
        try await second.test(.router) { client in
            let signedIn = try await self.signIn(client, secondState)
            let session = try XCTUnwrap(signedIn.cookie)
            StubProtocol.handler = { _, _ in .init(status: 500, body: Data(#"{"message": "internal detail"}"#.utf8)) }
            let response = try await client.execute(uri: "/api/sources/prod/policy", method: .get, headers: [.cookie: session])
            XCTAssertEqual(response.status, .badGateway)
            XCTAssertFalse(String(buffer: response.body).contains("internal detail"))
        }
    }

    func testAuditLogSurvivesRotation() throws {
        let log = try AuditLog(directory: dir.path)
        log.record("login", user: "a@example.com", detail: "first")
        try FileManager.default.moveItem(at: log.url, to: dir.appendingPathComponent("audit.jsonl.1"))
        log.record("login", user: "b@example.com", detail: "after rotation")
        XCTAssertEqual(log.entries().map(\.detail), ["after rotation"])
        let mode = try XCTUnwrap(FileManager.default.attributesOfItem(atPath: log.url.path)[.posixPermissions] as? NSNumber)
        XCTAssertEqual(mode.intValue & 0o077, 0)
    }

    func testDevelopmentLoginOnlyWhenAskedFor() async throws {
        let dev = try config(#", "devLogin": {"login": "Dev@Example.com", "roles": ["viewer", "approver"]}"#, publicURL: "http://localhost:8080")
        XCTAssertFalse(dev.problems(devLoginAllowed: false).isEmpty)
        let (app, state) = try app(dev)
        try await app.test(.router) { client in
            let start = try await client.execute(uri: "/login", method: .get)
            let session = try XCTUnwrap(self.cookie(start, "tsacl_session"), "http on localhost: a plain cookie name")
            let me = try await client.execute(uri: "/api/me", method: .get, headers: [.cookie: "tsacl_session=\(session)"])
            XCTAssertEqual(me.status, .ok)
            XCTAssertTrue(String(buffer: me.body).contains("dev@example.com"))
        }
        XCTAssertEqual(state.audit.entries().first?.detail, "development login")
    }

    func testServeCommandChecksTheConfig() async throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let path = dir.appendingPathComponent("server.json").path
        var lines: [String] = []
        let noFile = await runServeCommand(["--config", path, "--check"]) { lines.append($0) }
        XCTAssertEqual(noFile, 1)
        try Data(#"{"publicURL": "http://acl.example.com", "dataDir": "\#(dir.path)", "sources": []}"#.utf8).write(to: URL(fileURLWithPath: path))
        let bad = await runServeCommand(["--config", path, "--check"]) { lines.append($0) }
        XCTAssertEqual(bad, 1)
        XCTAssertTrue(lines.joined().contains("must be https"))
        lines = []
        try Data("""
        {"publicURL": "https://acl.example.ts.net", "dataDir": "\(dir.path)/data",
         "entra": {"tenant": "\(tenant)", "clientID": "a", "clientSecret": "s"}, "roles": {"viewer": ["Viewer"]},
         "sources": [{"id": "prod", "name": "P", "kind": "tailscale", "credential": "k"}]}
        """.utf8).write(to: URL(fileURLWithPath: path))
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path)
        let good = await runServeCommand(["--config", path, "--check"]) { lines.append($0) }
        XCTAssertEqual(good, 0, lines.joined(separator: "\n"))
        XCTAssertTrue(lines.contains { $0.contains("can be read by other accounts") })
        XCTAssertTrue(lines.last?.contains("https://acl.example.ts.net/auth/callback") == true)
        let usage = await runServeCommand(["--nope"]) { _ in }
        XCTAssertEqual(usage, 2)
    }
}
