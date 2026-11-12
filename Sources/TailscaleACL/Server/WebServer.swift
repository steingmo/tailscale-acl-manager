import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Hummingbird
import HummingbirdTLS
import HTTPTypes
import NIOSSL

// `tailscale-acl serve`: the read-only web service. People sign in with
// Microsoft; viewers can read the policy, its problems and devices, and
// simulate access. It never changes a policy.

// MARK: - Audit log

/// Who did what, appended as JSON lines to <dataDir>/audit.jsonl (readable by
/// the server's account only). Never contains secrets or tokens.
final class AuditLog: @unchecked Sendable {
    struct Entry: Codable, Equatable {
        var time: Date
        var event: String
        var user: String?
        var detail: String
        var from: String?
    }

    let url: URL
    private let lock = NSLock()
    private let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return e
    }()

    /// `create: false` (a config check, maybe run as root) touches nothing:
    /// a log created by root couldn't be written by the service's account.
    init(directory: String, create: Bool = true) throws {
        let dir = URL(fileURLWithPath: directory, isDirectory: true)
        url = dir.appendingPathComponent("audit.jsonl")
        guard create else { return }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if !FileManager.default.fileExists(atPath: url.path) {
            guard FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
                throw ConfigError("\(url.path): cannot create the audit log")
            }
        }
        // Fail at start, not at the first sign-in.
        guard FileManager.default.isWritableFile(atPath: url.path) else { throw ConfigError("\(url.path): the audit log isn't writable") }
    }

    func record(_ event: String, user: String?, detail: String, from: String? = nil, time: Date = Date()) {
        // JSON encoding escapes line breaks, so a crafted path can't forge a line.
        guard var line = try? encoder.encode(Entry(time: time, event: event, user: user, detail: detail, from: from)) else { return }
        line.append(0x0A)
        lock.withLock {
            // Rotated away (logrotate) or deleted: start a new file rather than lose the entry.
            if !FileManager.default.fileExists(atPath: url.path) {
                _ = FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600])
            }
            guard let handle = try? FileHandle(forWritingTo: url) else { return }
            defer { try? handle.close() }
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: line)
        }
    }

    func entries() -> [Entry] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let text = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        return text.split(separator: "\n").compactMap { try? decoder.decode(Entry.self, from: Data($0.utf8)) }
    }
}

// MARK: - Policy sources

/// One tailnet's policy and devices, read from its server and kept for a
/// minute, so a page of requests is one fetch.
actor PolicySource {
    struct Snapshot {
        var text: String
        var tree: JSON?
        var model: PolicyModel?
        var parseError: HuJSONError?
        var nodes: [HeadscaleNode]
        /// Everyone the server knows, for the "not a user" check; nil when it couldn't be listed.
        var logins: Set<String>?
        var fetched: Date
        /// Why this is older than it should be, when the last refresh failed.
        var stale: String?
    }

    nonisolated let config: ServerConfig.Source
    private let client: PolicyServer
    private var cached: Snapshot?
    private var loading: Task<Snapshot, Error>?
    static let maxAge: TimeInterval = 60

    init(_ config: ServerConfig.Source, client: PolicyServer) {
        self.config = config
        self.client = client
    }

    func snapshot(now: Date = Date()) async throws -> Snapshot {
        if let cached, cached.stale == nil, now.timeIntervalSince(cached.fetched) < Self.maxAge { return cached }
        // Requests arriving together share one fetch.
        let task = loading ?? Task { try await Self.fetch(client) }
        loading = task
        do {
            let fresh = try await task.value
            loading = nil
            cached = fresh
            return fresh
        } catch {
            loading = nil
            // The server being down for a moment shouldn't blank the page: show the last good copy, marked.
            guard var old = cached else { throw error }
            old.stale = error.localizedDescription
            return old
        }
    }

    private static func outcome<T>(_ work: () async throws -> T) async -> Result<T, Error> {
        do { return .success(try await work()) } catch { return .failure(error) }
    }

    private static func fetch(_ client: PolicyServer) async throws -> Snapshot {
        // Both requests run to the end before either error is thrown: with
        // `try await (a, b)` a failure cancels the other request, and on Linux
        // cancelling a URLSession request can hang the caller for good.
        async let policy = outcome { try await client.getPolicy() }
        async let devices = outcome { try await client.listNodes() }
        let (policyResult, devicesResult) = await (policy, devices)
        let text = try policyResult.get(), nodes = try devicesResult.get()
        // Role autogroups (autogroup:admin…) come from the user list; without the scope they just don't match.
        let users = try? await client.serverUsers()
        var snapshot = Snapshot(text: text, nodes: nodes, logins: users?.logins, fetched: Date())
        do {
            let tree = try HuJSONParser.parse(text)
            var model = PolicyModel(tree: tree)
            model.userAutogroups = users?.autogroups ?? [:]
            snapshot.tree = tree
            snapshot.model = model
        } catch let error as HuJSONError {
            snapshot.parseError = error
        }
        return snapshot
    }
}

// MARK: - Server state

final class ServerState: Sendable {
    let origin: String
    let secure: Bool
    let login: EntraLogin?
    let local: LocalLogin?
    let devUser: SignedInUser?
    let roles: ServerConfig.Roles?
    let sessions = SessionStore()
    let sources: [PolicySource]
    let audit: AuditLog

    var sessionCookie: String { secure ? "__Host-tsacl_session" : "tsacl_session" }
    var loginCookie: String { secure ? "__Host-tsacl_login" : "tsacl_login" }

    init(config: ServerConfig, session: URLSession = serverSession, checkOnly: Bool = false) throws {
        guard let origin = config.origin else { throw ConfigError("publicURL: not a usable address") }
        self.origin = origin
        secure = config.isSecure
        roles = config.roles
        audit = try AuditLog(directory: config.dataDir, create: !checkOnly)
        local = config.localUsers.map(LocalLogin.init)
        if let dev = config.devLogin {
            devUser = SignedInUser(id: "dev", login: dev.login.lowercased(), name: dev.login, roles: Set(dev.roles.compactMap(Role.init(rawValue:))))
            login = nil
        } else if config.localUsers != nil {
            devUser = nil
            login = nil
        } else if let entra = config.entra {
            devUser = nil
            login = EntraLogin(tenant: entra.tenant.lowercased(), clientID: entra.clientID,
                               clientSecret: try secret(entra.clientSecret, file: entra.clientSecretFile),
                               redirectURI: origin + "/auth/callback", session: session)
        } else {
            throw ConfigError("entra or localUsers: missing")
        }
        sources = try config.sources.map { s in
            guard let client = makeServer(kind: s.kind, serverURL: s.serverURL ?? "", tailnet: s.tailnet ?? "-",
                                          credential: try secret(s.credential, file: s.credentialFile), session: session) else {
                throw ConfigError("sources[\(s.id)]: no usable server address or credential")
            }
            return PolicySource(s, client: client)
        }
    }

    func cookie(_ name: String, _ value: String, maxAge: Int) -> Cookie {
        Cookie(name: name, value: value, maxAge: maxAge, path: "/", secure: secure, httpOnly: true, sameSite: .lax)
    }

    func user(for request: Request) async -> SignedInUser? {
        guard let id = request.cookies[sessionCookie]?.value, !id.isEmpty else { return nil }
        return await sessions.user(for: id)
    }
}

extension ServerState {
    /// The tailnet named in the route's `:source`, read (or cached).
    func snapshot(_ context: AppContext) async throws -> PolicySource.Snapshot {
        let id = try context.parameters.require("source")
        guard let source = sources.first(where: { $0.config.id == id }) else { throw HTTPError(.notFound, message: "No such tailnet.") }
        do {
            return try await source.snapshot()
        } catch {
            // What the control server said is for the operator's log, not for every viewer.
            context.logger.error("source \(id): \(error.localizedDescription)")
            throw HTTPError(.badGateway, message: "The tailnet's server couldn't be read.")
        }
    }
}

func requireModel(_ snapshot: PolicySource.Snapshot) throws -> PolicyModel {
    guard let model = snapshot.model else { throw HTTPError(.conflict, message: "The policy on the server has a syntax error.") }
    return model
}

struct AppContext: RequestContext {
    var coreContext: CoreRequestContextStorage
    var user: SignedInUser?

    init(source: ApplicationRequestContextSource) {
        coreContext = .init(source: source)
    }
}

/// The address the proxy says the request came from. Only for the audit
/// log: the header is whatever the proxy (or a direct caller) sent.
private func forwardedFor(_ request: Request) -> String? {
    guard let name = HTTPField.Name("X-Forwarded-For"), let value = request.headers[name] else { return nil }
    return String(value.prefix(100))
}

/// A form post from this site's own pages: the browser says so with Origin,
/// or — when it sends Origin: null — with Sec-Fetch-Site, which pages can't set.
func postedFromThisSite(_ request: Request, origin: String) -> Bool {
    if let sent = request.headers[.origin], sent != "null" { return sent == origin }
    guard let name = HTTPField.Name("Sec-Fetch-Site") else { return false }
    return request.headers[name] == "same-origin"
}

// MARK: - Middleware

/// Headers that keep the pages from being framed, sniffed, or cached with
/// someone's data in them — on errors too.
struct SecurityHeaders: RouterMiddleware {
    typealias Context = AppContext
    let secure: Bool

    func handle(_ request: Request, context: Context, next: (Request, Context) async throws -> Response) async throws -> Response {
        var response: Response
        do {
            response = try await next(request, context)
        } catch let error as HTTPResponseError {
            response = try error.response(from: request, context: context)
        }
        response.headers[.xContentTypeOptions] = "nosniff"
        response.headers[.cacheControl] = "no-store"
        response.headers[.contentSecurityPolicy] = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        if let name = HTTPField.Name("X-Frame-Options") { response.headers[name] = "DENY" }
        // Nothing to other sites. (With no-referrer, browsers post forms with Origin: null.)
        if let name = HTTPField.Name("Referrer-Policy") { response.headers[name] = "same-origin" }
        if secure { response.headers[.strictTransportSecurity] = "max-age=31536000" }
        return response
    }
}

/// Lets only signed-in people with the role through, and writes each of
/// their requests to the audit log.
struct RequireRole: RouterMiddleware {
    typealias Context = AppContext
    let state: ServerState
    let role: Role

    func handle(_ request: Request, context: Context, next: (Request, Context) async throws -> Response) async throws -> Response {
        guard let user = await state.user(for: request) else {
            throw HTTPError(.unauthorized, message: "Sign in at /login")
        }
        let what = "\(request.method.rawValue) \(request.uri.string.prefix(400))"
        guard user.roles.contains(role) else {
            state.audit.record("denied", user: user.login, detail: what, from: forwardedFor(request))
            throw HTTPError(.forbidden, message: "Your account isn't allowed to do this.")
        }
        var context = context
        context.user = user
        do {
            let response = try await next(request, context)
            state.audit.record("request", user: user.login, detail: "\(what) → \(response.status.code)", from: forwardedFor(request))
            return response
        } catch {
            let status = (error as? HTTPResponseError)?.status.code ?? 500
            state.audit.record("request", user: user.login, detail: "\(what) → \(status)", from: forwardedFor(request))
            throw error
        }
    }
}

// MARK: - API answers

struct MeReply: ResponseEncodable { var login: String; var name: String; var roles: [String] }

struct SourcesReply: ResponseEncodable {
    struct Source: Encodable { var id: String; var name: String; var kind: String }
    var sources: [Source]
}

struct PolicyReply: ResponseEncodable {
    struct ParseError: Encodable { var line: Int; var message: String }
    var text: String
    var valid: Bool
    var error: ParseError?
    var fetched: Date
    var stale: String?
}

struct ProblemsReply: ResponseEncodable {
    struct Problem: Encodable { var severity: String; var title: String; var detail: String; var line: Int?; var security: Bool }
    var problems: [Problem]
    var stale: String?
}

/// Names for the pickers, with what each one is.
struct EntitiesReply: ResponseEncodable {
    struct Named: Encodable { var name: String; var detail: [String] }
    var users: [String]
    var groups: [Named]
    var tags: [Named]
    var hosts: [Named]
    var ipsets: [Named]
    var autogroups: [String]
}

/// The Access Map for one entity: the rules that apply to it, and what they
/// reach (or, reached by, who they let in).
struct MapReply: ResponseEncodable {
    struct Entity: Encodable { var name: String; var label: String; var subtitle: String }
    struct Rule: Encodable {
        var id: String
        var kind: String
        var index: Int
        var name: String
        var badge: String
        var sources: [String]
        var destinations: [String]
        var notes: [String]
        var explanation: String?
        var line: Int?
    }
    struct Routes: Encodable {
        struct Subnet: Encodable { var route: String; var routers: [String] }
        var exitNode: Bool
        var exitVia: [String]
        var exitNodes: [String]
        var subnets: [Subnet]
    }
    var focus: Entity
    var direction: String
    var rules: [Rule]
    /// The far column, in order: what the rules reach, or who they let in.
    var endpoints: [Entity]
    var routes: Routes?
    var stale: String?
}

struct DevicesReply: ResponseEncodable {
    var stale: String?
    struct Device: Encodable {
        var id: String
        var name: String
        var user: String?
        var tags: [String]
        var addresses: [String]
        var online: Bool
        var lastSeen: Date?
    }
    var devices: [Device]
}

struct SimulateReply: ResponseEncodable {
    struct Rule: Encodable {
        var kind: String
        var index: Int
        var src: String
        var dst: String
        var ports: String?
        /// Postures the source device must meet for this rule to count.
        var posture: [String]
        var via: [String]
        var explanation: String?
        var line: Int?
    }
    var allowed: Bool
    /// Allowed only if the source device meets a posture.
    var conditional: Bool
    var rules: [Rule]
    var stale: String?
}

// MARK: - Routes

func buildRouter(_ state: ServerState) -> Router<AppContext> {
    let router = Router(context: AppContext.self)
    router.add(middleware: SecurityHeaders(secure: state.secure))

    router.get("healthz") { _, _ in "ok" }

    router.get("login") { request, _ -> Response in
        let returnTo = safeReturnPath(request.uri.queryParameters.get("return"))
        if let dev = state.devUser {
            let id = await state.sessions.signIn(dev)
            state.audit.record("login", user: dev.login, detail: "development login", from: forwardedFor(request))
            var response = Response(status: .found, headers: [.location: returnTo])
            response.setCookie(state.cookie(state.sessionCookie, id, maxAge: Int(SessionStore.sessionLifetime)))
            return response
        }
        if state.local != nil { return localLoginPage(returnTo: returnTo) }
        guard let login = state.login else { throw HTTPError(.internalServerError) }
        let nonce = randomToken(), verifier = randomToken()
        guard let pending = await state.sessions.begin(nonce: nonce, verifier: verifier, returnTo: returnTo) else {
            throw HTTPError(.tooManyRequests, message: "Too many sign-ins under way; try again in a few minutes.")
        }
        let url = login.authorizeURL(state: pending, nonce: nonce, challenge: pkceChallenge(verifier))
        var response = Response(status: .found, headers: [.location: url.absoluteString])
        // Ties this sign-in to this browser: the callback must carry the same state in its cookie.
        response.setCookie(state.cookie(state.loginCookie, pending, maxAge: Int(SessionStore.pendingLifetime)))
        return response
    }

    router.post("login") { request, context -> Response in
        guard let local = state.local else { throw HTTPError(.notFound) }
        // Only this site's own form: a sign-in posted from elsewhere is refused.
        guard postedFromThisSite(request, origin: state.origin) else {
            state.audit.record("login-failed", user: nil, detail: "form posted from another site (\(request.headers[.origin] ?? "no Origin"))",
                               from: forwardedFor(request))
            return localLoginPage(returnTo: "/", message: "That sign-in didn't come from this page. Try again here.", status: .forbidden)
        }
        let body = try await request.body.collect(upTo: 8_192)
        let form = parseForm(String(buffer: body))
        let returnTo = safeReturnPath(form["return"])
        let name = String((form["username"] ?? "").prefix(200))
        switch await local.check(login: name, password: form["password"] ?? "") {
        case .signedIn(let user):
            let id = await state.sessions.signIn(user)
            state.audit.record("login", user: user.login,
                               detail: "local account, roles: \(user.roles.map(\.rawValue).sorted().joined(separator: ", "))",
                               from: forwardedFor(request))
            var response = Response(status: .seeOther, headers: [.location: returnTo])
            response.setCookie(state.cookie(state.sessionCookie, id, maxAge: Int(SessionStore.sessionLifetime)))
            return response
        case .wrong(let reason):
            state.audit.record("login-failed", user: name.lowercased(), detail: reason, from: forwardedFor(request))
            return localLoginPage(returnTo: returnTo, message: "Wrong user name or password.", status: .unauthorized)
        case .throttled:
            state.audit.record("login-failed", user: name.lowercased(), detail: "too many attempts", from: forwardedFor(request))
            return localLoginPage(returnTo: returnTo, message: "Too many failed attempts. Wait 15 minutes and try again.",
                                  status: .tooManyRequests)
        }
    }

    router.get("auth/callback") { request, _ -> Response in
        guard let login = state.login else { throw HTTPError(.notFound) }
        let query = request.uri.queryParameters
        let from = forwardedFor(request)
        func refuse(_ status: HTTPResponse.Status, _ shown: String, log: String) -> Response {
            state.audit.record("login-failed", user: nil, detail: log, from: from)
            var response = Response(status: status, headers: [.contentType: "text/plain; charset=utf-8"],
                                    body: .init(byteBuffer: .init(string: shown + "\nStart again at /login\n")))
            response.setCookie(state.cookie(state.loginCookie, "", maxAge: 0))
            return response
        }
        if let error = query.get("error") {
            return refuse(.badRequest, "Microsoft didn't complete the sign-in.",
                          log: "Microsoft: \(error): \(String((query.get("error_description") ?? "").prefix(300)))")
        }
        guard let code = query.get("code"), let stateParameter = query.get("state"),
              let cookie = request.cookies[state.loginCookie]?.value, !cookie.isEmpty, cookie == stateParameter,
              let pending = await state.sessions.finish(state: stateParameter) else {
            return refuse(.badRequest, "This sign-in wasn't started in this browser, or it took too long.", log: "state mismatch or expired")
        }
        let claims: IDTokenClaims
        do {
            claims = try login.validate(idToken: try await login.exchange(code: code, verifier: pending.verifier), nonce: pending.nonce)
        } catch {
            return refuse(.badGateway, "Signing in with Microsoft failed.", log: error.localizedDescription)
        }
        let granted = roles(for: claims, state.roles)
        let person = user(from: claims, roles: granted)
        guard !granted.isEmpty else {
            return refuse(.forbidden, "You're signed in to Microsoft as \(person.login), but that account has no access here.",
                          log: "\(person.login) has no role")
        }
        let id = await state.sessions.signIn(person)
        state.audit.record("login", user: person.login, detail: "roles: \(granted.map(\.rawValue).sorted().joined(separator: ", "))", from: from)
        var response = Response(status: .found, headers: [.location: pending.returnTo])
        response.setCookie(state.cookie(state.sessionCookie, id, maxAge: Int(SessionStore.sessionLifetime)))
        response.setCookie(state.cookie(state.loginCookie, "", maxAge: 0))
        return response
    }

    // POST, so another site can't sign people out with a link (the cookie is SameSite=Lax).
    router.post("logout") { request, _ -> Response in
        if let id = request.cookies[state.sessionCookie]?.value {
            if let user = await state.sessions.user(for: id) {
                state.audit.record("logout", user: user.login, detail: "", from: forwardedFor(request))
            }
            await state.sessions.signOut(id)
        }
        var response = Response(status: .seeOther, headers: [.location: "/"])
        response.setCookie(state.cookie(state.sessionCookie, "", maxAge: 0))
        return response
    }

    let api = router.group("api").add(middleware: RequireRole(state: state, role: .viewer))

    api.get("me") { _, context -> MeReply in
        guard let user = context.user else { throw HTTPError(.unauthorized) }
        return MeReply(login: user.login, name: user.name, roles: user.roles.map(\.rawValue).sorted())
    }

    api.get("sources") { _, _ in
        SourcesReply(sources: state.sources.map { .init(id: $0.config.id, name: $0.config.name, kind: $0.config.kind.rawValue) })
    }

    @Sendable func snapshot(_ context: AppContext) async throws -> PolicySource.Snapshot { try await state.snapshot(context) }
    @Sendable func model(_ snapshot: PolicySource.Snapshot) throws -> PolicyModel { try requireModel(snapshot) }

    api.get("sources/:source/policy") { _, context -> PolicyReply in
        let s = try await snapshot(context)
        return PolicyReply(text: s.text, valid: s.model != nil,
                           error: s.parseError.map { .init(line: $0.line, message: $0.message) }, fetched: s.fetched, stale: s.stale)
    }

    api.get("sources/:source/problems") { _, context -> ProblemsReply in
        let s = try await snapshot(context)
        let m = try model(s)
        // The same checks as the app's Problems screen with devices loaded.
        let issues = lintPolicy(m) + lintNodes(m, nodes: s.nodes) + lintUsers(m, logins: s.logins)
        return ProblemsReply(problems: issues.map { issue in
            .init(severity: issue.severity == .error ? "error" : "warning", title: issue.title, detail: issue.detail,
                  line: issue.line ?? issue.path.flatMap { s.tree?.line(at: $0) }, security: issue.security)
        }, stale: s.stale)
    }

    api.get("sources/:source/devices") { _, context -> DevicesReply in
        let s = try await snapshot(context)
        return DevicesReply(stale: s.stale, devices: s.nodes.map { n in
            .init(id: n.id, name: n.displayName, user: n.user?.email ?? n.user?.name, tags: n.allTags,
                  addresses: n.ipAddresses ?? [], online: n.online == true, lastSeen: n.lastSeenDate)
        })
    }

    // ?src=…&dst=…&port=443[&proto=tcp] — src and dst are policy names
    // (a user, group, tag, host, address) or node:<device id>.
    api.get("sources/:source/simulate") { request, context -> SimulateReply in
        let s = try await snapshot(context)
        let m = try model(s)
        let query = request.uri.queryParameters
        guard let src = query.get("src"), let dst = query.get("dst"), !src.isEmpty, !dst.isEmpty, src.count <= 256, dst.count <= 256 else {
            throw HTTPError(.badRequest, message: "Give src and dst.")
        }
        let port = query.get("port").map { Int($0) ?? -1 } ?? 443
        guard (0...65_535).contains(port) else { throw HTTPError(.badRequest, message: "port must be 0–65535.") }
        var proto: Int?
        if let name = query.get("proto"), !name.isEmpty {
            guard let number = Evaluator.protoNumber(name) else { throw HTTPError(.badRequest, message: "Unknown proto.") }
            proto = number
        }
        func device(_ selection: String) throws -> HeadscaleNode? {
            guard selection.hasPrefix("node:") else { return nil }
            guard let node = s.nodes.first(where: { $0.id == selection.dropFirst(5) }) else {
                throw HTTPError(.badRequest, message: "No device \(selection).")
            }
            return node
        }
        let source = try device(src), destination = try device(dst)
        // From the device list only os and version are known, so other posture conditions stay "conditional".
        let result = Evaluator(model: m, sourceAttributes: source?.postureAttributes, proto: proto)
            .evaluate(sourceIDs: source?.identities ?? [src], destIDs: destination?.identities ?? [dst], port: port)
        return SimulateReply(allowed: result.allowed, conditional: result.conditional, rules: result.matches.map { match in
            let kind: RuleSummary.Kind = match.kind == .grant ? .grant : .acl
            return .init(kind: match.kind == .grant ? "grant" : "acl", index: match.ruleIndex, src: match.srcSpec, dst: match.dstSpec,
                         ports: match.ipSpec, posture: match.posture, via: match.via,
                         explanation: ruleExplanation(m, kind: kind, index: match.ruleIndex),
                         line: s.tree?.line(at: "\(match.kind == .grant ? "grants" : "acls")[\(match.ruleIndex)]"))
        }, stale: s.stale)
    }

    api.get("sources/:source/entities") { _, context -> EntitiesReply in
        let m = try model(try await snapshot(context))
        return EntitiesReply(
            users: m.allUsers,
            groups: m.groupOrder.map { .init(name: $0, detail: m.groups[$0] ?? []) },
            tags: m.tagOrder.map { .init(name: $0, detail: m.tagOwners[$0] ?? []) },
            hosts: m.hostOrder.map { .init(name: $0, detail: [m.hosts[$0] ?? ""]) },
            ipsets: m.ipsetOrder.map { .init(name: $0, detail: m.ipsets[$0] ?? []) },
            autogroups: EditorVocabulary.autogroups.map(\.0))
    }

    // ?focus=<policy name, or node:<device id>>&direction=reaches|reachedBy
    api.get("sources/:source/map") { request, context -> MapReply in
        let s = try await snapshot(context)
        let m = try model(s)
        let query = request.uri.queryParameters
        guard let focus = query.get("focus"), !focus.isEmpty, focus.count <= 256 else { throw HTTPError(.badRequest, message: "Give focus.") }
        let reaches = query.get("direction") != "reachedBy"
        var ids = [focus], label = focus, subtitle = entitySubtitle(focus, model: m, nodes: s.nodes)
        if focus.hasPrefix("node:") {
            guard let node = s.nodes.first(where: { $0.id == focus.dropFirst(5) }) else { throw HTTPError(.badRequest, message: "No device \(focus).") }
            ids = node.identities
            label = node.displayName
            subtitle = ([node.online == true ? "online" : "offline"] + node.allTags + [node.user?.email ?? node.user?.name].compactMap { $0 })
                .joined(separator: " · ")
        }
        let summaries = reaches ? ruleSummaries(m, sourceIDs: ids) : ruleSummaries(m, sourceIDs: nil, destIDs: ids)
        let far = summaries.flatMap { reaches ? $0.destinations : $0.sources }.uniqued()
        var routes: MapReply.Routes?
        if reaches, !s.nodes.isEmpty {
            let r = routeAccess(m, sourceIDs: ids, nodes: s.nodes)
            routes = .init(exitNode: r.exitNode, exitVia: r.exitVia, exitNodes: r.exitNodes,
                           subnets: r.subnets.map { .init(route: $0.route, routers: $0.routers) })
        }
        return MapReply(
            focus: .init(name: focus, label: label, subtitle: subtitle),
            direction: reaches ? "reaches" : "reachedBy",
            rules: summaries.map { r in
                .init(id: r.id, kind: "\(r.kind)", index: r.index, name: r.name, badge: r.badge, sources: r.sources,
                      destinations: r.destinations, notes: r.notes, explanation: ruleExplanation(m, kind: r.kind, index: r.index),
                      line: s.tree?.line(at: "\(r.section)[\(r.index)]"))
            },
            endpoints: far.map { .init(name: $0, label: $0, subtitle: entitySubtitle($0, model: m, nodes: s.nodes)) },
            routes: routes, stale: s.stale)
    }

    addViewRoutes(to: api, state: state)

    // The web interface: the page for signed-in people, the files for everyone (they hold no data).
    @Sendable func page(_ request: Request) async -> Response {
        guard await state.user(for: request) != nil else {
            let back = safeReturnPath(request.uri.string)
            return Response(status: .found, headers: [.location: "/login?return=" + (back.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? "/")])
        }
        return asset(PackageResources.index_html, "text/html; charset=utf-8")
    }
    router.get("/") { request, _ in await page(request) }
    router.get("s/:source/:view") { request, _ in await page(request) }
    router.get("app.js") { _, _ in asset(PackageResources.app_js, "text/javascript; charset=utf-8") }
    router.get("style.css") { _, _ in asset(PackageResources.style_css, "text/css; charset=utf-8") }
    router.get("favicon.svg") { _, _ in asset(PackageResources.favicon_svg, "image/svg+xml") }

    return router
}

private func asset(_ bytes: [UInt8], _ type: String) -> Response {
    Response(status: .ok, headers: [.contentType: type], body: .init(byteBuffer: .init(bytes: bytes)))
}

// MARK: - Command

private let serveUsage = """
usage: tailscale-acl serve --config <server.json>   run the web service
       tailscale-acl serve --config <server.json> --check   check the config and exit
       --insecure-dev-login   honour the config's devLogin (localhost only; never in production)
       tailscale-acl hash-password   a bcrypt hash for the config's localUsers
"""

/// `tailscale-acl serve …`; returns the exit code.
func runServeCommand(_ args: [String], output: (String) -> Void = { print($0) }) async -> Int32 {
    var path: String?
    var check = false, devLogin = false
    var rest = args[...]
    while let arg = rest.popFirst() {
        switch arg {
        case "--config": path = rest.popFirst()
        case "--check": check = true
        case "--insecure-dev-login": devLogin = true
        default:
            output(serveUsage)
            return 2
        }
    }
    guard let path else {
        output(serveUsage)
        return 2
    }
    do {
        let config = try ServerConfig.load(path)
        let problems = config.problems(devLoginAllowed: devLogin)
        guard problems.isEmpty else {
            problems.forEach { output("\(path): \($0)") }
            return 1
        }
        let secretFiles = [path] + [config.entra?.clientSecretFile].compactMap { $0 } + config.sources.compactMap(\.credentialFile)
        for file in readableByOthers(secretFiles) {
            output("warning: \(file) can be read by other accounts on this machine (chmod 600 it)")
        }
        if config.devLogin != nil { output("warning: development login is ON — everyone who can reach this is signed in without Microsoft") }
        if config.tls == nil, let host = config.listenAddress?.host, !["127.0.0.1", "localhost", "::1"].contains(host) {
            output("warning: listening on \(host), not the loopback address — put a TLS proxy in front and firewall the port")
        }
        let state = try ServerState(config: config, checkOnly: check)
        if check {
            let signIn = config.localUsers.map { "\($0.count) local account\($0.count == 1 ? "" : "s")" }
                ?? (config.devLogin != nil ? "development login" : "sign-in redirect \(state.origin)/auth/callback")
            output("\(path): ok — \(config.sources.count) tailnet\(config.sources.count == 1 ? "" : "s"), \(signIn)")
            return 0
        }
        let address = config.listenAddress!
        let configuration = ApplicationConfiguration(address: .hostname(address.host, port: address.port))
        let app: any ApplicationProtocol
        if let tls = config.tls {
            let tlsConfiguration = TLSConfiguration.makeServerConfiguration(
                certificateChain: try NIOSSLCertificate.fromPEMFile(tls.certificateFile).map { .certificate($0) },
                privateKey: .privateKey(try NIOSSLPrivateKey(file: tls.keyFile, format: .pem)))
            app = Application(router: buildRouter(state), server: try .tls(.http1(), tlsConfiguration: tlsConfiguration),
                              configuration: configuration)
        } else {
            app = Application(router: buildRouter(state), configuration: configuration)
        }
        output("tailscale-acl: serving \(state.origin) on \(address.host):\(address.port)")
        try await app.runService()
        return 0
    } catch {
        output("tailscale-acl serve: \(error.localizedDescription)")
        return 1
    }
}
