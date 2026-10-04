import Foundation

/// Which control server a workspace talks to.
enum ServerKind: String, Codable, CaseIterable {
    case headscale
    case tailscale
}

/// What the app needs from a control server. Headscale and Tailscale both
/// implement it, so every server feature works the same with either.
protocol PolicyServer: AnyObject {
    /// Shown in the UI and recorded in push history.
    var displayHost: String { get }
    func getPolicy() async throws -> String
    func setPolicy(_ policy: String) async throws
    /// The server's own verdict on a policy (and its tests) without saving it,
    /// or nil when the server has no such check (Headscale).
    func validate(_ policy: String) async throws -> ValidationReport?
    /// Users that can own auth keys (Headscale); empty when keys don't need one.
    func listUsers() async throws -> [ServerUser]
    /// Create a pre-authorized key for joining devices. Returns the secret,
    /// which the server shows only once.
    func createAuthKey(_ request: AuthKeyRequest) async throws -> String
    func listNodes() async throws -> [HeadscaleNode]
    func setTags(nodeID: String, tags: [String]) async throws
    /// Replaces the device's whole list of approved routes.
    func setApprovedRoutes(nodeID: String, routes: [String]) async throws
    /// Expire the device's key now: it must log in again to reconnect.
    func expireNode(nodeID: String) async throws
    /// Remove the device from the tailnet.
    func deleteNode(nodeID: String) async throws
    func renameNode(nodeID: String, name: String) async throws
    /// Who changed the policy on the server in the last `days` days, newest
    /// first; nil when the server keeps no audit log (Headscale).
    func policyChanges(days: Int) async throws -> [PolicyChange]?
    /// The server's users: to spot group members who are no longer users,
    /// and (Tailscale) to know who holds a role.
    func serverUsers() async throws -> ServerUsers
    func deleteUser(id: String) async throws
    // Declared here (with defaults below) so calls dispatch to each server.
    func listInvites() async throws -> [PendingInvite]
    func invite(email: String, role: String) async throws -> PendingInvite
    func resendInvite(id: String) async throws
    func cancelInvite(id: String) async throws
    func createUser(name: String, displayName: String, email: String) async throws -> ServerAccount
    func setRole(userID: String, role: String) async throws
    func approveUser(id: String) async throws
    func suspendUser(id: String) async throws
    func restoreUser(id: String) async throws
}

struct ServerUsers {
    var accounts: [ServerAccount] = []

    /// Every name a policy can use for a user (emails, "name@"), lowercased.
    var logins: Set<String> { Set(accounts.flatMap(\.policyNames)) }

    /// Lowercased login → the role autogroups it belongs to, e.g.
    /// ["autogroup:admin"] or ["autogroup:shared"]. Empty for Headscale.
    var autogroups: [String: Set<String>] {
        var out: [String: Set<String>] = [:]
        for a in accounts {
            var groups = Set<String>()
            if let role = a.role, Evaluator.roleAutogroups.contains("autogroup:\(role)") { groups.insert("autogroup:\(role)") }
            if a.isShared { groups.insert("autogroup:shared") }
            guard !groups.isEmpty else { continue }
            for name in a.policyNames { out[name] = groups }
        }
        return out
    }
}

/// A user on the control server.
struct ServerAccount: Identifiable, Equatable {
    var id: String
    /// How a policy names the user: their email, or "name@" on Headscale.
    var login: String
    var displayName: String
    /// Every lowercased name a policy may use for this user.
    var policyNames: [String]
    /// Tailscale: owner, admin, member, it-admin, network-admin, billing-admin, auditor.
    var role: String?
    /// Tailscale: active, idle, suspended, needs-approval, over-billing-limit.
    var status: String?
    var isShared = false
    var deviceCount: Int?
    var lastSeen: String?
}

/// A Tailscale invite nobody has accepted yet.
struct PendingInvite: Identifiable {
    var id: String
    var email: String
    var role: String
    var lastEmailSentAt: String?
    var inviteURL: String?
}

/// User management the app offers. Each server supports part of it:
/// Tailscale invites people and manages roles; Headscale creates users.
extension PolicyServer {
    private func unsupported(_ what: String) -> ServerError {
        ServerError(status: 0, message: "\(displayHost) doesn't support \(what).")
    }
    func listInvites() async throws -> [PendingInvite] { [] }
    func invite(email: String, role: String) async throws -> PendingInvite { throw unsupported("invites") }
    func resendInvite(id: String) async throws { throw unsupported("invites") }
    func cancelInvite(id: String) async throws { throw unsupported("invites") }
    func createUser(name: String, displayName: String, email: String) async throws -> ServerAccount {
        throw unsupported("creating users directly — invite them instead")
    }
    func setRole(userID: String, role: String) async throws { throw unsupported("user roles") }
    func approveUser(id: String) async throws { throw unsupported("user approval") }
    func suspendUser(id: String) async throws { throw unsupported("suspending users") }
    func restoreUser(id: String) async throws { throw unsupported("suspending users") }
}

struct PolicyChange: Identifiable {
    var date: Date
    var who: String
    /// How it was changed, e.g. "admin console" or "API".
    var origin: String
    var id: String { "\(date.timeIntervalSince1970)-\(who)" }
}

/// The server for a workspace's settings and credential, or nil if not configured.
func makeServer(kind: ServerKind, serverURL: String, tailnet: String, credential: String,
                session: URLSession = .shared) -> PolicyServer? {
    guard !credential.isEmpty else { return nil }
    switch kind {
    case .headscale:
        guard let url = URL(string: serverURL.trimmingCharacters(in: .whitespaces)),
              url.scheme != nil, url.host != nil else { return nil }
        return HeadscaleClient(baseURL: url, apiKey: credential, session: session)
    case .tailscale:
        return TailscaleClient(tailnet: tailnet, credential: credential, session: session)
    }
}

/// Display name for a workspace's server; must match the client's `displayHost`
/// because push history is filtered by it.
func serverName(kind: ServerKind, serverURL: String, tailnet: String) -> String {
    switch kind {
    case .headscale:
        return URL(string: serverURL.trimmingCharacters(in: .whitespaces))?.host ?? ""
    case .tailscale:
        let t = tailnet.trimmingCharacters(in: .whitespaces)
        return t.isEmpty || t == "-" ? "Tailscale" : "Tailscale (\(t))"
    }
}

/// A server's validation verdict: nil message means the policy and its tests pass.
struct ValidationReport {
    var message: String?
    /// Failing test sources and their errors.
    var failures: [(user: String, errors: [String])] = []

    var passed: Bool { message == nil }
    var summary: String {
        ([message ?? "Passed"] + failures.prefix(5).flatMap { f in f.errors.map { "\(f.user): \($0)" } })
            .joined(separator: " · ")
    }
}

struct ServerUser: Identifiable, Hashable {
    var id: String
    var name: String
}

struct AuthKeyRequest {
    var tags: [String]
    var reusable = false
    var ephemeral = false
    /// Tailscale: devices joining with the key skip device approval.
    var preauthorized = true
    var expiry: TimeInterval = 86_400
    /// Headscale user id; optional when tags are given.
    var user: String?
}

struct ServerError: LocalizedError {
    var status: Int
    var message: String
    var errorDescription: String? { message }
}

/// Throws a `ServerError` for non-2xx responses, using the body's "message"
/// when it's JSON and the raw text otherwise.
func checkResponse(_ data: Data, _ response: URLResponse) throws -> HTTPURLResponse {
    guard let http = response as? HTTPURLResponse else {
        throw ServerError(status: 0, message: "No HTTP response from server.")
    }
    guard (200..<300).contains(http.statusCode) else {
        let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        let detail = (json?["message"] as? String)
            ?? String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        throw ServerError(status: http.statusCode,
                          message: "HTTP \(http.statusCode): \(detail.isEmpty ? "request failed" : detail)")
    }
    return http
}

// MARK: - Tailscale

/// Client for the official Tailscale API (api.tailscale.com/api/v2).
/// Accepts a personal API access token (tskey-api-…) or an OAuth client
/// secret (tskey-client-…), which is exchanged for short-lived tokens.
final class TailscaleClient: PolicyServer {
    static let base = "https://api.tailscale.com/api/v2/"

    let tailnet: String
    private let credential: String
    private let session: URLSession
    private var accessToken: (value: String, expires: Date)?
    /// ETag of the policy last read. Sent as If-Match on the next write, so
    /// Tailscale refuses the push if someone changed the policy in between.
    private var etag: String?

    init(tailnet: String, credential: String, session: URLSession = .shared) {
        let t = tailnet.trimmingCharacters(in: .whitespaces)
        self.tailnet = t.isEmpty ? "-" : t
        self.credential = credential
        self.session = session
    }

    var displayHost: String { serverName(kind: .tailscale, serverURL: "", tailnet: tailnet) }

    private var tailnetPath: String {
        "tailnet/\(tailnet.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? tailnet)"
    }

    func getPolicy() async throws -> String {
        let (data, http) = try await request("GET", "\(tailnetPath)/acl", accept: "application/hujson")
        etag = http.value(forHTTPHeaderField: "ETag")
        return String(decoding: data, as: UTF8.self)
    }

    func setPolicy(_ policy: String) async throws {
        var headers = ["Content-Type": "application/hujson"]
        if let etag { headers["If-Match"] = etag }
        do {
            let (_, http) = try await request("POST", "\(tailnetPath)/acl", body: Data(policy.utf8),
                                              headers: headers, accept: "application/hujson")
            etag = http.value(forHTTPHeaderField: "ETag")
        } catch let error as ServerError where error.status == 412 {
            throw ServerError(status: 412, message: "The policy changed on Tailscale after the app read it, so nothing was pushed. Review the push again to see the latest version.")
        }
    }

    func validate(_ policy: String) async throws -> ValidationReport? {
        let (data, _) = try await request("POST", "\(tailnetPath)/acl/validate", body: Data(policy.utf8),
                                          headers: ["Content-Type": "application/hujson"])
        // An empty body (or no message) means the policy and its tests pass.
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let message = json["message"] as? String, !message.isEmpty else { return ValidationReport() }
        let failures = (json["data"] as? [[String: Any]] ?? []).map { entry in
            (user: entry["user"] as? String ?? "", errors: entry["errors"] as? [String] ?? [])
        }
        return ValidationReport(message: message, failures: failures)
    }

    /// Tailscale auth keys don't take a user: they belong to the token's user,
    /// or to the tailnet (tags required) when made with an OAuth client.
    func listUsers() async throws -> [ServerUser] { [] }

    func createAuthKey(_ r: AuthKeyRequest) async throws -> String {
        let body: [String: Any] = [
            "description": "Created with Tailscale ACL app",
            "expirySeconds": Int(r.expiry),
            "capabilities": ["devices": ["create": [
                "reusable": r.reusable, "ephemeral": r.ephemeral,
                "preauthorized": r.preauthorized, "tags": r.tags,
            ]]],
        ]
        let (data, _) = try await request("POST", "\(tailnetPath)/keys",
                                          body: try JSONSerialization.data(withJSONObject: body),
                                          headers: ["Content-Type": "application/json"])
        struct Key: Decodable { var key: String }
        return try JSONDecoder().decode(Key.self, from: data).key
    }

    func listNodes() async throws -> [HeadscaleNode] {
        struct Device: Decodable {
            var id: String
            var nodeId: String?
            var name: String?
            var hostname: String?
            var addresses: [String]?
            var user: String?
            var tags: [String]?
            var lastSeen: String?
            var connectedToControl: Bool?
            var advertisedRoutes: [String]?
            var enabledRoutes: [String]?
            var expires: String?
            var keyExpiryDisabled: Bool?
            var os: String?
            var clientVersion: String?
        }
        struct Response: Decodable { var devices: [Device]? }
        let (data, _) = try await request("GET", "\(tailnetPath)/devices?fields=all")
        return (try JSONDecoder().decode(Response.self, from: data).devices ?? []).map { d in
            HeadscaleNode(id: d.nodeId ?? d.id, name: d.name, givenName: d.hostname,
                          ipAddresses: d.addresses,
                          user: d.user.map { HeadscaleNode.User(name: $0, email: $0) },
                          online: d.connectedToControl, lastSeen: d.lastSeen,
                          availableRoutes: d.advertisedRoutes, approvedRoutes: d.enabledRoutes,
                          tags: d.tags, expiry: d.keyExpiryDisabled == true ? nil : d.expires,
                          os: d.os, clientVersion: d.clientVersion)
        }
    }

    func expireNode(nodeID: String) async throws {
        _ = try await request("POST", "device/\(nodeID)/expire")
    }

    /// Needs the users:read scope. Roles map to autogroup:owner, :admin,
    /// :it-admin, :network-admin, :billing-admin, :auditor; users shared in
    /// from other tailnets to autogroup:shared.
    func serverUsers() async throws -> ServerUsers {
        let (data, _) = try await request("GET", "\(tailnetPath)/users")
        let users = (try JSONSerialization.jsonObject(with: data) as? [String: Any])?["users"] as? [[String: Any]] ?? []
        return ServerUsers(accounts: users.compactMap { u in
            guard let login = u["loginName"] as? String else { return nil }
            let id = (u["id"] as? String) ?? (u["id"] as? NSNumber)?.stringValue ?? login
            return ServerAccount(id: id, login: login, displayName: u["displayName"] as? String ?? login,
                                 policyNames: [login.lowercased()], role: u["role"] as? String,
                                 status: u["status"] as? String, isShared: u["type"] as? String == "shared",
                                 deviceCount: u["deviceCount"] as? Int, lastSeen: u["lastSeen"] as? String)
        })
    }

    // Invites need a personal access token: Tailscale only lets a user invite.
    func listInvites() async throws -> [PendingInvite] {
        let (data, _) = try await request("GET", "\(tailnetPath)/user-invites")
        return (try JSONSerialization.jsonObject(with: data) as? [[String: Any]] ?? []).compactMap(Self.invite)
    }

    func invite(email: String, role: String) async throws -> PendingInvite {
        let body = try JSONSerialization.data(withJSONObject: [["email": email, "role": role]])
        let (data, _) = try await request("POST", "\(tailnetPath)/user-invites", body: body,
                                          headers: ["Content-Type": "application/json"])
        guard let first = (try JSONSerialization.jsonObject(with: data) as? [[String: Any]])?.first,
              let invite = Self.invite(first) else {
            throw ServerError(status: 0, message: "Tailscale didn't return the invite.")
        }
        return invite
    }

    private static func invite(_ j: [String: Any]) -> PendingInvite? {
        guard let id = (j["id"] as? String) ?? (j["id"] as? NSNumber)?.stringValue else { return nil }
        return PendingInvite(id: id, email: j["email"] as? String ?? "", role: j["role"] as? String ?? "member",
                             lastEmailSentAt: j["lastEmailSentAt"] as? String, inviteURL: j["inviteUrl"] as? String)
    }

    func resendInvite(id: String) async throws { _ = try await request("POST", "user-invites/\(id)/resend") }
    func cancelInvite(id: String) async throws { _ = try await request("DELETE", "user-invites/\(id)") }

    func setRole(userID: String, role: String) async throws {
        _ = try await request("POST", "users/\(userID)/role",
                              body: try JSONSerialization.data(withJSONObject: ["role": role]),
                              headers: ["Content-Type": "application/json"])
    }
    func approveUser(id: String) async throws { _ = try await request("POST", "users/\(id)/approve") }
    func suspendUser(id: String) async throws { _ = try await request("POST", "users/\(id)/suspend") }
    func restoreUser(id: String) async throws { _ = try await request("POST", "users/\(id)/restore") }
    func deleteUser(id: String) async throws { _ = try await request("POST", "users/\(id)/delete") }

    /// From the configuration audit log (needs the logs:configuration:read scope).
    func policyChanges(days: Int) async throws -> [PolicyChange]? {
        let iso = ISO8601DateFormatter()
        let end = Date()
        var query = URLComponents()
        query.queryItems = [
            URLQueryItem(name: "start", value: iso.string(from: end.addingTimeInterval(-Double(days) * 86_400))),
            URLQueryItem(name: "end", value: iso.string(from: end)),
            URLQueryItem(name: "event", value: "TAILNET.UPDATE.ACL"),
        ]
        let (data, _) = try await request("GET", "\(tailnetPath)/logging/configuration?\(query.percentEncodedQuery ?? "")")
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let logs = (try JSONSerialization.jsonObject(with: data) as? [String: Any])?["logs"] as? [[String: Any]] ?? []
        return logs.compactMap { log -> PolicyChange? in
            guard (log["target"] as? [String: Any])?["property"] as? String == "ACL",
                  let time = log["eventTime"] as? String,
                  let date = fractional.date(from: time) ?? iso.date(from: time) else { return nil }
            let actor = log["actor"] as? [String: Any] ?? [:]
            let who = [actor["displayName"], actor["loginName"], actor["type"]]
                .compactMap { $0 as? String }.first { !$0.isEmpty } ?? "unknown"
            let origin = (log["origin"] as? String).map {
                ["ADMIN_CONSOLE": "admin console", "CONFIG_API": "API"][$0] ?? $0.lowercased().replacingOccurrences(of: "_", with: " ")
            } ?? ""
            return PolicyChange(date: date, who: who, origin: origin)
        }
        .sorted { $0.date > $1.date }
    }

    func deleteNode(nodeID: String) async throws {
        _ = try await request("DELETE", "device/\(nodeID)")
    }

    func renameNode(nodeID: String, name: String) async throws {
        _ = try await request("POST", "device/\(nodeID)/name",
                              body: try JSONSerialization.data(withJSONObject: ["name": name]),
                              headers: ["Content-Type": "application/json"])
    }

    func setTags(nodeID: String, tags: [String]) async throws {
        _ = try await request("POST", "device/\(nodeID)/tags",
                              body: try JSONSerialization.data(withJSONObject: ["tags": tags]),
                              headers: ["Content-Type": "application/json"])
    }

    func setApprovedRoutes(nodeID: String, routes: [String]) async throws {
        _ = try await request("POST", "device/\(nodeID)/routes",
                              body: try JSONSerialization.data(withJSONObject: ["routes": routes]),
                              headers: ["Content-Type": "application/json"])
    }

    // MARK: Auth + transport

    /// OAuth client secrets look like tskey-client-<client id>-<secret>.
    private var oauthClientID: String? {
        guard credential.hasPrefix("tskey-client-") else { return nil }
        return credential.dropFirst("tskey-client-".count).split(separator: "-").first.map(String.init)
    }

    private func bearerToken() async throws -> String {
        guard let clientID = oauthClientID else { return credential }
        if let token = accessToken, token.expires > Date().addingTimeInterval(60) { return token.value }
        var req = URLRequest(url: URL(string: Self.base + "oauth/token")!)
        req.httpMethod = "POST"
        req.timeoutInterval = 15
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        var form = URLComponents()
        form.queryItems = [URLQueryItem(name: "client_id", value: clientID),
                           URLQueryItem(name: "client_secret", value: credential)]
        req.httpBody = Data((form.percentEncodedQuery ?? "").utf8)
        let (data, response) = try await session.data(for: req)
        _ = try checkResponse(data, response)
        struct Token: Decodable {
            var access_token: String
            var expires_in: Double?
        }
        let token = try JSONDecoder().decode(Token.self, from: data)
        accessToken = (token.access_token, Date().addingTimeInterval(token.expires_in ?? 3600))
        return token.access_token
    }

    private func request(_ method: String, _ path: String, body: Data? = nil,
                         headers: [String: String] = [:], accept: String = "application/json")
        async throws -> (Data, HTTPURLResponse) {
        guard let url = URL(string: Self.base + path) else {
            throw ServerError(status: 0, message: "Invalid tailnet name.")
        }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.timeoutInterval = 20
        req.setValue("Bearer \(try await bearerToken())", forHTTPHeaderField: "Authorization")
        req.setValue(accept, forHTTPHeaderField: "Accept")
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        req.httpBody = body
        let (data, response) = try await session.data(for: req)
        return (data, try checkResponse(data, response))
    }
}
