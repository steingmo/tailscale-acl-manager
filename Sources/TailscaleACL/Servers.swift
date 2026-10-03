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
        }
        struct Response: Decodable { var devices: [Device]? }
        let (data, _) = try await request("GET", "\(tailnetPath)/devices?fields=all")
        return (try JSONDecoder().decode(Response.self, from: data).devices ?? []).map { d in
            HeadscaleNode(id: d.nodeId ?? d.id, name: d.name, givenName: d.hostname,
                          ipAddresses: d.addresses,
                          user: d.user.map { HeadscaleNode.User(name: $0, email: $0) },
                          online: d.connectedToControl, lastSeen: d.lastSeen,
                          availableRoutes: d.advertisedRoutes, approvedRoutes: d.enabledRoutes,
                          tags: d.tags)
        }
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
