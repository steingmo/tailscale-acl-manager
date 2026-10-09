import Foundation
import Security

/// A node as returned by Headscale's `GET /api/v1/node`. Everything is
/// optional so older and newer server versions both decode.
struct HeadscaleNode: Codable, Identifiable {
    struct User: Codable {
        var name: String?
        var email: String?
    }

    var id: String
    var name: String?
    var givenName: String?
    var ipAddresses: [String]?
    var user: User?
    var online: Bool?
    var lastSeen: String?
    var availableRoutes: [String]?  // advertised by the device
    var approvedRoutes: [String]?
    var tags: [String]?        // newer versions
    var forcedTags: [String]?  // older versions
    var validTags: [String]?   // older versions
    var expiry: String?        // key expiry; nil or year 1 = never
    var os: String?            // Tailscale only
    var clientVersion: String? // Tailscale only, e.g. "1.76.1-t1234abcd"
    /// Tailscale: every posture attribute (node:, huntress:, custom:…), when
    /// loaded; then the set is complete and a missing attribute is unset.
    var attributes: [String: String]? = nil

    var displayName: String {
        if let g = givenName, !g.isEmpty { return g }
        return name ?? id
    }
    var allTags: [String] { ((tags ?? []) + (forcedTags ?? []) + (validTags ?? [])).uniqued() }

    /// How a policy refers to this device: its first tag, or its user.
    var policyName: String? {
        identities.first { $0.hasPrefix("tag:") || $0.contains("@") }
    }

    var lastSeenDate: Date? { Self.date(lastSeen) }

    /// When the device's key expires; nil if it never does.
    var expiryDate: Date? {
        Self.date(expiry).flatMap { $0.timeIntervalSince1970 > 0 ? $0 : nil }
    }

    /// Headscale sends nanosecond timestamps, which ISO8601DateFormatter can't
    /// parse, so the fraction is dropped.
    private static func date(_ s: String?) -> Date? {
        guard let s else { return nil }
        let trimmed = s.replacingOccurrences(of: #"\.\d+"#, with: "", options: .regularExpression)
        return ISO8601DateFormatter().date(from: trimmed)
    }

    /// Posture attributes known from the device list ("node:os",
    /// "node:tsVersion"); others (custom:…, node:osVersion…) stay unknown.
    var postureAttributes: [String: String] {
        var attrs = attributes ?? [:]
        if attrs["node:os"] == nil, let os, !os.isEmpty { attrs["node:os"] = os.lowercased() }
        if attrs["node:tsVersion"] == nil, let v = clientVersion?.split(separator: "-").first, !v.isEmpty {
            attrs["node:tsVersion"] = v.hasPrefix("v") ? String(v.dropFirst()) : String(v)
        }
        return attrs
    }

    /// An evaluator for this device as the source: exact when its attributes
    /// were loaded, otherwise posture-gated rules count as conditional.
    func evaluator(_ m: PolicyModel) -> Evaluator {
        Evaluator(model: m, sourceAttributes: attributes == nil ? nil : postureAttributes,
                  attributesComplete: attributes != nil)
    }

    /// Whether the device meets a posture; nil when that can't be told.
    func meets(_ conditions: [String]) -> Bool? {
        postureHolds(conditions, attrs: postureAttributes, complete: attributes != nil)
    }

    /// Offline and not seen for `days` days (or never).
    func isStale(days: Int = 30, now: Date = Date()) -> Bool {
        guard online != true else { return false }
        guard let seen = lastSeenDate else { return true }
        return now.timeIntervalSince(seen) > Double(days) * 86_400
    }

    /// Days until the key expires (negative once expired); nil if it never does.
    func keyDaysLeft(now: Date = Date()) -> Int? {
        expiryDate.map { Int(($0.timeIntervalSince(now) / 86_400).rounded(.down)) }
    }

    /// "online", "last seen 3 hr. ago", or "offline".
    var statusText: String {
        if online == true { return "online" }
        guard let date = lastSeenDate else { return "offline" }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .short
        return "last seen \(f.localizedString(for: date, relativeTo: Date()))"
    }

    /// Policy identities this node matches as, following Tailscale semantics:
    /// a tagged node is its tags (it loses its user identity); an untagged
    /// node is its user. Its IPs are always included so host, IP set, and
    /// CIDR selectors match too.
    var identities: [String] {
        var ids = allTags
        if ids.isEmpty, let user {
            // Headscale policies name users as "name@" or by email.
            ids = [user.email, user.name, user.name.map { $0.contains("@") ? $0 : "\($0)@" }]
                .compactMap { $0 }
                .filter { !$0.isEmpty }
        }
        return (ids + (ipAddresses ?? [])).uniqued()
    }
}

/// Client for the Headscale REST API (`/api/v1`, Bearer API key).
final class HeadscaleClient: PolicyServer {
    let baseURL: URL
    private let apiKey: String
    private let session: URLSession

    init(baseURL: URL, apiKey: String, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.apiKey = apiKey
        self.session = session
    }

    var displayHost: String { serverName(kind: .headscale, serverURL: baseURL.absoluteString, tailnet: "") }

    func getPolicy() async throws -> String {
        struct Response: Decodable { var policy: String? }
        let data = try await send("GET", "policy")
        return try JSONDecoder().decode(Response.self, from: data).policy ?? ""
    }

    /// Headscale validates the policy server-side and applies it immediately.
    /// Requires `policy.mode: database` in the server config.
    func setPolicy(_ policy: String) async throws {
        _ = try await send("PUT", "policy", body: ["policy": policy])
    }

    /// Headscale has no validate-only endpoint; it validates on push.
    func validate(_ policy: String) async throws -> ValidationReport? { nil }

    func listUsers() async throws -> [ServerUser] {
        let data = try await send("GET", "user")
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        // Ids are uint64, sent as strings by newer servers and numbers by older ones.
        return (json?["users"] as? [[String: Any]] ?? []).compactMap { u in
            guard let id = (u["id"] as? String) ?? (u["id"] as? NSNumber)?.stringValue else { return nil }
            return ServerUser(id: id, name: (u["name"] as? String) ?? (u["email"] as? String) ?? id)
        }
    }

    func createAuthKey(_ r: AuthKeyRequest) async throws -> String {
        var body: [String: any Encodable] = [
            "reusable": r.reusable, "ephemeral": r.ephemeral,
            "expiration": ISO8601DateFormatter().string(from: Date().addingTimeInterval(r.expiry)),
            "aclTags": r.tags,
        ]
        if let user = r.user { body["user"] = user }
        let data = try await send("POST", "preauthkey", body: body)
        struct Response: Decodable {
            struct Key: Decodable { var key: String }
            var preAuthKey: Key
        }
        return try JSONDecoder().decode(Response.self, from: data).preAuthKey.key
    }

    func setApprovedRoutes(nodeID: String, routes: [String]) async throws {
        _ = try await send("POST", "node/\(nodeID)/approve_routes", body: ["routes": routes])
    }

    /// Headscale requires at least one tag, and a user-owned device that gets
    /// tags becomes a tagged device.
    func setTags(nodeID: String, tags: [String]) async throws {
        _ = try await send("POST", "node/\(nodeID)/tags", body: ["tags": tags])
    }

    /// An empty body expires the key now; the device must log in again.
    func expireNode(nodeID: String) async throws {
        _ = try await send("POST", "node/\(nodeID)/expire")
    }

    func deleteNode(nodeID: String) async throws {
        _ = try await send("DELETE", "node/\(nodeID)")
    }

    /// Policies name Headscale users by email or as "name@".
    /// Headscale has no roles. Policies name its users by email or "name@".
    func serverUsers() async throws -> ServerUsers {
        let data = try await send("GET", "user")
        let users = (try JSONSerialization.jsonObject(with: data) as? [String: Any])?["users"] as? [[String: Any]] ?? []
        return ServerUsers(accounts: users.compactMap(Self.account))
    }

    private static func account(_ u: [String: Any]) -> ServerAccount? {
        guard let id = (u["id"] as? String) ?? (u["id"] as? NSNumber)?.stringValue else { return nil }
        let name = (u["name"] as? String) ?? ""
        let email = (u["email"] as? String) ?? ""
        var names: [String] = []
        for v in [email, name].map({ $0.lowercased() }) where !v.isEmpty {
            names.append(v)
            if !v.contains("@") { names.append(v + "@") }
        }
        let login = !email.isEmpty ? email : name.contains("@") ? name : name + "@"
        let display = (u["displayName"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? name
        return ServerAccount(id: id, login: login, displayName: display, policyNames: names.uniqued())
    }

    func createUser(name: String, displayName: String, email: String) async throws -> ServerAccount {
        var body: [String: any Encodable] = ["name": name]
        if !displayName.isEmpty { body["displayName"] = displayName }
        if !email.isEmpty { body["email"] = email }
        let data = try await send("POST", "user", body: body)
        guard let user = (try JSONSerialization.jsonObject(with: data) as? [String: Any])?["user"] as? [String: Any],
              let account = Self.account(user) else {
            throw ServerError(status: 0, message: "Headscale didn't return the new user.")
        }
        return account
    }

    func deleteUser(id: String) async throws {
        _ = try await send("DELETE", "user/\(id)")
    }

    /// The API key's expiry, found by its prefix ("hskey-api-<prefix>-…", or
    /// "<prefix>.…" for keys made by older Headscale versions).
    func credentialInfo() async throws -> CredentialInfo? {
        let prefix = apiKey.hasPrefix("hskey-api-")
            ? String(apiKey.dropFirst("hskey-api-".count).prefix(12))
            : String(apiKey.split(separator: ".").first ?? "")
        let data = try await send("GET", "apikey")
        let keys = (try JSONSerialization.jsonObject(with: data) as? [String: Any])?["apiKeys"] as? [[String: Any]] ?? []
        let mine = keys.first { ($0["prefix"] as? String) == prefix }
        return CredentialInfo(kind: "Headscale API key", scopes: nil,
                              expires: (mine?["expiration"] as? String).flatMap { TailscaleClient.date($0) })
    }

    /// Headscale keeps no audit log.
    func policyChanges(days: Int) async throws -> [PolicyChange]? { nil }

    /// `name` must be a hostname-style name (no "/"); the server validates it.
    func renameNode(nodeID: String, name: String) async throws {
        _ = try await send("POST", "node/\(nodeID)/rename/\(name)")
    }

    func listNodes() async throws -> [HeadscaleNode] {
        struct Response: Decodable { var nodes: [HeadscaleNode]? }
        let data = try await send("GET", "node")
        return try JSONDecoder().decode(Response.self, from: data).nodes ?? []
    }

    private func send(_ method: String, _ path: String,
                      body: [String: any Encodable]? = nil) async throws -> Data {
        var req = URLRequest(url: baseURL.appendingPathComponent("api/v1/\(path)"))
        req.httpMethod = method
        req.timeoutInterval = 15
        req.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        if let body {
            req.httpBody = try JSONSerialization.data(withJSONObject: body)
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let (data, response) = try await session.data(for: req)
        _ = try checkResponse(data, response)
        return data
    }
}

/// Server credentials (Headscale API keys, Tailscale tokens or OAuth client
/// secrets) live in the login keychain (one per workspace id),
/// never in UserDefaults or the workspace file.
enum HeadscaleKeychain {
    /// Account used before workspaces existed; migrated on first launch.
    static let legacyAccount = "api-key"

    private static func query(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.local.tailscale-acl-manager.headscale",
            kSecAttrAccount as String: account,
        ]
    }

    static func load(account: String) -> String? {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Saving an empty key deletes the item.
    static func save(_ key: String, account: String) {
        SecItemDelete(query(account) as CFDictionary)
        guard !key.isEmpty else { return }
        var q = query(account)
        q[kSecValueData as String] = Data(key.utf8)
        SecItemAdd(q as CFDictionary, nil)
    }
}
