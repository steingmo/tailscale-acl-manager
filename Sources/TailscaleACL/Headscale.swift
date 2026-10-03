import Foundation
import Security

/// A node as returned by Headscale's `GET /api/v1/node`. Everything is
/// optional so older and newer server versions both decode.
struct HeadscaleNode: Decodable, Identifiable {
    struct User: Decodable {
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

    var displayName: String {
        if let g = givenName, !g.isEmpty { return g }
        return name ?? id
    }
    var allTags: [String] { ((tags ?? []) + (forcedTags ?? []) + (validTags ?? [])).uniqued() }

    /// How a policy refers to this device: its first tag, or its user.
    var policyName: String? {
        identities.first { $0.hasPrefix("tag:") || $0.contains("@") }
    }

    /// Headscale sends nanosecond timestamps, which ISO8601DateFormatter can't
    /// parse, so the fraction is dropped.
    var lastSeenDate: Date? {
        guard let s = lastSeen else { return nil }
        let trimmed = s.replacingOccurrences(of: #"\.\d+"#, with: "", options: .regularExpression)
        return ISO8601DateFormatter().date(from: trimmed)
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

/// Minimal client for the Headscale REST API (`/api/v1`, Bearer API key).
struct HeadscaleClient {
    var baseURL: URL
    var apiKey: String

    struct APIError: LocalizedError {
        var message: String
        var errorDescription: String? { message }
    }

    /// Client for a server URL + API key, or nil if either is missing/invalid.
    static func make(serverURL: String, apiKey: String) -> HeadscaleClient? {
        guard let url = URL(string: serverURL.trimmingCharacters(in: .whitespaces)),
              url.scheme != nil, url.host != nil, !apiKey.isEmpty else { return nil }
        return HeadscaleClient(baseURL: url, apiKey: apiKey)
    }

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

    /// Replace a device's tags. Headscale requires at least one tag, and a
    /// user-owned device that gets tags becomes a tagged device.
    func setTags(nodeID: String, tags: [String]) async throws {
        _ = try await send("POST", "node/\(nodeID)/tags", body: ["tags": tags])
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
        let (data, response) = try await URLSession.shared.data(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw APIError(message: "No HTTP response from server.")
        }
        guard (200..<300).contains(http.statusCode) else {
            // grpc-gateway errors are {"code": n, "message": "..."}; auth failures are plain text.
            let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            let detail = (json?["message"] as? String)
                ?? String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            throw APIError(message: "HTTP \(http.statusCode): \(detail.isEmpty ? "request failed" : detail)")
        }
        return data
    }
}

/// Headscale API keys live in the login keychain (one per workspace id),
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
