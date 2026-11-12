import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

// Signing in with Microsoft Entra ID: OpenID Connect, authorization code
// flow with PKCE, as a confidential client (the secret stays on the server).

enum Role: String, Codable, CaseIterable {
    case viewer    // look and simulate
    case approver  // also grant temporary access
}

struct SignedInUser: Codable, Equatable {
    /// The account's object ID in the tenant: stable, unlike the login name.
    var id: String
    var login: String
    var name: String
    var roles: Set<Role>
}

struct LoginError: LocalizedError, Equatable {
    var message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

/// The claims of an ID token this server reads.
struct IDTokenClaims: Decodable, Equatable {
    var iss: String
    var aud: String
    var tid: String?
    var exp: Double
    var nbf: Double?
    var nonce: String?
    var oid: String?
    var sub: String?
    var preferred_username: String?
    var email: String?
    var name: String?
    /// App roles assigned to the user (or to a group they're in).
    var roles: [String]?
    /// Group object IDs, when the app registration emits them. Missing for
    /// people in very many groups — app roles don't have that limit.
    var groups: [String]?
}

/// 32 random bytes, URL-safe. `SystemRandomNumberGenerator` is the system's
/// cryptographic generator on macOS and Linux.
func randomToken() -> String {
    var generator = SystemRandomNumberGenerator()
    return base64URL(Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) }))
}

func base64URL(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

func base64URLDecode(_ text: String) -> Data? {
    var s = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while s.count % 4 != 0 { s += "=" }
    return Data(base64Encoded: s)
}

/// PKCE: the challenge sent with the sign-in request for a verifier kept here.
func pkceChallenge(_ verifier: String) -> String {
    base64URL(Data(SHA256.hash(data: Data(verifier.utf8))))
}

private func formEncode(_ fields: [(String, String)]) -> Data {
    var allowed = CharacterSet.alphanumerics
    allowed.insert(charactersIn: "-._~")
    func enc(_ s: String) -> String { s.addingPercentEncoding(withAllowedCharacters: allowed) ?? "" }
    return Data(fields.map { "\(enc($0.0))=\(enc($0.1))" }.joined(separator: "&").utf8)
}

struct EntraLogin {
    var tenant: String
    var clientID: String
    var clientSecret: String
    /// <publicURL>/auth/callback, exactly as registered.
    var redirectURI: String
    var session: URLSession = .shared

    private var authority: String { "https://login.microsoftonline.com/\(tenant)" }

    /// Where the browser goes to sign in.
    func authorizeURL(state: String, nonce: String, challenge: String) -> URL {
        var c = URLComponents(string: "\(authority)/oauth2/v2.0/authorize")!
        c.queryItems = [
            .init(name: "client_id", value: clientID),
            .init(name: "response_type", value: "code"),
            .init(name: "redirect_uri", value: redirectURI),
            .init(name: "response_mode", value: "query"),
            .init(name: "scope", value: "openid profile email"),
            .init(name: "state", value: state),
            .init(name: "nonce", value: nonce),
            .init(name: "code_challenge", value: challenge),
            .init(name: "code_challenge_method", value: "S256"),
        ]
        return c.url!
    }

    /// Trades the code from the redirect for an ID token, server to server.
    func exchange(code: String, verifier: String) async throws -> String {
        var request = URLRequest(url: URL(string: "\(authority)/oauth2/v2.0/token")!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = formEncode([
            ("client_id", clientID), ("client_secret", clientSecret), ("grant_type", "authorization_code"),
            ("code", code), ("redirect_uri", redirectURI), ("code_verifier", verifier), ("scope", "openid profile email"),
        ])
        request.timeoutInterval = 20
        let (data, response) = try await session.data(for: request)
        struct Reply: Decodable { var id_token: String?; var error: String?; var error_description: String? }
        let reply = try? JSONDecoder().decode(Reply.self, from: data)
        guard (response as? HTTPURLResponse)?.statusCode == 200, let token = reply?.id_token else {
            // Microsoft's description says what's wrong with the registration; it holds no secrets.
            throw LoginError("Microsoft refused the sign-in: \(reply?.error_description ?? reply?.error ?? "no ID token in the answer")")
        }
        return token
    }

    /// Checks an ID token that came straight from Microsoft's token endpoint.
    /// ponytail: the signature isn't verified. OpenID Connect Core §3.1.3.7
    /// allows that for a token received directly from the token endpoint over
    /// TLS, which is the only way this server gets one; it saves an RSA and
    /// JWKS dependency. Verify it (e.g. with jwt-kit) if tokens ever arrive
    /// any other way — through the browser, or from a proxy.
    func validate(idToken: String, nonce: String, now: Date = Date()) throws -> IDTokenClaims {
        let parts = idToken.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, let payload = base64URLDecode(String(parts[1])),
              let claims = try? JSONDecoder().decode(IDTokenClaims.self, from: payload) else {
            throw LoginError("The ID token couldn't be read.")
        }
        let skew = 120.0
        guard claims.iss == "\(authority)/v2.0", claims.tid?.lowercased() == tenant.lowercased() else {
            throw LoginError("The ID token is from another tenant.")
        }
        guard claims.aud == clientID else { throw LoginError("The ID token is for another application.") }
        guard claims.exp > now.timeIntervalSince1970 - skew else { throw LoginError("The ID token has expired.") }
        guard (claims.nbf ?? 0) < now.timeIntervalSince1970 + skew else { throw LoginError("The ID token isn't valid yet.") }
        guard let got = claims.nonce, got == nonce else { throw LoginError("The ID token doesn't belong to this sign-in.") }
        guard claims.oid ?? claims.sub != nil else { throw LoginError("The ID token names nobody.") }
        return claims
    }
}

/// Roles from the token's app roles and group IDs. Approvers are viewers too.
func roles(for claims: IDTokenClaims, _ config: ServerConfig.Roles?) -> Set<Role> {
    let held = Set((claims.roles ?? []) + (claims.groups ?? []))
    var out = Set<Role>()
    if !held.isDisjoint(with: config?.approver ?? []) { out = [.viewer, .approver] }
    if !held.isDisjoint(with: config?.viewer ?? []) { out.insert(.viewer) }
    return out
}

func user(from claims: IDTokenClaims, roles: Set<Role>) -> SignedInUser {
    let login = claims.preferred_username ?? claims.email ?? claims.oid ?? claims.sub ?? ""
    return SignedInUser(id: claims.oid ?? claims.sub ?? login, login: login.lowercased(), name: claims.name ?? login, roles: roles)
}

/// A path on this site to return to after signing in — never another site.
func safeReturnPath(_ path: String?) -> String {
    guard let path, path.hasPrefix("/"), !path.hasPrefix("//"), !path.contains("\\"), !path.contains("\r"), !path.contains("\n"),
          path.count <= 512 else { return "/" }
    return path
}

/// Sign-ins under way and the sessions of those that finished. In memory:
/// ponytail: a restart signs everyone out (one redirect with SSO); move to
/// the database if sessions must survive restarts or there's more than one
/// server process.
actor SessionStore {
    struct Pending {
        var nonce: String
        var verifier: String
        var returnTo: String
        var expires: Date
    }
    struct Session {
        var user: SignedInUser
        var expires: Date
    }

    static let pendingLifetime: TimeInterval = 10 * 60
    /// A working day; then Microsoft is asked again, which also picks up role changes.
    static let sessionLifetime: TimeInterval = 8 * 3_600
    /// Starting a sign-in needs no login, so their number is bounded.
    static let maxPending = 2_000

    private var pending: [String: Pending] = [:]
    private var sessions: [String: Session] = [:]

    /// Starts a sign-in; returns its state, or nil when too many are under way.
    func begin(nonce: String, verifier: String, returnTo: String, now: Date = Date()) -> String? {
        pending = pending.filter { $0.value.expires > now }
        guard pending.count < Self.maxPending else { return nil }
        let state = randomToken()
        pending[state] = Pending(nonce: nonce, verifier: verifier, returnTo: returnTo, expires: now.addingTimeInterval(Self.pendingLifetime))
        return state
    }

    /// The sign-in for a state, once.
    func finish(state: String, now: Date = Date()) -> Pending? {
        guard let p = pending.removeValue(forKey: state), p.expires > now else { return nil }
        return p
    }

    func signIn(_ user: SignedInUser, now: Date = Date()) -> String {
        sessions = sessions.filter { $0.value.expires > now }
        let id = randomToken()
        sessions[id] = Session(user: user, expires: now.addingTimeInterval(Self.sessionLifetime))
        return id
    }

    func user(for id: String, now: Date = Date()) -> SignedInUser? {
        guard let s = sessions[id], s.expires > now else { return nil }
        return s.user
    }

    func signOut(_ id: String) {
        sessions[id] = nil
    }
}
