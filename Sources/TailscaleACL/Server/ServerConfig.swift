import Foundation

/// What `tailscale-acl serve` reads from its JSON config file.
struct ServerConfig: Decodable {
    /// host:port to listen on. Keep it on the loopback address, behind a
    /// proxy that does TLS (e.g. `tailscale serve`). Default 127.0.0.1:8080.
    var listen: String?
    /// The address people open, e.g. https://acl.example.ts.net — the
    /// sign-in redirect and the cookie rules follow from it.
    var publicURL: String
    /// Where the audit log is kept.
    var dataDir: String
    /// Sign in with Microsoft Entra ID…
    var entra: Entra?
    /// …or with accounts listed here (one or the other).
    var localUsers: [LocalUser]?
    /// Serve HTTPS directly with this certificate, instead of behind a proxy.
    var tls: TLS?
    var roles: Roles?
    var sources: [Source]
    /// Sign in without Microsoft, for development on localhost only (also
    /// needs --insecure-dev-login).
    var devLogin: DevLogin?

    /// Microsoft Entra ID app registration (web platform, redirect URI
    /// <publicURL>/auth/callback).
    struct Entra: Decodable {
        /// The tenant's ID (a GUID) — not a domain name, and not "common".
        var tenant: String
        var clientID: String
        var clientSecret: String?
        var clientSecretFile: String?
    }

    /// Which values of the ID token's `roles` (app roles) or `groups` (group
    /// object IDs) claims give each role. Approvers are viewers too.
    struct Roles: Decodable {
        var viewer: [String]?
        var approver: [String]?
    }

    /// A tailnet to show: a Tailscale tailnet or a Headscale server.
    struct Source: Decodable {
        /// In URLs: lowercase letters, digits, dashes.
        var id: String
        var name: String
        var kind: ServerKind
        var serverURL: String?
        var tailnet: String?
        var credential: String?
        var credentialFile: String?
    }

    struct TLS: Decodable {
        var certificateFile: String
        var keyFile: String
    }

    struct DevLogin: Decodable {
        var login: String
        var roles: [String]
    }

    static func load(_ path: String) throws -> ServerConfig {
        guard let data = FileManager.default.contents(atPath: path) else {
            throw ConfigError("\(path): cannot read the config file")
        }
        do {
            return try JSONDecoder().decode(ServerConfig.self, from: data)
        } catch let error as DecodingError {
            throw ConfigError("\(path): \(describe(error))")
        }
    }

    private static func describe(_ error: DecodingError) -> String {
        func at(_ c: DecodingError.Context) -> String { c.codingPath.map(\.stringValue).joined(separator: ".") }
        switch error {
        case .keyNotFound(let key, let c): return "missing \"\((c.codingPath.map(\.stringValue) + [key.stringValue]).joined(separator: "."))\""
        case .typeMismatch(_, let c), .valueNotFound(_, let c): return "wrong kind of value at \"\(at(c))\""
        case .dataCorrupted(let c): return c.codingPath.isEmpty ? "not valid JSON" : "bad value at \"\(at(c))\""
        @unknown default: return "\(error)"
        }
    }

    // MARK: - Derived

    var listenAddress: (host: String, port: Int)? {
        let parts = (listen ?? "127.0.0.1:8080").split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count >= 2, let port = Int(parts[parts.count - 1]), (1...65_535).contains(port) else { return nil }
        let host = parts.dropLast().joined(separator: ":")
        return host.isEmpty ? nil : (host, port)
    }

    /// The public URL without a trailing slash, when it's a usable http(s) origin.
    var origin: String? {
        guard let c = URLComponents(string: publicURL), let scheme = c.scheme?.lowercased(), ["http", "https"].contains(scheme),
              let host = c.host, !host.isEmpty, (c.path.isEmpty || c.path == "/"), c.query == nil else { return nil }
        return "\(scheme)://\(host)" + (c.port.map { ":\($0)" } ?? "")
    }

    var isSecure: Bool { origin?.hasPrefix("https://") == true }
    var isLocalhost: Bool {
        guard let host = URLComponents(string: publicURL)?.host?.lowercased() else { return false }
        return ["localhost", "127.0.0.1", "[::1]", "::1"].contains(host)
    }

    /// Everything wrong with the config, in words. Empty: good to start.
    func problems(devLoginAllowed: Bool) -> [String] {
        var out: [String] = []
        if listenAddress == nil { out.append("listen: expected host:port, e.g. 127.0.0.1:8080") }
        if origin == nil {
            out.append("publicURL: expected an address like https://acl.example.ts.net (no path)")
        } else if !isSecure && !isLocalhost {
            out.append("publicURL: must be https — over plain http the sign-in cookie could be read on the way (http is for localhost only)")
        }
        if dataDir.isEmpty { out.append("dataDir: where should the audit log go?") }

        let modes = [devLogin != nil, entra != nil, localUsers != nil].filter { $0 }.count
        if modes > 1 { out.append("entra, localUsers, devLogin: use one way of signing in, not several") }
        if let tls {
            if !isSecure { out.append("tls: the publicURL must then start with https://") }
            for file in [tls.certificateFile, tls.keyFile] where !FileManager.default.isReadableFile(atPath: file) {
                out.append("tls: cannot read \(file)")
            }
        }

        if let devLogin {
            if !devLoginAllowed {
                out.append("devLogin: signs everyone in without Microsoft. Remove it, or pass --insecure-dev-login on localhost.")
            } else if !isLocalhost {
                out.append("devLogin: only with a localhost publicURL")
            }
            if devLogin.roles.contains(where: { Role(rawValue: $0) == nil }) { out.append("devLogin.roles: use \"viewer\" and \"approver\"") }
        } else if let entra {
            // The token's issuer contains the tenant's ID, so a domain name or "common" can't be checked against it.
            if UUID(uuidString: entra.tenant) == nil { out.append("entra.tenant: use the tenant ID (a GUID), not a domain name or \"common\"") }
            if entra.clientID.isEmpty { out.append("entra.clientID: missing") }
            if (try? secret(entra.clientSecret, file: entra.clientSecretFile))?.isEmpty != false {
                out.append("entra: give clientSecretFile (a file holding only the secret) or clientSecret")
            }
            if (roles?.viewer ?? []).isEmpty && (roles?.approver ?? []).isEmpty {
                out.append("roles: nobody could sign in — list the app roles or group IDs for viewer and approver")
            }
        } else if let localUsers {
            if localUsers.isEmpty { out.append("localUsers: nobody could sign in — add an account") }
            var logins = Set<String>()
            for (i, u) in localUsers.enumerated() {
                let label = "localUsers[\(i)]"
                if u.login.trimmingCharacters(in: .whitespaces).isEmpty { out.append("\(label).login: missing") }
                if !logins.insert(u.login.lowercased()).inserted { out.append("\(label).login: \(u.login) is listed twice") }
                if !u.isBcryptHash { out.append("\(label).passwordHash: not a bcrypt hash — make one with: tailscale-acl hash-password") }
                if u.roles.isEmpty || u.roles.contains(where: { Role(rawValue: $0) == nil }) {
                    out.append("\(label).roles: use \"viewer\" and/or \"approver\"")
                }
            }
        } else {
            out.append("entra or localUsers: missing — how people sign in (Microsoft Entra ID, or accounts listed here)")
        }

        if sources.isEmpty { out.append("sources: add at least one tailnet") }
        var seen = Set<String>()
        for s in sources {
            let label = "sources[\(s.id)]"
            if s.id.isEmpty || s.id.count > 40 || !s.id.allSatisfy({ $0.isASCII && ($0.isLowercase || $0.isNumber || $0 == "-") }) {
                out.append("\(label).id: lowercase letters, digits, and dashes only")
            }
            if !seen.insert(s.id).inserted { out.append("\(label).id: used twice") }
            if s.kind == .headscale, URL(string: s.serverURL ?? "")?.host == nil { out.append("\(label).serverURL: the Headscale server's address") }
            if (try? secret(s.credential, file: s.credentialFile))?.isEmpty != false {
                out.append("\(label): give credentialFile (a file holding only the API key or OAuth client secret) or credential")
            }
        }
        return out
    }
}

struct ConfigError: LocalizedError {
    var message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

/// A secret given inline or, better, as the path of a file that holds only it.
func secret(_ inline: String?, file: String?) throws -> String {
    guard let file, !file.isEmpty else { return inline ?? "" }
    guard let data = FileManager.default.contents(atPath: file), let text = String(data: data, encoding: .utf8) else {
        throw ConfigError("\(file): cannot read the secret file")
    }
    return text.trimmingCharacters(in: .whitespacesAndNewlines)
}

/// Paths among the config's files that other accounts on the machine can
/// read: anyone at all, or a group other than this process's own or the
/// service's (root owning a file the tailscale-acl group reads is the
/// intended layout, and root runs the check too).
func readableByOthers(_ paths: [String], ownGroups: Set<UInt32> = serviceGroups()) -> [String] {
    paths.filter { path in
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
              let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue else { return false }
        let group = (attributes[.groupOwnerAccountID] as? NSNumber)?.uint32Value
        return mode & 0o007 != 0 || (mode & 0o070 != 0 && !ownGroups.contains(group ?? .max))
    }
}

func serviceGroups() -> Set<UInt32> {
    var groups: Set<UInt32> = [UInt32(getegid())]
    if let entry = getgrnam("tailscale-acl") { groups.insert(UInt32(entry.pointee.gr_gid)) }
    return groups
}
