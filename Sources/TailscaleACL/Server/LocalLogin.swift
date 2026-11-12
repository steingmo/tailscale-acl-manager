import Foundation
import Hummingbird
import HummingbirdBcrypt

// Signing in with accounts listed in the config (user name, bcrypt hash,
// roles), for running on a LAN before Microsoft sign-in is set up.

/// One account in the config's `localUsers`.
struct LocalUser: Decodable {
    var login: String
    var name: String?
    /// bcrypt, from `tailscale-acl hash-password`. Never the password itself.
    var passwordHash: String
    var roles: [String]

    var isBcryptHash: Bool {
        passwordHash.count == 60 && ["$2a$", "$2b$", "$2y$"].contains(String(passwordHash.prefix(4)))
    }
}

/// Checks passwords, and slows down guessing: an account with five failed
/// attempts in 15 minutes is refused until they age out, and more than 30
/// failures a minute across all accounts refuses everyone for a minute.
/// ponytail: in memory, so a restart forgets the counts; fine for a LAN tool.
actor LocalLogin {
    static let perAccount = (attempts: 5, window: TimeInterval(15 * 60))
    static let overall = (attempts: 30, window: TimeInterval(60))

    enum Outcome: Equatable {
        case signedIn(SignedInUser)
        case wrong(String)      // the reason, for the audit log only
        case throttled
    }

    private let users: [String: LocalUser]
    /// Checked when the user name is unknown, so that takes as long as a wrong password.
    private let decoy: String
    private var failures: [String: [Date]] = [:]
    private var recent: [Date] = []

    init(_ users: [LocalUser]) {
        self.users = Dictionary(users.map { ($0.login.lowercased(), $0) }, uniquingKeysWith: { a, _ in a })
        let cost = users.first.flatMap { UInt8($0.passwordHash.dropFirst(4).prefix(2)) } ?? 12
        decoy = Bcrypt.hash(randomToken(), cost: min(max(cost, 4), 31))
    }

    func check(login rawLogin: String, password: String, now: Date = Date()) async -> Outcome {
        let login = rawLogin.trimmingCharacters(in: .whitespaces).lowercased()
        recent = recent.filter { now.timeIntervalSince($0) < Self.overall.window }
        let mine = (failures[login] ?? []).filter { now.timeIntervalSince($0) < Self.perAccount.window }
        failures[login] = mine
        if mine.count >= Self.perAccount.attempts || recent.count >= Self.overall.attempts { return .throttled }

        let user = users[login]
        let matches = await Self.verify(password, hash: user?.passwordHash ?? decoy)
        guard let user, matches else {
            failures[login, default: []].append(now)
            recent.append(now)
            return .wrong(user == nil ? "unknown user" : "wrong password")
        }
        failures[login] = nil
        return .signedIn(SignedInUser(id: "local:\(login)", login: login, name: user.name ?? user.login,
                                      roles: Set(user.roles.compactMap(Role.init(rawValue:)))))
    }

    /// bcrypt is slow on purpose, so off Swift's cooperative threads.
    private static func verify(_ password: String, hash: String) async -> Bool {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: Bcrypt.verify(password, hash: hash))
            }
        }
    }
}

// MARK: - The sign-in page

private func escapeHTML(_ s: String) -> String {
    s.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
        .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
        .replacingOccurrences(of: "'", with: "&#39;")
}

/// The form. Only constant text and the escaped return path go into it.
func localLoginPage(returnTo: String, message: String? = nil, status: HTTPResponse.Status = .ok) -> Response {
    let html = """
    <!doctype html>
    <html lang="en">
    <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign in · Tailscale ACL</title>
    <link rel="icon" href="/favicon.svg" type="image/svg+xml">
    <link rel="stylesheet" href="/style.css">
    </head>
    <body class="login-page">
    <form class="login card" method="post" action="/login">
      <div class="brand"><img src="/favicon.svg" alt="" width="22" height="22"><span>Tailscale ACL</span></div>
      \(message.map { "<p class=\"banner error\" role=\"alert\">\(escapeHTML($0))</p>" } ?? "")
      <label>User name <input type="text" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus></label>
      <label>Password <input type="password" name="password" autocomplete="current-password" required></label>
      <input type="hidden" name="return" value="\(escapeHTML(returnTo))">
      <button type="submit" class="primary">Sign in</button>
    </form>
    </body>
    </html>
    """
    return Response(status: status, headers: [.contentType: "text/html; charset=utf-8"],
                    body: .init(byteBuffer: .init(string: html)))
}

/// `application/x-www-form-urlencoded` into fields.
func parseForm(_ body: String) -> [String: String] {
    var out: [String: String] = [:]
    for pair in body.split(separator: "&") {
        let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        func decode(_ s: Substring) -> String { s.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? "" }
        guard let key = parts.first else { continue }
        out[decode(key)] = parts.count > 1 ? decode(parts[1]) : ""
    }
    return out
}

// MARK: - tailscale-acl hash-password

/// Reads a password (twice, without echo, on a terminal; one line otherwise)
/// and prints its bcrypt hash for the config's `localUsers`.
func runHashPasswordCommand(interactive: Bool = isatty(0) != 0,
                            readLine read: () -> String? = { Swift.readLine(strippingNewline: true) },
                            output: (String) -> Void = { print($0) }) -> Int32 {
    func ask(_ prompt: String) -> String? {
        if interactive, let p = getpass(prompt) { return String(cString: p) }
        return read()
    }
    guard let password = ask("Password: "), password.count >= 12 else {
        output("Use at least 12 characters.")
        return 1
    }
    if interactive {
        guard ask("Again: ") == password else {
            output("The two didn't match.")
            return 1
        }
    }
    output(Bcrypt.hash(password, cost: 12))
    return 0
}
