import Foundation
import AppKit
import SwiftUI
import LocalAuthentication

// MARK: - Settings

enum SecuritySettings {
    static let requireAuthKey = "requireAuthForChanges"
    static let clearSecretsKey = "clearCopiedSecrets"

    /// Touch ID or the login password before any change to a live server.
    static var requireAuth: Bool {
        UserDefaults.standard.object(forKey: requireAuthKey) as? Bool ?? true
    }

    static var clearCopiedSecrets: Bool {
        UserDefaults.standard.object(forKey: clearSecretsKey) as? Bool ?? true
    }
}

// MARK: - Touch ID before changes

/// Asks for Touch ID (or the login password) before a change to a live
/// server. One approval covers changes in the next two minutes, so a bulk
/// action or a review-then-push asks once.
@MainActor
enum Authorizer {
    private static var approvedUntil = Date.distantPast
    static let grace: TimeInterval = 120

    static func confirm(_ reason: String) async throws {
        guard Date() >= approvedUntil else { return }
        let context = LAContext()
        var error: NSError?
        // A Mac with no password or Touch ID can't ask; don't lock the user out.
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { return }
        do {
            try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
            approvedUntil = Date().addingTimeInterval(grace)
        } catch {
            throw ServerError(status: 0, message: "Not changed: the change wasn't confirmed with Touch ID or your password.")
        }
    }
}

// MARK: - Clipboard for secrets

/// Copies a secret (auth key, invite link) so clipboard managers skip it
/// (the nspasteboard.org "concealed" marker), and clears it after a minute
/// unless something else was copied meanwhile.
@MainActor
enum SecureClipboard {
    static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    static let clearAfter: TimeInterval = 60

    static func copy(_ secret: String) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.declareTypes([.string, concealed], owner: nil)
        pb.setString(secret, forType: .string)
        pb.setString("", forType: concealed)
        guard SecuritySettings.clearCopiedSecrets else { return }
        let count = pb.changeCount
        Task {
            try? await Task.sleep(nanoseconds: UInt64(clearAfter * 1_000_000_000))
            if pb.changeCount == count { pb.clearContents() }
        }
    }
}

// MARK: - Unencrypted connections

/// An http:// server other than this Mac: the API key would cross the
/// network unencrypted.
func isUnencryptedRemote(_ urlString: String) -> Bool {
    guard let url = URL(string: urlString.trimmingCharacters(in: .whitespaces)),
          url.scheme?.lowercased() == "http", let host = url.host?.lowercased() else { return false }
    return !["localhost", "127.0.0.1", "::1", "[::1]"].contains(host)
}

// MARK: - Credentials

/// What the stored credential is and what it may do.
struct CredentialInfo: Equatable {
    var kind: String
    /// Granted OAuth scopes; nil when the server doesn't say. "all" = full access.
    var scopes: [String]?
    var expires: Date?

    var isFullAccess: Bool { scopes?.contains("all") == true }

    /// Scopes each app feature needs (Tailscale OAuth clients).
    static let featureScopes: [(feature: String, scope: String)] = [
        ("pull and push the policy", "policy_file"),
        ("devices, tags, key expiry", "devices:core"),
        ("route approval", "devices:routes"),
        ("auth keys", "auth_keys"),
        ("listing users and roles", "users:read"),
        ("managing users", "users"),
        ("who changed the policy", "logs:configuration:read"),
        ("traffic (flow logs)", "logs:network:read"),
    ]

    /// Features this credential's scopes don't cover (a write scope covers its :read).
    var missingFeatures: [String] {
        guard let scopes, !isFullAccess else { return [] }
        return Self.featureScopes.filter { f in
            !scopes.contains(f.scope) && !(f.scope.hasSuffix(":read") && scopes.contains(String(f.scope.dropLast(5))))
        }.map(\.feature)
    }
}

// MARK: - Activity log

/// Every change the app makes on a server, appended as JSON lines to
/// <data>/activity.jsonl — who, when, which workspace and server, what, and
/// whether it worked. Never contains secrets.
struct ActivityEntry: Codable, Identifiable {
    var date: Date
    var user: String
    var workspace: String
    var server: String
    var action: String
    var detail: String
    var error: String?

    var id: String { "\(date.timeIntervalSince1970)-\(action)-\(detail)" }
}

enum ActivityLog {
    static var fileURL: URL { appDataDirectory.appendingPathComponent("activity.jsonl") }

    static func record(_ entry: ActivityEntry) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard var line = try? encoder.encode(entry) else { return }
        line.append(0x0A)
        try? FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let handle = try? FileHandle(forWritingTo: fileURL) {
            defer { try? handle.close() }
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: line)
        } else {
            try? line.write(to: fileURL)
        }
    }

    /// Newest first.
    static func recent(server: String? = nil, limit: Int = 20) -> [ActivityEntry] {
        guard let data = try? Data(contentsOf: fileURL) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let entries = data.split(separator: 0x0A).compactMap { try? decoder.decode(ActivityEntry.self, from: Data($0)) }
        return Array(entries.reversed().filter { server == nil || $0.server == server }.prefix(limit))
    }
}

// MARK: - Guarded server

/// Wraps the workspace's server so every change asks for Touch ID (when
/// enabled) and lands in the activity log. Reads pass straight through.
final class GuardedServer: PolicyServer {
    let inner: PolicyServer
    let workspace: String
    let requireAuth: Bool

    init(_ inner: PolicyServer, workspace: String, requireAuth: Bool) {
        self.inner = inner
        self.workspace = workspace
        self.requireAuth = requireAuth
    }

    var displayHost: String { inner.displayHost }

    private func change<T>(_ action: String, _ detail: String, _ work: () async throws -> T) async throws -> T {
        let entry = { (error: String?) in
            ActivityEntry(date: Date(), user: NSUserName(), workspace: self.workspace, server: self.displayHost,
                          action: action, detail: detail, error: error)
        }
        if requireAuth {
            do {
                try await Authorizer.confirm("\(action) on \(displayHost)")
            } catch {
                ActivityLog.record(entry("not confirmed"))
                throw error
            }
        }
        do {
            let result = try await work()
            ActivityLog.record(entry(nil))
            return result
        } catch {
            ActivityLog.record(entry(error.localizedDescription))
            throw error
        }
    }

    // Reads
    func getPolicy() async throws -> String { try await inner.getPolicy() }
    func validate(_ policy: String) async throws -> ValidationReport? { try await inner.validate(policy) }
    func listUsers() async throws -> [ServerUser] { try await inner.listUsers() }
    func listNodes() async throws -> [HeadscaleNode] { try await inner.listNodes() }
    func policyChanges(days: Int) async throws -> [PolicyChange]? { try await inner.policyChanges(days: days) }
    func serverUsers() async throws -> ServerUsers { try await inner.serverUsers() }
    func listInvites() async throws -> [PendingInvite] { try await inner.listInvites() }
    func flowRecords(from: Date, to: Date) async throws -> [FlowRecord]? { try await inner.flowRecords(from: from, to: to) }
    func credentialInfo() async throws -> CredentialInfo? { try await inner.credentialInfo() }

    // Changes
    func setPolicy(_ policy: String) async throws {
        try await change("Push the policy", "\(policy.count) characters") { try await inner.setPolicy(policy) }
    }
    func createAuthKey(_ r: AuthKeyRequest) async throws -> String {
        try await change("Create an auth key", "tags: \(r.tags.joined(separator: ", "))\(r.reusable ? ", reusable" : "")") {
            try await inner.createAuthKey(r)
        }
    }
    func setTags(nodeID: String, tags: [String]) async throws {
        try await change("Set device tags", "device \(nodeID): \(tags.joined(separator: ", "))") { try await inner.setTags(nodeID: nodeID, tags: tags) }
    }
    func setApprovedRoutes(nodeID: String, routes: [String]) async throws {
        try await change("Approve routes", "device \(nodeID): \(routes.joined(separator: ", "))") {
            try await inner.setApprovedRoutes(nodeID: nodeID, routes: routes)
        }
    }
    func expireNode(nodeID: String) async throws {
        try await change("Expire a device key", "device \(nodeID)") { try await inner.expireNode(nodeID: nodeID) }
    }
    func deleteNode(nodeID: String) async throws {
        try await change("Delete a device", "device \(nodeID)") { try await inner.deleteNode(nodeID: nodeID) }
    }
    func renameNode(nodeID: String, name: String) async throws {
        try await change("Rename a device", "device \(nodeID) → \(name)") { try await inner.renameNode(nodeID: nodeID, name: name) }
    }
    func deleteUser(id: String) async throws {
        try await change("Delete a user", "user \(id)") { try await inner.deleteUser(id: id) }
    }
    func invite(email: String, role: String) async throws -> PendingInvite {
        try await change("Invite a user", "\(email) as \(role)") { try await inner.invite(email: email, role: role) }
    }
    func resendInvite(id: String) async throws {
        try await change("Resend an invite", "invite \(id)") { try await inner.resendInvite(id: id) }
    }
    func cancelInvite(id: String) async throws {
        try await change("Cancel an invite", "invite \(id)") { try await inner.cancelInvite(id: id) }
    }
    func createUser(name: String, displayName: String, email: String) async throws -> ServerAccount {
        try await change("Create a user", name) { try await inner.createUser(name: name, displayName: displayName, email: email) }
    }
    func setRole(userID: String, role: String) async throws {
        try await change("Change a user's role", "user \(userID) → \(role)") { try await inner.setRole(userID: userID, role: role) }
    }
    func approveUser(id: String) async throws {
        try await change("Approve a user", "user \(id)") { try await inner.approveUser(id: id) }
    }
    func suspendUser(id: String) async throws {
        try await change("Suspend a user", "user \(id)") { try await inner.suspendUser(id: id) }
    }
    func restoreUser(id: String) async throws {
        try await change("Restore a user", "user \(id)") { try await inner.restoreUser(id: id) }
    }
}

// MARK: - Settings window

struct SettingsView: View {
    @AppStorage(SecuritySettings.requireAuthKey) private var requireAuth = true
    @AppStorage(SecuritySettings.clearSecretsKey) private var clearSecrets = true

    var body: some View {
        Form {
            Section("Security") {
                Toggle("Require Touch ID or your password before changing a server", isOn: $requireAuth)
                Text("Covers pushes, device and user changes, route approvals, auth keys, and invites. One confirmation lasts two minutes.")
                    .font(.caption).foregroundStyle(.secondary)
                Toggle("Clear copied auth keys and invite links after a minute", isOn: $clearSecrets)
                Text("Copied secrets are also marked so clipboard managers don't keep them.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Activity log") {
                Text("Every change the app makes on a server is recorded with the date, your user, the workspace, and the result.")
                    .font(.caption).foregroundStyle(.secondary)
                Button("Show activity log") { NSWorkspace.shared.activateFileViewerSelecting([ActivityLog.fileURL]) }
            }
        }
        .formStyle(.grouped)
        .frame(width: 480)
        .padding(.vertical, 8)
    }
}
