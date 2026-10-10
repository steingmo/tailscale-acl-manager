import Foundation
import Security
import SwiftUI

/// Server credentials kept in 1Password: the app stores only a secret
/// reference (op://vault/item/field) and reads the secret with the 1Password
/// CLI when it's first needed. With the CLI integration turned on in the
/// 1Password app, each read is approved there (Touch ID). The secret is held
/// in memory only, read once per reference however many requests need it,
/// and forgotten when the app locks.
enum OnePassword {
    static func isReference(_ s: String) -> Bool { s.trimmingCharacters(in: .whitespaces).hasPrefix("op://") }

    /// Homebrew (Apple silicon, Intel) or the 1Password installer's location.
    static var cliPath: String? {
        (cliPathForTests.map { [$0] } ?? ["/opt/homebrew/bin/op", "/usr/local/bin/op"])
            .first { FileManager.default.isExecutableFile(atPath: $0) }
    }
    /// Tests point this at a stand-in script.
    nonisolated(unsafe) static var cliPathForTests: String?

    private static let lock = NSLock()
    nonisolated(unsafe) private static var cache: [String: String] = [:]
    nonisolated(unsafe) private static var reads: [String: Task<String, Error>] = [:]

    /// The secret a reference points to; concurrent callers share one read.
    static func read(_ reference: String) async throws -> String {
        let ref = reference.trimmingCharacters(in: .whitespaces)
        let task: Task<String, Error> = lock.withLock {
            if let secret = cache[ref] { return Task { secret } }
            if let running = reads[ref] { return running }
            let task = Task {
                let out = try await run(["read", "--no-newline", ref])
                return String(decoding: out, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            }
            reads[ref] = task
            return task
        }
        do {
            let secret = try await task.value
            guard !secret.isEmpty else { throw OnePasswordError("\(ref) is empty in 1Password.") }
            lock.withLock { cache[ref] = secret; reads[ref] = nil }
            return secret
        } catch {
            lock.withLock { reads[ref] = nil }
            throw error
        }
    }

    /// Drop every secret read so far (app lock), so the next use asks again.
    static func forget() {
        lock.withLock { cache = [:] }
    }

    /// Vault names, for choosing where to move a key.
    static func vaults() async throws -> [String] {
        let out = try await run(["vault", "list", "--format", "json"])
        let list = (try JSONSerialization.jsonObject(with: out) as? [[String: Any]]) ?? []
        return list.compactMap { $0["name"] as? String }
    }

    /// Save `secret` as a new API Credential item and return the reference to
    /// its credential field. The secret goes in on standard input, never as an
    /// argument (other processes can see arguments).
    static func createItem(vault: String, title: String, secret: String) async throws -> String {
        let template: [String: Any] = [
            "title": title,
            "category": "API_CREDENTIAL",
            "fields": [["id": "credential", "type": "CONCEALED", "label": "credential", "value": secret]],
        ]
        let out = try await run(["item", "create", "--vault", vault, "--format", "json", "-"],
                                input: try JSONSerialization.data(withJSONObject: template))
        let fields = ((try JSONSerialization.jsonObject(with: out) as? [String: Any])?["fields"] as? [[String: Any]]) ?? []
        guard let reference = fields.first(where: { $0["id"] as? String == "credential" })?["reference"] as? String else {
            throw OnePasswordError("1Password created the item but didn't return its secret reference.")
        }
        lock.withLock { cache[reference] = secret }
        return reference
    }

    /// Runs the CLI. Allows two minutes, since 1Password may wait for Touch ID.
    private static func run(_ args: [String], input: Data? = nil) async throws -> Data {
        guard let path = cliPath else {
            throw OnePasswordError("The 1Password CLI isn't installed. Install it (brew install 1password-cli), then turn on Settings ▸ Developer ▸ Integrate with 1Password CLI in the 1Password app.")
        }
        // /opt/homebrew is writable without admin rights, and the CLI may be
        // handed a key (Move to 1Password), so only 1Password's own signed
        // binary runs.
        guard cliPathForTests != nil || isSignedBy1Password(path) else {
            throw OnePasswordError("\(path) isn't signed by 1Password (AgileBits), so it wasn't run. Reinstall the 1Password CLI.")
        }
        return try await Task.detached { try runBlocking(path, args, input) }.value
    }

    static func isSignedBy1Password(_ path: String) -> Bool {
        var code: SecStaticCode?
        var requirement: SecRequirement?
        let url = URL(fileURLWithPath: path).resolvingSymlinksInPath() as CFURL
        guard SecStaticCodeCreateWithPath(url, [], &code) == errSecSuccess, let code,
              SecRequirementCreateWithString(#"anchor apple generic and identifier "com.1password.op" and certificate leaf[subject.OU] = "2BUA8C4S2C""# as CFString,
                                             [], &requirement) == errSecSuccess else { return false }
        return SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures), requirement) == errSecSuccess
    }

    private static func runBlocking(_ path: String, _ args: [String], _ input: Data?) throws -> Data {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let out = Pipe(), err = Pipe(), inPipe = Pipe()
        p.standardOutput = out
        p.standardError = err
        p.standardInput = inPipe
        try p.run()
        if let input { inPipe.fileHandleForWriting.write(input) }
        try? inPipe.fileHandleForWriting.close()
        let timer = DispatchWorkItem { if p.isRunning { p.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 120, execute: timer)
        // Read both pipes before waiting, so a full pipe can't block the CLI.
        var errData = Data()
        let errDone = DispatchSemaphore(value: 0)
        DispatchQueue.global().async { errData = err.fileHandleForReading.readDataToEndOfFile(); errDone.signal() }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        errDone.wait()
        timer.cancel()
        guard p.terminationStatus == 0 else {
            let message = String(decoding: errData, as: UTF8.self)
                .replacingOccurrences(of: #"^\[ERROR\] [0-9/: ]+"#, with: "", options: .regularExpression)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            throw OnePasswordError(message.isEmpty ? "1Password didn't answer (locked, or the request was declined)." : "1Password: \(message)")
        }
        return data
    }
}

struct OnePasswordError: LocalizedError {
    var message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

/// A server credential as stored: the key itself, or a 1Password reference.
struct Credential {
    let stored: String
    var isReference: Bool { OnePassword.isReference(stored) }
    /// The key, read from 1Password when it's a reference.
    func value() async throws -> String { isReference ? try await OnePassword.read(stored) : stored }
}

/// Saves the workspace's key in 1Password and hands back the reference
/// that replaces it in the Keychain (Server screen).
struct MoveToOnePasswordSheet: View {
    var secret: String
    @State var title: String
    var onMoved: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var vaults: [String] = []
    @State private var vault = ""
    @State private var working = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Move the key to 1Password").font(.system(size: 16, weight: .bold))
            Text("The key is saved as a new API Credential item. This Mac then keeps only its secret reference, and the app reads the key from 1Password (approved with Touch ID) when it needs it. Anyone you share the vault with can use the same reference.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if vaults.isEmpty && error == nil {
                HStack { ProgressView().controlSize(.small); Text("Asking 1Password for your vaults…").font(.callout) }
            } else if !vaults.isEmpty {
                Picker("Vault", selection: $vault) { ForEach(vaults, id: \.self) { Text($0).tag($0) } }
                TextField("Item name", text: $title)
            }
            if let error {
                Text(error).font(.callout).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                if working { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Move to 1Password") { move() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(vault.isEmpty || title.trimmingCharacters(in: .whitespaces).isEmpty || working)
            }
        }
        .padding(20)
        .frame(width: 460)
        .task {
            do {
                vaults = try await OnePassword.vaults()
                vault = vaults.first ?? ""
                if vaults.isEmpty { error = "No vaults found in 1Password." }
            } catch {
                self.error = error.localizedDescription
            }
        }
    }

    private func move() {
        working = true
        error = nil
        Task {
            defer { working = false }
            do {
                let reference = try await OnePassword.createItem(vault: vault, title: title.trimmingCharacters(in: .whitespaces), secret: secret)
                onMoved(reference)
                dismiss()
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}
