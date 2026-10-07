import Foundation
import CryptoKit
import CommonCrypto
import Security

/// Optional encryption of the app's data files (workspaces with their
/// policies, push history, snapshots, activity log) with AES-256-GCM. The
/// key lives in the login Keychain, readable by this app without a prompt.
/// Encrypted files start with a marker; files without it are read as plain
/// JSON, so turning encryption on or off migrates file by file safely.
enum DataEncryption {
    static let marker = Data("TSACL-ENC1\n".utf8)
    static let settingKey = "encryptData"
    private static let keychainAccount = "data-encryption-key"

    /// The key while the app is unlocked and encryption is on; writes are
    /// encrypted exactly when it's set.
    nonisolated(unsafe) static var key: SymmetricKey?

    static var isOn: Bool { UserDefaults.standard.bool(forKey: settingKey) }

    // MARK: Files

    static func isEncrypted(_ data: Data) -> Bool { data.starts(with: marker) }

    /// The file's contents, decrypted if needed; nil if missing or if it's
    /// encrypted and can't be decrypted (no key, or the wrong one).
    static func read(_ url: URL) -> Data? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        guard isEncrypted(data) else { return data }
        guard let key, let box = try? AES.GCM.SealedBox(combined: data.dropFirst(marker.count)) else { return nil }
        return try? AES.GCM.open(box, using: key)
    }

    /// A file exists but can't be read — encrypted with a key we don't have.
    static func isUnreadable(_ url: URL) -> Bool {
        FileManager.default.fileExists(atPath: url.path) && read(url) == nil
    }

    /// Writes atomically, encrypted when a key is set. Never replaces an
    /// encrypted file with plain text (that would mean the key went missing).
    static func write(_ data: Data, to url: URL, encrypt: Bool? = nil) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        if encrypt ?? (key != nil), let key {
            let sealed = try AES.GCM.seal(data, using: key)
            guard let combined = sealed.combined else { throw CocoaError(.fileWriteUnknown) }
            try (marker + combined).write(to: url, options: .atomic)
        } else {
            if encrypt == nil, let existing = try? Data(contentsOf: url), isEncrypted(existing) {
                throw CocoaError(.fileWriteNoPermission, userInfo: [NSLocalizedDescriptionKey:
                    "Refusing to overwrite an encrypted file with unencrypted data: \(url.lastPathComponent)"])
            }
            try data.write(to: url, options: .atomic)
        }
    }

    /// Every data file the app keeps.
    static var dataFiles: [URL] {
        let dir = appDataDirectory
        var files = ["workspaces.json", "push-history.json", "activity.jsonl"].map { dir.appendingPathComponent($0) }
        let snapshots = dir.appendingPathComponent("snapshots", isDirectory: true)
        files += (try? FileManager.default.contentsOfDirectory(at: snapshots, includingPropertiesForKeys: nil)) ?? []
        return files.filter { FileManager.default.fileExists(atPath: $0.path) }
    }

    /// Rewrite every data file encrypted (`true`) or plain (`false`) with the
    /// current key. Each file is read before it's rewritten and checked after,
    /// so a failure leaves every file readable.
    static func rewriteAll(encrypted: Bool) throws {
        for url in dataFiles {
            guard let plain = read(url) else {
                throw CocoaError(.fileReadCorruptFile, userInfo: [NSLocalizedDescriptionKey: "Can't read \(url.lastPathComponent)."])
            }
            try write(plain, to: url, encrypt: encrypted)
            guard read(url) == plain else {
                throw CocoaError(.fileWriteUnknown, userInfo: [NSLocalizedDescriptionKey: "Couldn't verify \(url.lastPathComponent)."])
            }
        }
    }

    // MARK: Key and setting

    /// The stored key, if encryption has been turned on.
    static func storedKey() -> SymmetricKey? {
        HeadscaleKeychain.load(account: keychainAccount)
            .flatMap { Data(base64Encoded: $0) }
            .map { SymmetricKey(data: $0) }
    }

    /// Turn encryption on: make a key, keep it in the Keychain, encrypt every file.
    static func enable() throws {
        let newKey = SymmetricKey(size: .bits256)
        let encoded = newKey.withUnsafeBytes { Data($0) }.base64EncodedString()
        HeadscaleKeychain.save(encoded, account: keychainAccount)
        let bytes = { (k: SymmetricKey) in k.withUnsafeBytes { Data($0) } }
        guard let saved = storedKey(), bytes(saved) == bytes(newKey) else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSLocalizedDescriptionKey: "Couldn't store the key in the Keychain."])
        }
        key = newKey
        do {
            try rewriteAll(encrypted: true)
        } catch {
            try? rewriteAll(encrypted: false)   // back to plain; nothing half-done
            key = nil
            HeadscaleKeychain.save("", account: keychainAccount)
            throw error
        }
        UserDefaults.standard.set(true, forKey: settingKey)
    }

    /// Turn encryption off: decrypt every file, then forget the key.
    static func disable() throws {
        key = key ?? storedKey()
        try rewriteAll(encrypted: false)
        key = nil
        HeadscaleKeychain.save("", account: keychainAccount)
        UserDefaults.standard.set(false, forKey: settingKey)
    }
}

/// Whether FileVault (full-disk encryption) is on — the first protection for a lost Mac.
func fileVaultIsOn() -> Bool? {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/fdesetup")
    p.arguments = ["isactive"]
    let out = Pipe()
    p.standardOutput = out
    p.standardError = Pipe()
    guard (try? p.run()) != nil else { return nil }
    let text = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    p.waitUntilExit()
    return text.trimmingCharacters(in: .whitespacesAndNewlines) == "true"
}

// MARK: - Password-protected backup

/// One file holding every workspace, the push history, snapshots, and the
/// activity log (not credentials — those stay in the Keychain), encrypted
/// with a key derived from a password: PBKDF2-SHA256, then AES-256-GCM.
/// Format: marker, 16-byte salt, 4-byte round count, sealed archive.
enum Backup {
    static let marker = Data("TSACL-BACKUP1\n".utf8)
    static let defaultRounds: UInt32 = 600_000

    struct Archive: Codable {
        var version = 1
        var created: Date
        /// Path inside the data folder → plain contents.
        var files: [String: Data]
    }

    static func make(password: String, rounds: UInt32 = defaultRounds) throws -> Data {
        var files: [String: Data] = [:]
        for url in DataEncryption.dataFiles {
            guard let data = DataEncryption.read(url) else {
                throw CocoaError(.fileReadCorruptFile, userInfo: [NSLocalizedDescriptionKey: "Can't read \(url.lastPathComponent)."])
            }
            files[relativePath(url)] = data
        }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let archive = try encoder.encode(Archive(created: Date(), files: files))
        var salt = Data(count: 16)
        _ = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        let sealed = try AES.GCM.seal(archive, using: key(password, salt: salt, rounds: rounds))
        var roundsBE = rounds.bigEndian
        return marker + salt + Data(bytes: &roundsBE, count: 4) + (sealed.combined ?? Data())
    }

    static func open(_ data: Data, password: String) throws -> Archive {
        let bad = CocoaError(.fileReadCorruptFile, userInfo: [NSLocalizedDescriptionKey: "Wrong password, or not a Tailscale ACL backup."])
        guard data.starts(with: marker), data.count > marker.count + 20 else { throw bad }
        let body = data.dropFirst(marker.count)
        let salt = Data(body.prefix(16))
        let rounds = body.dropFirst(16).prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        guard (1_000...10_000_000).contains(rounds),
              let box = try? AES.GCM.SealedBox(combined: body.dropFirst(20)),
              let plain = try? AES.GCM.open(box, using: key(password, salt: salt, rounds: rounds)) else { throw bad }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let archive = try decoder.decode(Archive.self, from: plain)
        // Only the app's own file names: a crafted backup can't write elsewhere.
        guard archive.files.keys.allSatisfy(isAllowedPath) else { throw bad }
        return archive
    }

    /// Replace the app's data with the backup. The current files are first
    /// copied, as they are (encrypted or not), to before-restore-<time>/.
    /// Restored files follow the current encryption setting.
    static func restore(_ archive: Archive, now: Date = Date()) throws -> URL {
        let stamp = DateFormatter()
        stamp.dateFormat = "yyyyMMdd-HHmmss"
        stamp.locale = Locale(identifier: "en_US_POSIX")
        let aside = appDataDirectory.appendingPathComponent("before-restore-\(stamp.string(from: now))", isDirectory: true)
        let fm = FileManager.default
        for url in DataEncryption.dataFiles {
            let target = aside.appendingPathComponent(relativePath(url))
            try fm.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
            try fm.copyItem(at: url, to: target)
        }
        for url in DataEncryption.dataFiles { try fm.removeItem(at: url) }
        for (path, contents) in archive.files {
            try DataEncryption.write(contents, to: appDataDirectory.appendingPathComponent(path))
        }
        return aside
    }

    static func relativePath(_ url: URL) -> String {
        let base = appDataDirectory.standardizedFileURL.path
        let full = url.standardizedFileURL.path
        return full.hasPrefix(base + "/") ? String(full.dropFirst(base.count + 1)) : url.lastPathComponent
    }

    static func isAllowedPath(_ path: String) -> Bool {
        if ["workspaces.json", "push-history.json", "activity.jsonl"].contains(path) { return true }
        let parts = path.split(separator: "/")
        return parts.count == 2 && parts[0] == "snapshots" && parts[1].hasSuffix(".json")
            && UUID(uuidString: String(parts[1].dropLast(5))) != nil
    }

    private static func key(_ password: String, salt: Data, rounds: UInt32) -> SymmetricKey {
        var out = [UInt8](repeating: 0, count: 32)
        let passwordBytes = Array(password.utf8)
        salt.withUnsafeBytes { s in
            _ = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), password, passwordBytes.count,
                                     s.bindMemory(to: UInt8.self).baseAddress, salt.count,
                                     CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds, &out, out.count)
        }
        return SymmetricKey(data: out)
    }
}
