import Foundation
import CryptoKit

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
