import Foundation
import Security

// The Apple-only part of the server clients: the Keychain.

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
