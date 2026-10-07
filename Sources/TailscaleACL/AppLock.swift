import SwiftUI
import AppKit
import LocalAuthentication

/// Owns the open workspaces. With the app lock on, nothing is loaded (or
/// decrypted) until Touch ID or the password unlocks it, and locking drops
/// the store — policies, devices, traffic — from memory.
@MainActor
final class AppSession: ObservableObject {
    static let lockSettingKey = "lockApp"

    @Published private(set) var store: PolicyStore?
    @Published var error: String?
    @Published private(set) var unlocking = false
    /// Ask for Touch ID as soon as the lock screen shows: at launch, not
    /// right after the user locked on purpose.
    private(set) var promptAutomatically = true

    var lockEnabled: Bool { UserDefaults.standard.bool(forKey: Self.lockSettingKey) }
    private var observers: [NSObjectProtocol] = []

    init() {
        if !lockEnabled { open() }
        // Lock when the Mac sleeps or the screen locks.
        let ws = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.screensDidSleepNotification] {
            observers.append(ws.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in self?.lock(manual: false) }
            })
        }
        observers.append(DistributedNotificationCenter.default().addObserver(
            forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in self?.lock(manual: false) }
            })
    }

    func unlock() async {
        guard store == nil, !unlocking else { return }
        unlocking = true
        defer { unlocking = false }
        error = nil
        let context = LAContext()
        var canAsk: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &canAsk) {
            do {
                try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "open your Tailscale ACL workspaces")
            } catch {
                self.error = "Not unlocked."
                return
            }
        }
        open()
    }

    /// Load the key (if the data is encrypted) and the workspaces. Refuses
    /// to start — rather than start empty and overwrite — if the data can't
    /// be decrypted.
    private func open() {
        if DataEncryption.isOn {
            guard let key = DataEncryption.storedKey() else {
                error = "Your saved workspaces are encrypted, but the key isn't in your Keychain (item \u{201C}data-encryption-key\u{201D}). Nothing was changed. Restore the Keychain item, or move the TailscaleACL folder out of Application Support to start fresh."
                return
            }
            DataEncryption.key = key
        }
        if DataEncryption.isUnreadable(WorkspaceStore.fileURL) {
            DataEncryption.key = nil
            error = "Your saved workspaces are encrypted and can't be read with the key available. Nothing was changed."
            return
        }
        store = PolicyStore()
    }

    /// Manual locks always lock; sleep and screen lock only with the app lock on.
    func lock(manual: Bool) {
        guard store != nil, manual || lockEnabled else { return }
        store = nil
        DataEncryption.key = nil
        promptAutomatically = false
    }
}

struct SessionRootView: View {
    @EnvironmentObject var session: AppSession

    var body: some View {
        if let store = session.store {
            RootView().environmentObject(store)
        } else {
            LockView()
        }
    }
}

struct LockView: View {
    @EnvironmentObject var session: AppSession

    var body: some View {
        VStack(spacing: 14) {
            Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 72, height: 72)
            Image(systemName: "lock.fill").font(.system(size: 20)).foregroundStyle(Theme.textSecondary)
            Text("Tailscale ACL is locked")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            if let error = session.error {
                Text(error)
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.red)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 420)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Button {
                Task { await session.unlock() }
            } label: {
                Label("Unlock", systemImage: "touchid").padding(.horizontal, 8)
            }
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .disabled(session.unlocking)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Theme.background)
        .preferredColorScheme(.dark)
        .frame(minWidth: 980, minHeight: 620)
        .task { if session.promptAutomatically { await session.unlock() } }
    }
}
