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

    /// Reopen the workspaces from disk (after restoring a backup).
    func reload() {
        store = nil
        open()
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

// MARK: - Backup

/// Export or restore a password-protected backup of all workspaces and history.
struct BackupSheet: View {
    enum Mode { case export, restore }
    var mode: Mode

    @EnvironmentObject var session: AppSession
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var confirm = ""
    @State private var file: URL?
    @State private var archive: Backup.Archive?
    @State private var working = false
    @State private var error: String?
    @State private var done: String?

    private var archiveSummary: String {
        guard let archive else { return "" }
        let workspaces = archive.files["workspaces.json"].flatMap { try? JSONDecoder().decode([Workspace].self, from: $0) } ?? []
        return "Backup from \(archive.created.formatted(date: .long, time: .shortened)): \(workspaces.count) workspace\(workspaces.count == 1 ? "" : "s") (\(workspaces.map(\.name).joined(separator: ", "))), \(archive.files.count) files."
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(mode == .export ? "Export backup" : "Restore from backup")
                .font(.system(size: 16, weight: .bold))
            if let done {
                Label(done, systemImage: "checkmark.seal.fill").foregroundStyle(.green).fixedSize(horizontal: false, vertical: true)
                HStack { Spacer(); Button("Done") { dismiss() }.keyboardShortcut(.defaultAction) }
            } else if mode == .export {
                Text("One file with every workspace, push history, snapshots, and the activity log, encrypted with this password. Credentials aren't included — re-enter them after restoring. There's no way to recover a forgotten password.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                SecureField("Password (at least 10 characters)", text: $password)
                SecureField("Repeat password", text: $confirm)
                footer(action: "Save Backup…", enabled: password.count >= 10 && password == confirm, run: export)
            } else if let archive {
                Text(archiveSummary).fixedSize(horizontal: false, vertical: true)
                Text("Restoring replaces all current workspaces and history. The current files are kept in a before-restore folder in the app's data folder first.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                footer(action: "Replace with Backup", enabled: true, destructive: true) { restore(archive) }
            } else {
                HStack {
                    Button(file == nil ? "Choose Backup File…" : "Change…", action: chooseFile)
                    Text(file?.lastPathComponent ?? "").font(.callout).foregroundStyle(.secondary)
                }
                SecureField("Backup password", text: $password)
                footer(action: "Open Backup", enabled: file != nil && !password.isEmpty, run: openBackup)
            }
        }
        .padding(20)
        .frame(width: 440)
    }

    private func footer(action: String, enabled: Bool, destructive: Bool = false, run: @escaping () -> Void) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            if let error { Text(error).font(.callout).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true) }
            HStack {
                if working { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(action, role: destructive ? .destructive : nil, action: run)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!enabled || working)
            }
        }
    }

    private func export() {
        let panel = NSSavePanel()
        let stamp = DateFormatter()
        stamp.dateFormat = "yyyy-MM-dd"
        panel.nameFieldStringValue = "Tailscale ACL backup \(stamp.string(from: Date())).tsaclbackup"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        run {
            let data = try Backup.make(password: password)
            try data.write(to: url, options: .atomic)
            return "Saved \(url.lastPathComponent). Keep it and its password somewhere safe — a password manager is ideal."
        }
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.message = "Choose a Tailscale ACL backup (.tsaclbackup)"
        if panel.runModal() == .OK { file = panel.url }
    }

    private func openBackup() {
        guard let file else { return }
        working = true
        error = nil
        let pw = password
        Task {
            defer { working = false }
            do {
                let data = try Data(contentsOf: file)
                archive = try await Task.detached { try Backup.open(data, password: pw) }.value
            } catch {
                self.error = error.localizedDescription
            }
        }
    }

    private func restore(_ archive: Backup.Archive) {
        run {
            let aside = try Backup.restore(archive)
            session.reload()
            return "Restored. The previous data is in \(aside.lastPathComponent) in the app's data folder. Re-enter server credentials on the Server screen if this is a new Mac."
        }
    }

    private func run(_ work: @escaping () throws -> String) {
        working = true
        error = nil
        Task {
            defer { working = false }
            do {
                // PBKDF2 takes a moment; keep the window responsive.
                try await Task.sleep(nanoseconds: 50_000_000)
                done = try work()
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}
