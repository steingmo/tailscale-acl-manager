import SwiftUI

// Guards against the wrong policy ending up in the wrong place: large silent
// replacements (History), pushes of another workspace's policy, automatic
// backups, and a colour per workspace.

// MARK: - Large changes

/// Whether going from `old` to `new` throws away a big part of `old` in one
/// step — a replacement, not typing. What stays the same at the start and the
/// end doesn't count.
func isLargeChange(from old: String, to new: String) -> Bool {
    let a = Array(old.utf8), b = Array(new.utf8)
    let shortest = min(a.count, b.count)
    var prefix = 0
    while prefix < shortest, a[prefix] == b[prefix] { prefix += 1 }
    var suffix = 0
    while suffix < shortest - prefix, a[a.count - 1 - suffix] == b[b.count - 1 - suffix] { suffix += 1 }
    let lost = a.count - prefix - suffix
    return lost > 200 && lost * 4 > a.count
}

/// The reason History gives the version saved before such a change.
let largeChangeReason = "before a large change"

// MARK: - Push guard

/// Reasons to stop before pushing `candidate` over `server`: it is another
/// server's policy, or it drops most of the rules the server has.
func pushWarnings(server: String, candidate: String, workspace: Workspace, all: [Workspace]) -> [String] {
    func norm(_ s: String) -> String { s.trimmingCharacters(in: .whitespacesAndNewlines) }
    func host(_ w: Workspace) -> String { serverName(kind: w.kind, serverURL: w.serverURL, tailnet: w.tailnet ?? "-") }
    guard norm(server) != norm(candidate) else { return [] }
    var warnings: [String] = []

    // A duplicated workspace for the same server is fine; another server's policy isn't.
    let twins = all.filter {
        $0.id != workspace.id && !norm($0.policy).isEmpty && norm($0.policy) == norm(candidate)
            && !host($0).isEmpty && host($0) != host(workspace)
    }
    if !twins.isEmpty {
        let names = twins.map { "\u{201C}\($0.name)\u{201D} (\(host($0)))" }.joined(separator: ", ")
        warnings.append("This is exactly the policy of the workspace \(names) — a different server.")
    }

    func rules(_ text: String) -> [String]? {
        guard let tree = try? HuJSONParser.parse(text) else { return nil }
        let m = PolicyModel(tree: tree)
        return m.rules.map { "acl \($0.action) \($0.src) \($0.dst) \($0.proto ?? "")" }
            + m.grants.map { "grant \($0.src) \($0.dst) \($0.ip) \($0.via) \($0.hasApp)" }
            + m.sshRules.map { "ssh \($0.action) \($0.src) \($0.dst) \($0.users)" }
    }
    if let old = rules(server), old.count >= 4, let new = rules(candidate) {
        let kept = Set(new)
        let gone = old.filter { !kept.contains($0) }.count
        if gone * 2 > old.count {
            warnings.append("\(gone) of the \(old.count) rules on the server are removed or rewritten by this push.")
        }
    }
    return warnings
}

// MARK: - Workspace colours

let workspacePalette: [(name: String, color: Color)] = [
    ("Blue", Theme.blue), ("Green", Theme.green), ("Orange", Theme.orange), ("Purple", Theme.purple),
    ("Pink", Theme.pink), ("Teal", Color(hex: 0x4DD0C8)), ("Yellow", Color(hex: 0xE6C84F)),
]

extension PolicyStore {
    /// The chosen colour, or one by position in the list until one is chosen.
    func colorIndex(of id: UUID) -> Int {
        guard let i = workspaces.firstIndex(where: { $0.id == id }) else { return 0 }
        return abs(workspaces[i].color ?? i) % workspacePalette.count
    }

    var workspaceColor: Color { workspacePalette[colorIndex(of: currentWorkspaceID)].color }
}

// MARK: - Automatic backup

/// A password-protected backup (the same file as Export Backup) once a day,
/// newest 14 kept. The password is in the Keychain so it can run unattended.
enum AutoBackup {
    static let enabledKey = "autoBackup"
    static let folderKey = "autoBackupFolder"
    static let lastKey = "autoBackupLast"
    static let errorKey = "autoBackupError"
    static let passwordAccount = "auto-backup-password"
    static let prefix = "Tailscale ACL auto-backup "

    /// The chosen folder, or <data>/backups — not a data file, so backups
    /// never contain backups and a restore leaves them alone.
    static var folder: URL {
        let chosen = UserDefaults.standard.string(forKey: folderKey) ?? ""
        return chosen.isEmpty ? appDataDirectory.appendingPathComponent("backups", isDirectory: true)
            : URL(fileURLWithPath: chosen, isDirectory: true)
    }

    /// Writes the backup for `now`'s day into `folder` (replacing that day's)
    /// and deletes automatic backups beyond the newest `keep`. Other files in
    /// the folder are never touched.
    @discardableResult
    static func run(password: String, folder: URL, now: Date = Date(),
                    rounds: UInt32 = Backup.defaultRounds, keep: Int = 14) throws -> URL {
        let fm = FileManager.default
        try fm.createDirectory(at: folder, withIntermediateDirectories: true)
        let url = folder.appendingPathComponent("\(prefix)\(RuleExpiry.formatter.string(from: now)).tsaclbackup")
        try Backup.make(password: password, rounds: rounds).write(to: url, options: .atomic)
        let mine = ((try? fm.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil)) ?? [])
            .filter { $0.lastPathComponent.hasPrefix(prefix) && $0.pathExtension == "tsaclbackup" }
            .sorted { $0.lastPathComponent > $1.lastPathComponent }
        for old in mine.dropFirst(keep) { try? fm.removeItem(at: old) }
        return url
    }

    @MainActor private static var running = false

    /// Backs up if it's on and the last one is more than a day old. Off the
    /// main thread: deriving the key takes a moment.
    /// ponytail: checked when the app opens, unlocks, or comes to the front —
    /// no timer; an app left in the background for days backs up when used again.
    @MainActor
    static func runIfDue(now: Date = Date()) {
        let defaults = UserDefaults.standard
        guard defaults.bool(forKey: enabledKey), !running,
              now.timeIntervalSince1970 - defaults.double(forKey: lastKey) > 86_400,
              let password = HeadscaleKeychain.load(account: passwordAccount) else { return }
        running = true
        let folder = folder
        Task.detached(priority: .utility) {
            var failure: String?
            do { try run(password: password, folder: folder, now: now) } catch { failure = error.localizedDescription }
            let result = failure
            await MainActor.run {
                running = false
                if let result {
                    defaults.set(result, forKey: errorKey)
                } else {
                    defaults.set(now.timeIntervalSince1970, forKey: lastKey)
                    defaults.removeObject(forKey: errorKey)
                }
            }
        }
    }
}

/// The automatic-backup rows of Settings ▸ Backup.
struct AutoBackupSettings: View {
    @AppStorage(AutoBackup.enabledKey) private var enabled = false
    @AppStorage(AutoBackup.folderKey) private var folderPath = ""
    @AppStorage(AutoBackup.lastKey) private var last = 0.0
    @AppStorage(AutoBackup.errorKey) private var failure = ""
    @State private var hasPassword = false
    @State private var password = ""

    var body: some View {
        Toggle("Back up automatically once a day (the newest 14 are kept)", isOn: $enabled)
            .disabled(!hasPassword)
            .onChange(of: enabled) { AutoBackup.runIfDue() }
            .onAppear { hasPassword = HeadscaleKeychain.load(account: AutoBackup.passwordAccount) != nil }
        if hasPassword {
            LabeledContent("Backup password") {
                HStack {
                    Text("Saved in your Keychain").foregroundStyle(.secondary)
                    Button("Remove") { setPassword("") }
                }
            }
        } else {
            HStack {
                SecureField("Backup password", text: $password, prompt: Text("At least 10 characters"))
                Button("Save") { setPassword(password) }.disabled(password.count < 10)
            }
        }
        LabeledContent("Folder") {
            HStack {
                Text(AutoBackup.folder.path).lineLimit(1).truncationMode(.head).foregroundStyle(.secondary)
                    .help(AutoBackup.folder.path)
                Button("Choose…", action: chooseFolder)
                if !folderPath.isEmpty { Button("Default") { folderPath = "" } }
            }
        }
        Text(status).font(.caption).foregroundStyle(failure.isEmpty ? Color.secondary : Color.red)
            .fixedSize(horizontal: false, vertical: true)
    }

    private var status: String {
        if !failure.isEmpty { return "The last automatic backup failed: \(failure)" }
        let note = "The password stays in your Keychain so backups run unattended. You need it to restore — keep it in a password manager too."
        guard last > 0 else { return note }
        return "Last automatic backup: \(Date(timeIntervalSince1970: last).formatted(date: .abbreviated, time: .shortened)). \(note)"
    }

    private func setPassword(_ new: String) {
        HeadscaleKeychain.save(new, account: AutoBackup.passwordAccount)
        hasPassword = !new.isEmpty
        password = ""
        if new.isEmpty { enabled = false }
    }

    private func chooseFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.message = "Choose a folder for automatic backups"
        if panel.runModal() == .OK, let url = panel.url { folderPath = url.path }
    }
}
