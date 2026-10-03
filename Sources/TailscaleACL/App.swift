import SwiftUI
import AppKit
import Sparkle

/// Sparkle updater wrapper: checks the appcast daily and on demand.
@MainActor
final class UpdaterViewModel: ObservableObject {
    private let controller: SPUStandardUpdaterController
    @Published var canCheckForUpdates = false

    init() {
        controller = SPUStandardUpdaterController(
            startingUpdater: true, updaterDelegate: nil, userDriverDelegate: nil
        )
        controller.updater.publisher(for: \.canCheckForUpdates)
            .assign(to: &$canCheckForUpdates)
    }

    func checkForUpdates() {
        controller.updater.checkForUpdates()
    }
}

enum Screen: String, CaseIterable, Identifiable {
    case accessMap = "Access Map"
    case policyEditor = "Policy Editor"
    case accessMatrix = "Access Matrix"
    case visualBuilder = "Visual Builder"
    case accessSimulator = "Access Simulator"
    case ssh = "SSH"
    case tests = "Tests"
    case routes = "Routes"
    case problems = "Problems"
    case headscale = "Server"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .accessMap: return "circle.hexagongrid"
        case .policyEditor: return "doc.text"
        case .accessMatrix: return "tablecells"
        case .visualBuilder: return "point.3.connected.trianglepath.dotted"
        case .accessSimulator: return "play"
        case .ssh: return "terminal"
        case .tests: return "checkmark.shield"
        case .routes: return "arrow.triangle.branch"
        case .problems: return "exclamationmark.triangle"
        case .headscale: return "network"
        }
    }
}

struct RootView: View {
    @EnvironmentObject var store: PolicyStore
    @Environment(\.undoManager) private var undoManager
    @State private var screen: Screen = .policyEditor
    @State private var workspaceSheet: WorkspaceSheet.Mode?
    @State private var overlay: Overlay?

    /// Search, then (when a rule is picked) its editor, in one sheet slot so
    /// switching from one to the other dismisses and re-presents cleanly.
    enum Overlay: Identifiable {
        case search
        case rule(RuleSummary)
        case compare(DiffPresentation)
        var id: String {
            switch self {
            case .search: return "search"
            case .rule(let r): return "rule-\(r.id)"
            case .compare(let d): return "compare-\(d.id)"
            }
        }
    }
    @State private var confirmingDelete = false

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Divider()
                .overlay(Theme.panelBorder)
            VStack(spacing: 0) {
                if let server = store.serverDrift { driftBanner(server) }
                content
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(Theme.background)
        .preferredColorScheme(.dark)
        .frame(minWidth: 980, minHeight: 620)
        .onAppear { store.undoManager = undoManager }
        // Load devices for the open workspace so device views work without a manual refresh.
        .task(id: store.currentWorkspaceID) {
            try? await store.refreshNodes()
            await store.checkServerDrift()
        }
        .onChange(of: undoManager) { store.undoManager = undoManager }
        .sheet(item: $workspaceSheet) { WorkspaceSheet(mode: $0) }
        .sheet(item: $overlay) { item in
            switch item {
            case .search:
                QuickSearchSheet { result in
                    switch result {
                    case .entity(let name):
                        store.mapFocusRequest = name
                        screen = .accessMap
                        overlay = nil
                    case .rule(let rule):
                        overlay = .rule(rule)
                    }
                }
            case .rule(let rule):
                RuleSheet(existing: rule)
            case .compare(let diff):
                DiffSheet(diff: diff)
            }
        }
        .confirmationDialog("Delete workspace \u{201C}\(store.currentWorkspace.name)\u{201D}?",
                            isPresented: $confirmingDelete) {
            Button("Delete", role: .destructive) { store.deleteWorkspace(store.currentWorkspaceID) }
        } message: {
            Text("Its policy and saved API key are removed from this Mac. The server itself is not changed.")
        }
    }

    /// Shown when the server's policy changed since this workspace's last
    /// pull or push — someone edited it elsewhere.
    private func driftBanner(_ server: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(Theme.orange)
            Text("The policy on \(store.serverDisplayName) changed since your last pull or push.")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(Theme.textPrimary)
            Spacer()
            Button("Compare") {
                overlay = .compare(DiffPresentation(title: "Changes made on the server",
                                                    oldLabel: "at your last pull/push", newLabel: "on the server now",
                                                    old: store.currentWorkspace.lastSyncedPolicy ?? "", new: server))
            }
            Button("Pull") {
                store.loadPolicy(server, reason: "pulled")
                store.markSynced(server)
            }
            .help("Replace the editor with the server's policy (undo with ⌘Z)")
            Button {
                store.serverDrift = nil
            } label: {
                Image(systemName: "xmark")
            }
            .buttonStyle(.borderless)
            .help("Hide until the workspace is opened again")
        }
        .font(.system(size: 11.5))
        .padding(.horizontal, 16)
        .padding(.vertical, 9)
        .background(Theme.orange.opacity(0.12))
        .overlay(Rectangle().fill(Theme.orange.opacity(0.35)).frame(height: 1), alignment: .bottom)
    }

    private var workspaceMenu: some View {
        Menu {
            Picker("Workspace", selection: Binding(
                get: { store.currentWorkspaceID },
                set: { store.switchWorkspace(to: $0) }
            )) {
                ForEach(store.workspaces) { Text($0.name).tag($0.id) }
            }
            .pickerStyle(.inline)
            Divider()
            Button("New Workspace…") { workspaceSheet = .new }
            Button("Duplicate Workspace…") { workspaceSheet = .duplicate }
            Button("Rename Workspace…") { workspaceSheet = .rename }
            Menu("Compare With") {
                ForEach(store.workspaces.filter { $0.id != store.currentWorkspaceID }) { ws in
                    Button(ws.name) {
                        overlay = .compare(DiffPresentation(title: "\(ws.name) vs \(store.currentWorkspace.name)",
                                                           oldLabel: ws.name, newLabel: store.currentWorkspace.name,
                                                           old: ws.policy, new: store.text))
                    }
                }
            }
            .disabled(store.workspaces.count < 2)
            Button("Delete Workspace…") { confirmingDelete = true }
                .disabled(store.workspaces.count < 2)
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "square.stack")
                    .font(.system(size: 10.5))
                Text(store.currentWorkspace.name)
                    .font(.system(size: 12, weight: .semibold))
                    .lineLimit(1)
            }
        }
        .menuStyle(.borderlessButton)
        .foregroundStyle(Theme.textPrimary)
        .help("Switch between workspaces — each has its own policy and Headscale or Tailscale server")
        .padding(.horizontal, 10)
        .padding(.bottom, 8)
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Image(nsImage: NSApp.applicationIconImage)
                    .resizable()
                    .frame(width: 24, height: 24)
                Text("Tailscale ACL")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(Theme.textPrimary)
            }
            .padding(.horizontal, 14)
            .padding(.top, 14)
            .padding(.bottom, 10)
            workspaceMenu

            Button { overlay = .search } label: {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .font(.system(size: 11, weight: .medium))
                    Text("Search")
                        .font(.system(size: 12))
                    Spacer()
                    Text("⌘K")
                        .font(.system(size: 10.5, design: .monospaced))
                        .foregroundStyle(Theme.textSecondary)
                }
                .foregroundStyle(Theme.textSecondary)
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .background(RoundedRectangle(cornerRadius: 8).fill(Color.white.opacity(0.05)))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.panelBorder, lineWidth: 1))
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .keyboardShortcut("k", modifiers: .command)
            .disabled(!store.isValid)
            .padding(.horizontal, 10)
            .padding(.bottom, 8)

            VStack(spacing: 2) {
                ForEach(Screen.allCases) { s in
                    sidebarItem(s)
                }
            }
            .padding(.horizontal, 8)

            Spacer()

            let results = store.testResults
            let problems = store.lintIssues.count
            VStack(alignment: .leading, spacing: 6) {
                StatusPill(label: store.isValid ? "Policy valid" : "Policy invalid",
                           ok: store.isValid)
                StatusPill(
                    label: "\(results.filter(\.passed).count)/\(results.count) tests pass",
                    ok: !results.isEmpty && results.allSatisfy(\.passed)
                )
                StatusPill(
                    label: problems == 0 ? "No problems" : "\(problems) problem\(problems == 1 ? "" : "s")",
                    ok: problems == 0
                )
            }
            .padding(10)
        }
        .frame(width: 210)
        .background(Theme.sidebar)
    }

    private func sidebarItem(_ s: Screen) -> some View {
        Button {
            screen = s
        } label: {
            HStack(spacing: 10) {
                Image(systemName: s.icon)
                    .font(.system(size: 12, weight: .medium))
                    .frame(width: 17)
                Text(s.rawValue)
                    .font(.system(size: 12.5, weight: screen == s ? .semibold : .regular))
                Spacer()
            }
            .foregroundStyle(screen == s ? Theme.textPrimary : Theme.textPrimary.opacity(0.78))
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(screen == s ? Color.white.opacity(0.08) : Color.clear)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    @ViewBuilder
    private var content: some View {
        switch screen {
        case .accessMap: AccessMapScreen()
        case .policyEditor: PolicyEditorScreen()
        case .accessMatrix: AccessMatrixScreen()
        case .visualBuilder: VisualBuilderScreen()
        case .accessSimulator: SimulatorScreen()
        case .ssh: SSHScreen()
        case .tests: TestsScreen()
        case .routes: RoutesScreen()
        case .problems: ProblemsScreen()
        case .headscale: HeadscaleScreen()
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    // Icon comes from the bundled AppIcon.icns (regenerate with
    // assets/make-icon.swift) — setting it at runtime is unreliable.
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }
}

@main
struct TailscaleACLApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var store = PolicyStore()
    @StateObject private var updater = UpdaterViewModel()

    var body: some SwiftUI.Scene {
        WindowGroup("Tailscale ACL") {
            RootView()
                .environmentObject(store)
        }
        .defaultSize(width: 1440, height: 900)
        .commands {
            CommandGroup(after: .appInfo) {
                Button("Check for Updates…") {
                    updater.checkForUpdates()
                }
                .disabled(!updater.canCheckForUpdates)
            }
        }
    }
}


/// Name a new, duplicated, or renamed workspace.
struct WorkspaceSheet: View {
    enum Mode: String, Identifiable {
        case new, duplicate, rename
        var id: String { rawValue }
    }

    var mode: Mode
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(title)
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            Text(detail)
                .font(.system(size: 11))
                .foregroundStyle(Theme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            TextField("Name, e.g. Home lab or a customer", text: $name)
                .textFieldStyle(.roundedBorder)
                .onSubmit(save)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(mode == .rename ? "Rename" : "Create", action: save)
                    .keyboardShortcut(.defaultAction)
                    .disabled(trimmed.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 400)
        .background(Theme.background)
        .onAppear {
            name = mode == .rename ? store.currentWorkspace.name
                : mode == .duplicate ? "\(store.currentWorkspace.name) copy" : ""
        }
    }

    private var trimmed: String { name.trimmingCharacters(in: .whitespaces) }

    private var title: String {
        switch mode {
        case .new: return "New workspace"
        case .duplicate: return "Duplicate workspace"
        case .rename: return "Rename workspace"
        }
    }

    private var detail: String {
        switch mode {
        case .new: return "Starts with an empty policy and no server. Pull from a Headscale or Tailscale server, import a policy file, or use Templates to fill it."
        case .duplicate: return "Copies the current policy, server URL, and API key."
        case .rename: return "Only the name changes."
        }
    }

    private func save() {
        guard !trimmed.isEmpty else { return }
        switch mode {
        case .new: store.addWorkspace(name: trimmed, duplicatingCurrent: false)
        case .duplicate: store.addWorkspace(name: trimmed, duplicatingCurrent: true)
        case .rename: store.renameWorkspace(store.currentWorkspaceID, to: trimmed)
        }
        dismiss()
    }
}
