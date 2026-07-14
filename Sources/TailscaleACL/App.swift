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
    case policyEditor = "Policy Editor"
    case accessMatrix = "Access Matrix"
    case visualBuilder = "Visual Builder"
    case accessSimulator = "Access Simulator"
    case ssh = "SSH"
    case tests = "Tests"
    case problems = "Problems"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .policyEditor: return "doc.text"
        case .accessMatrix: return "tablecells"
        case .visualBuilder: return "point.3.connected.trianglepath.dotted"
        case .accessSimulator: return "play"
        case .ssh: return "terminal"
        case .tests: return "checkmark.shield"
        case .problems: return "exclamationmark.triangle"
        }
    }
}

struct RootView: View {
    @EnvironmentObject var store: PolicyStore
    @State private var screen: Screen = .policyEditor

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Divider()
                .overlay(Theme.panelBorder)
            content
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(Theme.background)
        .preferredColorScheme(.dark)
        .frame(minWidth: 980, minHeight: 620)
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Tailscale ACL")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Theme.textSecondary)
                .padding(.horizontal, 16)
                .padding(.top, 14)
                .padding(.bottom, 9)

            VStack(spacing: 1) {
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
        .frame(width: 190)
        .background(Theme.sidebar)
    }

    private func sidebarItem(_ s: Screen) -> some View {
        Button {
            screen = s
        } label: {
            HStack(spacing: 8) {
                Image(systemName: s.icon)
                    .font(.system(size: 11, weight: .medium))
                    .frame(width: 15)
                Text(s.rawValue)
                    .font(.system(size: 12, weight: screen == s ? .semibold : .regular))
                Spacer()
            }
            .foregroundStyle(Theme.textPrimary)
            .padding(.horizontal, 9)
            .padding(.vertical, 6)
            .background(
                RoundedRectangle(cornerRadius: 6)
                    .fill(screen == s ? Color.white.opacity(0.09) : Color.clear)
            )
        }
        .buttonStyle(.plain)
    }

    @ViewBuilder
    private var content: some View {
        switch screen {
        case .policyEditor: PolicyEditorScreen()
        case .accessMatrix: AccessMatrixScreen()
        case .visualBuilder: VisualBuilderScreen()
        case .accessSimulator: SimulatorScreen()
        case .ssh: SSHScreen()
        case .tests: TestsScreen()
        case .problems: ProblemsScreen()
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
