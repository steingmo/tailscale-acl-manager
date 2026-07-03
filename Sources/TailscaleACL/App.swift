import SwiftUI
import AppKit

enum Screen: String, CaseIterable, Identifiable {
    case policyEditor = "Policy Editor"
    case accessMatrix = "Access Matrix"
    case visualBuilder = "Visual Builder"
    case accessSimulator = "Access Simulator"
    case tests = "Tests"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .policyEditor: return "doc.text"
        case .accessMatrix: return "tablecells"
        case .visualBuilder: return "point.3.connected.trianglepath.dotted"
        case .accessSimulator: return "play"
        case .tests: return "checkmark.shield"
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
            VStack(alignment: .leading, spacing: 6) {
                StatusPill(label: store.isValid ? "Policy valid" : "Policy invalid",
                           ok: store.isValid)
                StatusPill(
                    label: "\(results.filter(\.passed).count)/\(results.count) tests pass",
                    ok: !results.isEmpty && results.allSatisfy(\.passed)
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
        case .tests: TestsScreen()
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.applicationIconImage = Self.makeIcon()
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    /// Drawn app icon: dark rounded square with a green shield.
    static func makeIcon() -> NSImage {
        let size = NSSize(width: 512, height: 512)
        let image = NSImage(size: size)
        image.lockFocus()

        let rect = NSRect(x: 32, y: 32, width: 448, height: 448)
        let path = NSBezierPath(roundedRect: rect, xRadius: 100, yRadius: 100)
        let gradient = NSGradient(
            starting: NSColor(srgbRed: 0.13, green: 0.14, blue: 0.16, alpha: 1),
            ending: NSColor(srgbRed: 0.07, green: 0.08, blue: 0.09, alpha: 1)
        )
        gradient?.draw(in: path, angle: -90)

        if let shield = NSImage(
            systemSymbolName: "checkmark.shield.fill",
            accessibilityDescription: nil
        )?.withSymbolConfiguration(
            .init(pointSize: 240, weight: .medium)
                .applying(.init(paletteColors: [
                    NSColor(srgbRed: 0.19, green: 0.83, blue: 0.48, alpha: 1)
                ]))
        ) {
            let s = shield.size
            shield.draw(in: NSRect(
                x: (size.width - s.width) / 2,
                y: (size.height - s.height) / 2,
                width: s.width, height: s.height
            ))
        }

        image.unlockFocus()
        return image
    }
}

@main
struct TailscaleACLApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var store = PolicyStore()

    var body: some SwiftUI.Scene {
        WindowGroup("Tailscale ACL") {
            RootView()
                .environmentObject(store)
        }
        .defaultSize(width: 1440, height: 900)
    }
}
