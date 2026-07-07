import SwiftUI

extension Color {
    init(hex: UInt32) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255
        )
    }
}

enum Theme {
    static let background = Color(hex: 0x141414)
    static let panel = Color(hex: 0x1D1D1F)
    static let panelBorder = Color(hex: 0x2C2C2E)
    static let sidebar = Color(hex: 0x181818)
    static let editorBackground = NSColor(srgbRed: 0.09, green: 0.09, blue: 0.10, alpha: 1)

    static let green = Color(hex: 0x30D47B)
    static let red = Color(hex: 0xFF6B6B)
    static let orange = Color(hex: 0xF5A97F)
    static let blue = Color(hex: 0x6CB2FF)
    static let purple = Color(hex: 0xB29BF5)
    static let pink = Color(hex: 0xF06292)
    static let textPrimary = Color(hex: 0xEDEDED)
    static let textSecondary = Color(hex: 0x9A9AA2)

    static func entityColor(_ name: String) -> Color {
        if name == "*" { return red }
        if name.hasPrefix("autogroup:") { return pink }
        if name.hasPrefix("group:") { return blue }
        if name.hasPrefix("tag:") { return purple }
        return orange // hosts / IP sets
    }

    static func entityIcon(_ name: String) -> String {
        if name == "*" { return "asterisk" }
        if name.hasPrefix("autogroup:") { return "globe" }
        if name.hasPrefix("group:") { return "person.2" }
        if name.hasPrefix("tag:") { return "tag" }
        if name.hasPrefix("ipset:") { return "square.stack.3d.up" }
        return "server.rack"
    }
}

/// Colored pill chip used for entities, ports, and assertions.
struct Chip: View {
    var text: String
    var color: Color
    var icon: String?

    var body: some View {
        HStack(spacing: 4) {
            if let icon {
                Image(systemName: icon)
                    .font(.system(size: 9.5, weight: .medium))
            }
            Text(text)
                .font(.system(size: 11, weight: .medium, design: .monospaced))
        }
        .foregroundStyle(color)
        .padding(.horizontal, 6)
        .padding(.vertical, 3)
        .background(color.opacity(0.13), in: RoundedRectangle(cornerRadius: 5))
    }
}

struct EntityChip: View {
    var name: String

    var body: some View {
        Chip(text: name, color: Theme.entityColor(name), icon: Theme.entityIcon(name))
    }
}

/// Small round status dot + label, used in the sidebar footer.
struct StatusPill: View {
    var label: String
    var ok: Bool

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(ok ? Theme.green : Theme.red)
                .frame(width: 7, height: 7)
            Text(label)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Theme.textPrimary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(Capsule().fill(Color.white.opacity(0.06)))
        .overlay(Capsule().stroke(Color.white.opacity(0.08), lineWidth: 1))
    }
}

struct ToolbarButton: View {
    var label: String
    var icon: String
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Image(systemName: icon)
                    .font(.system(size: 10.5, weight: .semibold))
                Text(label)
                    .font(.system(size: 11.5, weight: .semibold))
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(Capsule().fill(Color.white.opacity(0.07)))
            .overlay(Capsule().stroke(Color.white.opacity(0.08), lineWidth: 1))
        }
        .buttonStyle(.plain)
        .foregroundStyle(Theme.textPrimary)
    }
}
