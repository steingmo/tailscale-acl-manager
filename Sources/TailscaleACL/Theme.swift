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
    static let background = Color(hex: 0x18191C)
    static let panel = Color(hex: 0x222429)
    static let panelBorder = Color(hex: 0x33353B)
    static let sidebar = Color(hex: 0x1B1C20)
    /// Connection lines on the maps.
    static let lineBlue = Color(hex: 0x2FA8E8)
    static let lineGreen = Color(hex: 0x3CCB7F)
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
        if name.contains("@") { return green } // users
        return orange // hosts / IP sets
    }

    static func entityIcon(_ name: String) -> String {
        if name == "*" { return "asterisk" }
        if name.hasPrefix("autogroup:") { return "globe" }
        if name.hasPrefix("group:") { return "person.2" }
        if name.hasPrefix("tag:") { return "tag" }
        if name.hasPrefix("ipset:") { return "square.stack.3d.up" }
        if name.contains("@") { return "person" }
        return "server.rack"
    }
}

/// Colored pill chip used for entities, ports, and assertions.
/// Lays children out left to right, wrapping onto new lines — for chip lists
/// whose length depends on the policy.
struct FlowLayout: Layout {
    var spacing: CGFloat = 6
    var lineSpacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let rows = arrange(proposal.width ?? .infinity, subviews)
        let width = rows.map { $0.width }.max() ?? 0
        let height = rows.map(\.height).reduce(0, +) + lineSpacing * CGFloat(max(rows.count - 1, 0))
        return CGSize(width: min(width, proposal.width ?? width), height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var y = bounds.minY
        for row in arrange(bounds.width, subviews) {
            var x = bounds.minX
            for i in row.items {
                let size = subviews[i].sizeThatFits(.unspecified)
                subviews[i].place(at: CGPoint(x: x, y: y + (row.height - size.height) / 2), proposal: .unspecified)
                x += size.width + spacing
            }
            y += row.height + lineSpacing
        }
    }

    private func arrange(_ maxWidth: CGFloat, _ subviews: Subviews) -> [(items: [Int], width: CGFloat, height: CGFloat)] {
        var rows: [(items: [Int], width: CGFloat, height: CGFloat)] = []
        var current: (items: [Int], width: CGFloat, height: CGFloat) = ([], 0, 0)
        for i in subviews.indices {
            let size = subviews[i].sizeThatFits(.unspecified)
            let needed = current.items.isEmpty ? size.width : current.width + spacing + size.width
            if needed > maxWidth, !current.items.isEmpty {
                rows.append(current)
                current = ([i], size.width, size.height)
            } else {
                current = (current.items + [i], needed, max(current.height, size.height))
            }
        }
        if !current.items.isEmpty { rows.append(current) }
        return rows
    }
}

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
                .lineLimit(1)
        }
        .fixedSize()  // never squeeze into a column of letters
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

/// Subtle dot grid drawn behind the map canvases.
struct DotGrid: View {
    var spacing: CGFloat = 18

    var body: some View {
        Canvas { ctx, size in
            var dots = Path()
            for x in stride(from: spacing / 2, to: size.width, by: spacing) {
                for y in stride(from: spacing / 2, to: size.height, by: spacing) {
                    dots.addEllipse(in: CGRect(x: x - 0.8, y: y - 0.8, width: 1.6, height: 1.6))
                }
            }
            ctx.fill(dots, with: .color(.white.opacity(0.07)))
        }
    }
}

/// Segmented tabs in a rounded container (icon + label per tab).
struct PillTabs<T: Hashable>: View {
    var tabs: [(value: T, label: String, icon: String)]
    @Binding var selection: T

    var body: some View {
        HStack(spacing: 2) {
            ForEach(tabs.indices, id: \.self) { i in
                let tab = tabs[i]
                let selected = tab.value == selection
                Button { selection = tab.value } label: {
                    HStack(spacing: 6) {
                        Image(systemName: tab.icon)
                            .font(.system(size: 11, weight: .medium))
                        Text(tab.label)
                            .font(.system(size: 12.5, weight: selected ? .semibold : .regular))
                    }
                    .foregroundStyle(selected ? Theme.textPrimary : Theme.textSecondary)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 7)
                    .background(RoundedRectangle(cornerRadius: 7)
                        .fill(selected ? Color.white.opacity(0.09) : Color.clear))
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .padding(3)
        .background(RoundedRectangle(cornerRadius: 10).fill(Theme.panel))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Theme.panelBorder, lineWidth: 1))
    }
}

/// Render a view to PNG data at 2x, in the app's dark appearance.
@MainActor
func renderPNG<V: View>(_ view: V) -> Data? {
    let renderer = ImageRenderer(content: view.environment(\.colorScheme, .dark))
    renderer.scale = 2
    guard let image = renderer.nsImage, let tiff = image.tiffRepresentation,
          let rep = NSBitmapImageRep(data: tiff) else { return nil }
    return rep.representation(using: .png, properties: [:])
}

extension Comparable {
    func clamped(to range: ClosedRange<Self>) -> Self { min(max(self, range.lowerBound), range.upperBound) }
}
