import SwiftUI

struct DiffPresentation: Identifiable {
    let id = UUID()
    var title: String
    var oldLabel: String
    var newLabel: String
    var old: String
    var new: String
}

/// Line-by-line comparison of two policy texts (unchanged runs collapsed).
struct DiffSheet: View {
    var diff: DiffPresentation
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        let lines = lineDiff(old: diff.old, new: diff.new)
        let changed = lines.contains { $0.kind == .added || $0.kind == .removed }
        VStack(alignment: .leading, spacing: 12) {
            Text(diff.title)
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            HStack(spacing: 14) {
                Text(verbatim: "− \(diff.oldLabel)").foregroundStyle(Theme.red)
                Text(verbatim: "+ \(diff.newLabel)").foregroundStyle(Theme.green)
            }
            .font(.system(size: 11.5, design: .monospaced))

            if changed {
                ScrollView([.vertical, .horizontal]) {
                    VStack(alignment: .leading, spacing: 0) {
                        ForEach(lines) { line in row(line) }
                    }
                    .padding(8)
                }
                .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: Theme.editorBackground)))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.panelBorder, lineWidth: 1))
            } else {
                Label("No differences.", systemImage: "checkmark.circle")
                    .font(.system(size: 12.5))
                    .foregroundStyle(Theme.green)
            }

            HStack {
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 720, height: changed ? 560 : nil)
        .background(Theme.background)
    }

    @ViewBuilder
    private func row(_ line: DiffLine) -> some View {
        switch line.kind {
        case .skipped:
            Text(verbatim: "⋯ \(line.text) unchanged line\(line.text == "1" ? "" : "s")")
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(Theme.textSecondary)
                .padding(.vertical, 3)
        default:
            let (prefix, color): (String, Color) = line.kind == .added ? ("+ ", Theme.green)
                : line.kind == .removed ? ("− ", Theme.red) : ("  ", Theme.textPrimary.opacity(0.75))
            Text(verbatim: prefix + line.text)
                .font(.system(size: 11.5, design: .monospaced))
                .foregroundStyle(color)
                .fixedSize()
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(line.kind == .same ? Color.clear : color.opacity(0.10))
        }
    }
}
