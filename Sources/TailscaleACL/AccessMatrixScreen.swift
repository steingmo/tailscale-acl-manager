import SwiftUI

/// Grid of source entities × destination targets showing which ports are open.
struct AccessMatrixScreen: View {
    @EnvironmentObject var store: PolicyStore

    private var rows: [String] { store.model.sourceSpecs }
    private var columns: [String] { store.model.destTargets }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 3) {
                Text("Access Matrix")
                    .font(.system(size: 16, weight: .bold))
                    .foregroundStyle(Theme.textPrimary)
                Text("Which ports each source can reach on each destination")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.textSecondary)
            }
            .padding(16)

            if store.isValid {
                ScrollView([.horizontal, .vertical]) {
                    matrixGrid
                        .padding([.horizontal, .bottom], 16)
                }
            } else {
                invalidNotice
            }
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Theme.background)
    }

    private var matrixGrid: some View {
        Grid(alignment: .leading, horizontalSpacing: 6, verticalSpacing: 6) {
            GridRow {
                Text("src \\ dst")
                    .font(.system(size: 10, weight: .semibold, design: .monospaced))
                    .foregroundStyle(Theme.textSecondary)
                    .gridColumnAlignment(.leading)
                ForEach(columns, id: \.self) { col in
                    EntityChip(name: col)
                }
            }
            ForEach(rows, id: \.self) { row in
                GridRow {
                    EntityChip(name: row)
                    ForEach(columns, id: \.self) { col in
                        cell(row: row, col: col)
                    }
                }
            }
        }
    }

    private func cell(row: String, col: String) -> some View {
        let ports = allowedPorts(from: row, to: col)
        return Group {
            if ports.isEmpty {
                Text("—")
                    .font(.system(size: 10.5, design: .monospaced))
                    .foregroundStyle(Theme.textSecondary.opacity(0.5))
                    .frame(maxWidth: .infinity, minHeight: 26)
            } else {
                Text(ports.joined(separator: ", "))
                    .font(.system(size: 10.5, weight: .medium, design: .monospaced))
                    .foregroundStyle(Theme.green)
                    .lineLimit(1)
                    .padding(.horizontal, 7)
                    .frame(maxWidth: .infinity, minHeight: 26)
                    .background(Theme.green.opacity(0.10), in: RoundedRectangle(cornerRadius: 5))
            }
        }
        .frame(minWidth: 88)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(Color.white.opacity(ports.isEmpty ? 0.02 : 0))
        )
        .help(ports.isEmpty
              ? "\(row) cannot reach \(col)"
              : "\(row) → \(col) on ports \(ports.joined(separator: ", "))")
    }

    private func allowedPorts(from row: String, to col: String) -> [String] {
        let evaluator = store.evaluator
        var ports: [String] = []
        for rule in store.model.rules where rule.action == "accept" {
            for src in rule.src where evaluator.sourceSpecCovers(spec: src, row: row) {
                for dst in rule.dst {
                    let d = DestSpec(dst)
                    if d.target == col || d.target == "*" || evaluator.targetMatches(target: d.target, destID: col) {
                        ports.append(d.ports == "*" ? "all" : d.ports)
                    }
                }
            }
        }
        for grant in store.model.grants {
            for src in grant.src where evaluator.sourceSpecCovers(spec: src, row: row) {
                for dst in grant.dst
                where dst == col || dst == "*" || evaluator.targetMatches(target: dst, destID: col) {
                    ports.append(contentsOf: grant.ip.map { $0 == "*" ? "all" : $0 })
                }
            }
        }
        return ports.uniqued()
    }

    private var invalidNotice: some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(Theme.orange)
            Text("Fix the policy in the editor to see the access matrix.")
                .foregroundStyle(Theme.textSecondary)
        }
        .padding(20)
    }
}
