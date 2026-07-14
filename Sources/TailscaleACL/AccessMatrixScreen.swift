import SwiftUI

/// One access edge contributing to a matrix cell.
struct CellConnection: Identifiable {
    var kind: RuleMatch.Kind
    var ruleIndex: Int
    var srcs: [String]
    var dstRaw: String    // ACL: dst spec incl. ports; grant: dst name
    var portsDisplay: String
    var ports: String     // for the edit sheet
    var proto: String

    var id: String { "\(kind)-\(ruleIndex)-\(dstRaw)" }
}

private struct Cell: Identifiable {
    var row: String
    var col: String
    var id: String { "\(row)|\(col)" }
}

/// Grid of source entities × destination targets showing which ports are
/// open. Cells are clickable: add, edit, or remove access in place.
struct AccessMatrixScreen: View {
    @EnvironmentObject var store: PolicyStore
    @State private var selectedCell: Cell?

    private var rows: [String] { store.model.sourceSpecs }
    private var columns: [String] { store.model.destTargets }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 3) {
                Text("Access Matrix")
                    .font(.system(size: 16, weight: .bold))
                    .foregroundStyle(Theme.textPrimary)
                Text("Which ports each source can reach on each destination · click a cell to add, edit, or remove access")
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
        .sheet(item: $selectedCell) { cell in
            MatrixCellSheet(row: cell.row, col: cell.col)
        }
    }

    /// All rules/grants contributing access from `row` to `col`.
    static func cellConnections(model: PolicyModel, evaluator: Evaluator,
                                row: String, col: String) -> [CellConnection] {
        var out: [CellConnection] = []
        for rule in model.rules where rule.action == "accept" {
            guard rule.src.contains(where: { evaluator.sourceSpecCovers(spec: $0, row: row) })
            else { continue }
            for dst in rule.dst {
                let d = DestSpec(dst)
                if d.target == col || d.target == "*"
                    || evaluator.targetMatches(target: d.target, destID: col) {
                    out.append(CellConnection(
                        kind: .acl, ruleIndex: rule.index, srcs: rule.src,
                        dstRaw: dst, portsDisplay: d.ports,
                        ports: d.ports, proto: rule.proto ?? "any"
                    ))
                }
            }
        }
        for grant in model.grants {
            guard grant.src.contains(where: { evaluator.sourceSpecCovers(spec: $0, row: row) })
            else { continue }
            for dst in grant.dst
            where dst == col || dst == "*" || evaluator.targetMatches(target: dst, destID: col) {
                let split = PolicyStore.splitIPEntries(grant.ip)
                out.append(CellConnection(
                    kind: .grant, ruleIndex: grant.index, srcs: grant.src,
                    dstRaw: dst, portsDisplay: grant.ip.joined(separator: ", "),
                    ports: split.ports, proto: split.proto
                ))
            }
        }
        return out
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
        return Button {
            selectedCell = Cell(row: row, col: col)
        } label: {
            Group {
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
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(ports.isEmpty
              ? "\(row) cannot reach \(col) — click to grant access"
              : "\(row) → \(col) on ports \(ports.joined(separator: ", ")) — click to edit")
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

// MARK: - Cell sheet

private struct MatrixCellSheet: View {
    var row: String
    var col: String
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var editing: CellConnection?
    @State private var adding = false

    private var connections: [CellConnection] {
        AccessMatrixScreen.cellConnections(model: store.model,
                                           evaluator: store.evaluator,
                                           row: row, col: col)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Access")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            HStack(spacing: 8) {
                EntityChip(name: row)
                Image(systemName: "arrow.right")
                    .foregroundStyle(Theme.textSecondary)
                EntityChip(name: col)
            }

            if connections.isEmpty {
                Text("No rule allows this connection.")
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.textSecondary)
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(connections) { conn in
                        connectionRow(conn)
                    }
                }
            }

            HStack {
                Button {
                    adding = true
                } label: {
                    Label("Add access", systemImage: "plus")
                        .font(.system(size: 12, weight: .semibold))
                }
                .buttonStyle(.plain)
                .foregroundStyle(Theme.blue)
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 480)
        .background(Theme.background)
        .sheet(item: $editing) { conn in
            ConnectionSheet(
                title: conn.kind == .grant ? "Edit access (grant)" : "Edit access (ACL)",
                src: conn.srcs.joined(separator: ", "),
                dstTarget: conn.dstRaw,
                initialPorts: conn.ports,
                initialProto: conn.proto,
                showRemove: true,
                allowTypeChoice: false,
                initialIsGrant: conn.kind == .grant,
                onSave: { ports, proto, _ in
                    if conn.kind == .grant {
                        store.updateGrantIP(grantIndex: conn.ruleIndex,
                                            ports: ports, proto: proto)
                    } else {
                        store.updateConnection(ruleIndex: conn.ruleIndex, oldDst: conn.dstRaw,
                                               newPorts: ports, proto: proto)
                    }
                },
                onRemove: {
                    if conn.kind == .grant {
                        store.removeGrantConnection(grantIndex: conn.ruleIndex, dst: conn.dstRaw)
                    } else {
                        store.removeConnection(ruleIndex: conn.ruleIndex, dst: conn.dstRaw)
                    }
                }
            )
        }
        .sheet(isPresented: $adding) {
            ConnectionSheet(
                title: "Grant access",
                src: row,
                dstTarget: col,
                initialPorts: "",
                initialProto: "any",
                showRemove: false,
                allowTypeChoice: true,
                initialIsGrant: true,
                onSave: { ports, proto, isGrant in
                    let p = ports.isEmpty ? "*" : ports
                    if isGrant {
                        store.addGrant(src: row, dstTarget: col, ports: p, proto: proto)
                    } else {
                        store.addRule(src: row, dstTarget: col, ports: p, proto: proto)
                    }
                },
                onRemove: {}
            )
        }
    }

    private func connectionRow(_ conn: CellConnection) -> some View {
        HStack(spacing: 8) {
            Text(conn.kind == .grant ? "Grant #\(conn.ruleIndex + 1)" : "Rule #\(conn.ruleIndex + 1)")
                .font(.system(size: 10, weight: .bold))
                .foregroundStyle(conn.kind == .grant ? Theme.green : Theme.blue)
                .padding(.horizontal, 5)
                .padding(.vertical, 3)
                .background((conn.kind == .grant ? Theme.green : Theme.blue).opacity(0.15),
                            in: RoundedRectangle(cornerRadius: 4))
            Text("\(conn.srcs.joined(separator: ", ")) → \(conn.dstRaw)")
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(Theme.textPrimary)
                .lineLimit(1)
            Chip(text: conn.portsDisplay, color: Theme.orange)
            Spacer()
            Button("Edit") { editing = conn }
                .font(.system(size: 11))
        }
        .padding(.vertical, 2)
    }
}
