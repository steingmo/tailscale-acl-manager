import SwiftUI

enum CopyPayload {
    case rule(RuleSummary)
    case entities([String])
    case template(PolicyTemplate, [String: String])

    var title: String {
        switch self {
        case .rule(let r): return "Copy \u{201C}\(r.name)\u{201D} to other workspaces"
        case .entities(let names): return "Copy \(names.joined(separator: ", ")) to other workspaces"
        case .template(let t, _): return "Add \u{201C}\(t.title)\u{201D} to other workspaces"
        }
    }
}

/// Pick target workspaces and copy a rule, definitions, or template into them.
/// Groups, tags, hosts, and IP sets a rule needs come along when missing;
/// existing definitions in the target are never overwritten.
struct CopyToWorkspacesSheet: View {
    var payload: CopyPayload
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var selected: Set<UUID> = []
    @State private var results: [(name: String, outcome: CopyOutcome)]?

    private var others: [Workspace] { store.workspaces.filter { $0.id != store.currentWorkspaceID } }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(payload.title)
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
            Text("Missing groups, tags, hosts, and IP sets come along; existing ones in the target are kept as they are. Each target saves a version before and after in its History.")
                .font(.system(size: 11))
                .foregroundStyle(Theme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            if let results {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(results.indices, id: \.self) { i in
                        let r = results[i]
                        Label("\(r.name): \(describe(r.outcome))",
                              systemImage: r.outcome == .copied ? "checkmark.circle.fill"
                                : r.outcome == .alreadyThere ? "equal.circle" : "xmark.octagon.fill")
                            .font(.system(size: 12))
                            .foregroundStyle(r.outcome == .copied ? Theme.green
                                             : r.outcome == .alreadyThere ? Theme.textSecondary : Theme.red)
                    }
                }
            } else {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(others) { ws in
                        Toggle(ws.name, isOn: Binding(
                            get: { selected.contains(ws.id) },
                            set: { if $0 { selected.insert(ws.id) } else { selected.remove(ws.id) } }))
                            .font(.system(size: 12.5))
                    }
                }
            }
            HStack {
                Spacer()
                if results == nil {
                    Button("Cancel") { dismiss() }
                        .keyboardShortcut(.cancelAction)
                    Button("Copy") { copy() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(selected.isEmpty || store.tree == nil)
                } else {
                    Button("Done") { dismiss() }
                        .keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(20)
        .frame(width: 440)
        .background(Theme.background)
    }

    private func describe(_ outcome: CopyOutcome) -> String {
        switch outcome {
        case .copied: return "copied"
        case .alreadyThere: return "already there"
        case .failed(let why): return "not copied — \(why)"
        }
    }

    private func copy() {
        guard let source = store.tree else { return }
        let reason = "copied from \(store.currentWorkspace.name)"
        let targets = others.map(\.id).filter(selected.contains)
        switch payload {
        case .rule(let r):
            results = store.modifyWorkspaces(targets, reason: reason) {
                copyRule(section: r.section, index: r.index, from: source, into: $0)
            }
        case .entities(let names):
            results = store.modifyWorkspaces(targets, reason: reason) {
                copyEntities(names, from: source, into: $0)
            }
        case .template(let t, let values):
            results = store.modifyWorkspaces(targets, reason: "template \(t.title)") {
                applyTemplate(t, values: values, to: $0)
            }
        }
    }
}
