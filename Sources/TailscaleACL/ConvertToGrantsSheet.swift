import SwiftUI

/// Preview of rewriting the ACLs as grants, with proof that access is unchanged.
struct ConvertToGrantsSheet: View {
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var showingDiff = false

    private struct Preview {
        var text: String
        var aclCount: Int
        var grantCount: Int
        var differences: [String]
        var deviceChanges: [AccessChange]
    }

    private var preview: Preview? {
        guard var tree = store.tree else { return nil }
        let before = store.model
        let converted = convertACLsToGrants(&tree)
        guard converted > 0 else { return nil }
        let after = PolicyModel(tree: tree)
        return Preview(text: HuJSONSerializer.serialize(tree), aclCount: converted,
                       grantCount: after.grants.count - before.grants.count,
                       differences: entityAccessDifferences(before, after),
                       deviceChanges: accessChanges(from: before, to: after, nodes: store.headscaleNodes))
    }

    var body: some View {
        let p = preview
        VStack(alignment: .leading, spacing: 14) {
            Text("Convert ACLs to grants")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            if let p {
                Text(verbatim: "\(p.aclCount) ACL rule\(p.aclCount == 1 ? "" : "s") become\(p.aclCount == 1 ? "s" : "") \(p.grantCount) grant\(p.grantCount == 1 ? "" : "s"). An ACL whose destinations use different ports is split into one grant per port list. Comments, expiry dates, and posture requirements carry over.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                let same = p.differences.isEmpty && p.deviceChanges.isEmpty
                Label(same ? "Access is unchanged: every user, group, tag, host, and autogroup reaches exactly the same destinations and ports\(store.headscaleNodes.isEmpty ? "" : ", and so does every device")."
                      : "Access would change — this shouldn't happen; please report it:",
                      systemImage: same ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundStyle(same ? Theme.green : Theme.red)
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(p.differences, id: \.self) { d in
                    Text(verbatim: d).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Theme.textSecondary)
                }
                ForEach(p.deviceChanges) { c in
                    Text(verbatim: "\(c.src) → \(c.dst): +\(c.gained.joined(separator: ",")) −\(c.lost.joined(separator: ","))")
                        .font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Theme.textSecondary)
                }
                if store.currentWorkspace.kind == .headscale {
                    Label("Headscale supports grants from version 0.29.0. Older servers reject the converted policy on push.",
                          systemImage: "info.circle")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                HStack {
                    Button("Show text changes") { showingDiff = true }
                    Spacer()
                    Button("Cancel") { dismiss() }
                        .keyboardShortcut(.cancelAction)
                    Button(same ? "Convert" : "Convert anyway") {
                        store.convertToGrants()
                        dismiss()
                    }
                    .keyboardShortcut(.defaultAction)
                }
                .sheet(isPresented: $showingDiff) {
                    DiffSheet(diff: DiffPresentation(title: "ACLs → grants", oldLabel: "now", newLabel: "converted",
                                                     old: store.text, new: p.text))
                }
            } else {
                Text("There are no ACL rules to convert.")
                    .foregroundStyle(Theme.textSecondary)
                Button("Close") { dismiss() }
            }
        }
        .padding(20)
        .frame(width: 520)
        .background(Theme.background)
    }
}
