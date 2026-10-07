import SwiftUI

/// Snapshots of this workspace's policy: compare any with the editor, or restore.
struct HistorySheet: View {
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var snapshots: [Snapshot] = []
    @State private var comparing: DiffPresentation?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Version history")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundStyle(Theme.textPrimary)
                    Text("Saved when the workspace opens, and before and after pulls, imports, pushes, and restores. The newest 100 are kept.")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                Button("Save snapshot now") {
                    store.snapshot(reason: "saved by hand")
                    snapshots = SnapshotStore.load(store.currentWorkspaceID)
                }
            }
            ScrollView {
                VStack(spacing: 1) {
                    ForEach(snapshots) { snap in
                        HStack(spacing: 10) {
                            Image(systemName: snap.text == store.text ? "checkmark.circle.fill" : "clock")
                                .font(.system(size: 11))
                                .foregroundStyle(snap.text == store.text ? Theme.green : Theme.textSecondary)
                                .help(snap.text == store.text ? "Same as the editor" : "")
                            Text(snap.date.formatted(date: .abbreviated, time: .shortened))
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundStyle(Theme.textPrimary)
                            Text(snap.reason)
                                .font(.system(size: 11))
                                .foregroundStyle(Theme.textSecondary)
                            Spacer()
                            Button("Compare…") {
                                comparing = DiffPresentation(title: "Snapshot vs editor",
                                                             oldLabel: "snapshot (\(snap.reason))", newLabel: "in the editor",
                                                             old: snap.text, new: store.text)
                            }
                            .disabled(snap.text == store.text)
                            Button("Restore") {
                                store.loadPolicy(snap.text, reason: "restored snapshot")
                                dismiss()
                            }
                            .disabled(snap.text == store.text)
                            .help("Replace the editor with this version (undo with ⌘Z)")
                        }
                        .font(.system(size: 11))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(RoundedRectangle(cornerRadius: 6).fill(Theme.panel))
                    }
                    if snapshots.isEmpty {
                        Text("No snapshots yet.").font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                    }
                }
            }
            .frame(height: 360)
            HStack {
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 620)
        .background(Theme.background)
        .onAppear { snapshots = SnapshotStore.load(store.currentWorkspaceID) }
        .sheet(item: $comparing) { DiffSheet(diff: $0) }
    }
}
