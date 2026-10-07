import SwiftUI

/// Replace a device's tags on the Headscale server.
struct DeviceTagsSheet: View {
    var node: HeadscaleNode

    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var tags: [String] = []
    @State private var confirming = false
    @State private var saving = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(verbatim: "Tags for \(node.displayName)")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            Text(node.allTags.isEmpty
                 ? "This device belongs to \(node.user?.name ?? "a user"). Tagging it makes it a tagged device: it then matches the policy only as its tags and loses its user's access, and it can't be turned back into a user device from here."
                 : "A tagged device must keep at least one tag. The server applies the change immediately.")
                .font(.system(size: 11))
                .foregroundStyle(node.allTags.isEmpty ? Theme.orange : Theme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            StringListEditor(title: "Tags", addPrompt: "e.g. tag:server",
                             suggestions: store.model.tagOrder, items: $tags)
            let undeclared = tags.filter { store.model.tagOwners[$0] == nil }
            if !undeclared.isEmpty {
                Label("Not in tagOwners: \(undeclared.joined(separator: ", ")) — the server may reject it.",
                      systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.orange)
            }
            if let error {
                Label(error, systemImage: "xmark.octagon.fill")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                if saving { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Apply to server…") { confirming = true }
                    .keyboardShortcut(.defaultAction)
                    .disabled(tags.isEmpty || tags == node.allTags || saving
                              || !tags.allSatisfy { $0.hasPrefix("tag:") })
            }
        }
        .padding(20)
        .frame(width: 460)
        .background(Theme.background)
        .onAppear { tags = node.allTags }
        .confirmationDialog("Set tags on \(node.displayName) to \(tags.joined(separator: ", "))?",
                            isPresented: $confirming) {
            Button("Apply to server", role: .destructive, action: apply)
        } message: {
            Text("This changes the device on \(store.serverDisplayName) right away.")
        }
    }

    private func apply() {
        guard let client = store.serverClient() else { return }
        saving = true
        error = nil
        Task {
            do {
                try await client.setTags(nodeID: node.id, tags: tags)
                try? await store.refreshNodes()
                dismiss()
            } catch {
                self.error = "The server refused: \(error.localizedDescription)"
            }
            saving = false
        }
    }
}
