import SwiftUI

struct PolicyEditorScreen: View {
    @EnvironmentObject var store: PolicyStore
    @State private var confirmingReset = false
    @State private var copied = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Text("Policy Editor")
                    .font(.system(size: 16, weight: .bold))
                    .foregroundStyle(Theme.textPrimary)
                Spacer()
                validityPill
                ToolbarButton(label: "Import", icon: "square.and.arrow.up") {
                    store.importFromFile()
                }
                ToolbarButton(label: copied ? "Copied" : "Copy", icon: copied ? "checkmark" : "doc.on.doc") {
                    store.copyToClipboard()
                    copied = true
                    Task {
                        try? await Task.sleep(for: .seconds(1.5))
                        copied = false
                    }
                }
                ToolbarButton(label: "Export", icon: "square.and.arrow.down") {
                    store.exportToFile()
                }
                ToolbarButton(label: "Reset", icon: "arrow.counterclockwise") {
                    confirmingReset = true
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)

            CodeEditor(text: $store.text)
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Theme.panelBorder, lineWidth: 1)
                )
                .padding([.horizontal, .bottom], 12)

            if let error = store.parseError {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(Theme.red)
                    Text("Line \(error.line): \(error.message)")
                        .font(.system(size: 12.5, design: .monospaced))
                        .foregroundStyle(Theme.red)
                    Spacer()
                }
                .padding(.horizontal, 20)
                .padding(.bottom, 12)
            }
        }
        .background(Theme.background)
        .confirmationDialog("Reset to the sample policy?", isPresented: $confirmingReset) {
            Button("Reset", role: .destructive) { store.reset() }
        } message: {
            Text("This replaces the current policy with the built-in example. This cannot be undone.")
        }
    }

    private var validityPill: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(store.isValid ? Theme.green : Theme.red)
                .frame(width: 7, height: 7)
            Text(store.isValid ? "Valid" : "Invalid")
                .font(.system(size: 11.5, weight: .semibold))
        }
        .foregroundStyle(Theme.textPrimary)
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(Capsule().fill(Color.white.opacity(0.07)))
        .overlay(Capsule().stroke(Color.white.opacity(0.08), lineWidth: 1))
    }
}
