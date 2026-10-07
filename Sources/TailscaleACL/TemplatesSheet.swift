import SwiftUI

/// Pick a ready-made pattern, fill in its fields, and add it to the policy.
struct TemplatesSheet: View {
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var selected = policyTemplates[0].id
    @State private var values: [String: String] = [:]
    @State private var copyingTemplate = false

    private var template: PolicyTemplate { policyTemplates.first { $0.id == selected } ?? policyTemplates[0] }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Add from a template")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            HStack(alignment: .top, spacing: 14) {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(policyTemplates) { t in
                        Button { selected = t.id } label: {
                            Text(t.title)
                                .font(.system(size: 12, weight: t.id == selected ? .semibold : .regular))
                                .foregroundStyle(Theme.textPrimary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                                .background(RoundedRectangle(cornerRadius: 6)
                                    .fill(t.id == selected ? Color.white.opacity(0.09) : .clear))
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
                .frame(width: 210)
                VStack(alignment: .leading, spacing: 10) {
                    Text(template.detail)
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                    ForEach(template.fields, id: \.key) { field in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(field.label)
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundStyle(Theme.textSecondary)
                            TextField(field.defaultValue, text: Binding(
                                get: { values[field.key] ?? field.defaultValue },
                                set: { values[field.key] = $0 }))
                                .textFieldStyle(.roundedBorder)
                                .font(.system(size: 12, design: .monospaced))
                        }
                    }
                    Text("Existing groups and tags are kept. Undo with ⌘Z.")
                        .font(.system(size: 10.5))
                        .foregroundStyle(Theme.textSecondary.opacity(0.8))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                if store.workspaces.count > 1 {
                    Button("Add to other workspaces…") { copyingTemplate = true }
                }
                Button("Add to policy") {
                    store.applyTemplate(template, values: filledValues)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!store.isValid)
            }
        }
        .padding(20)
        .frame(width: 620)
        .background(Theme.background)
        .onChange(of: selected) { values = [:] }
        .sheet(isPresented: $copyingTemplate) {
            CopyToWorkspacesSheet(payload: .template(template, filledValues))
        }
    }

    private var filledValues: [String: String] {
        var v = Dictionary(uniqueKeysWithValues: template.fields.map { ($0.key, $0.defaultValue) })
        for (k, value) in values where template.fields.contains(where: { $0.key == k }) {
            v[k] = value.trimmingCharacters(in: .whitespaces)
        }
        return v
    }
}
