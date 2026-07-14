import SwiftUI

// Shared sheets and controls used by the visual builder, access matrix, and SSH screens.

struct QuickPort: Identifiable {
    var label: String
    var port: Int
    var id: Int { port }
}

let quickPorts: [QuickPort] = [
    .init(label: "SSH", port: 22),
    .init(label: "DNS", port: 53),
    .init(label: "HTTP", port: 80),
    .init(label: "HTTPS", port: 443),
    .init(label: "RDP", port: 3389),
    .init(label: "MySQL", port: 3306),
    .init(label: "PostgreSQL", port: 5432),
    .init(label: "Redis", port: 6379),
]


struct ConnectionSheet: View {
    var title: String
    var src: String
    var dstTarget: String
    var initialPorts: String
    var initialProto: String
    var showRemove: Bool
    var allowTypeChoice: Bool
    var initialIsGrant: Bool
    var onSave: (String, String, Bool) -> Void
    var onRemove: () -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var ports = ""
    @State private var proto = "any"
    @State private var isGrant = true

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(title)
                .font(.system(size: 17, weight: .bold))
                .foregroundStyle(Theme.textPrimary)

            HStack(spacing: 8) {
                EntityChip(name: src)
                Image(systemName: "arrow.right")
                    .foregroundStyle(Theme.textSecondary)
                EntityChip(name: dstTarget)
            }

            if allowTypeChoice {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Rule syntax")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(Theme.textSecondary)
                    Picker("", selection: $isGrant) {
                        Text("Grant (modern)").tag(true)
                        Text("ACL (legacy)").tag(false)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .frame(width: 260)
                }
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("Protocol")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
                Picker("", selection: $proto) {
                    Text("Any").tag("any")
                    Text("TCP").tag("tcp")
                    Text("UDP").tag("udp")
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 220)
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("Ports")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
                let columns = [GridItem(.adaptive(minimum: 100), spacing: 6)]
                LazyVGrid(columns: columns, alignment: .leading, spacing: 6) {
                    ForEach(quickPorts) { qp in
                        let active = portSet.contains(String(qp.port))
                        Button {
                            togglePort(qp.port)
                        } label: {
                            // verbatim: port numbers must never get locale
                            // grouping separators (3389, not 3.389)
                            Text(verbatim: "\(qp.label) \(qp.port)")
                                .font(.system(size: 11.5, weight: .medium))
                                .padding(.horizontal, 8)
                                .padding(.vertical, 5)
                                .frame(maxWidth: .infinity)
                                .background(
                                    RoundedRectangle(cornerRadius: 6)
                                        .fill(active ? Theme.green.opacity(0.2) : Color.white.opacity(0.06))
                                )
                                .overlay(
                                    RoundedRectangle(cornerRadius: 6)
                                        .stroke(active ? Theme.green : Theme.panelBorder, lineWidth: 1)
                                )
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(active ? Theme.green : Theme.textPrimary)
                    }
                }
                TextField("Custom, e.g. 22,80,8000-8100 or * for all", text: $ports)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12.5, design: .monospaced))
            }

            HStack {
                if showRemove {
                    Button(role: .destructive) {
                        onRemove()
                        dismiss()
                    } label: {
                        Text("Remove access")
                    }
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(showRemove ? "Save" : "Grant access") {
                    onSave(ports.trimmingCharacters(in: .whitespaces), proto, isGrant)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(ports.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 460)
        .background(Theme.background)
        .onAppear {
            ports = initialPorts
            proto = initialProto
            isGrant = initialIsGrant
        }
    }

    private var portSet: Set<String> {
        Set(ports.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) })
    }

    private func togglePort(_ port: Int) {
        var parts = ports.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && $0 != "*" }
        if let i = parts.firstIndex(of: String(port)) {
            parts.remove(at: i)
        } else {
            parts.append(String(port))
        }
        ports = parts.joined(separator: ",")
    }
}

/// Editable list of strings with add/remove rows and optional suggestions menu.
struct StringListEditor: View {
    var title: String
    var addPrompt: String
    var suggestions: [String]
    @Binding var items: [String]

    @State private var newItem = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Theme.textSecondary)

            ForEach(items.indices, id: \.self) { i in
                HStack(spacing: 6) {
                    TextField("", text: Binding(
                        get: { i < items.count ? items[i] : "" },
                        set: { if i < items.count { items[i] = $0 } }
                    ))
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12, design: .monospaced))
                    Button {
                        items.remove(at: i)
                    } label: {
                        Image(systemName: "minus.circle")
                            .font(.system(size: 11))
                            .foregroundStyle(Theme.textSecondary)
                    }
                    .buttonStyle(.plain)
                    .help("Remove")
                }
            }

            HStack(spacing: 6) {
                TextField(addPrompt, text: $newItem)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12, design: .monospaced))
                    .onSubmit { addItem() }
                if !suggestions.isEmpty {
                    Menu {
                        ForEach(suggestions.filter { !items.contains($0) }, id: \.self) { s in
                            Button(s) { items.append(s) }
                        }
                    } label: {
                        Image(systemName: "chevron.down.circle")
                            .font(.system(size: 11))
                    }
                    .menuStyle(.borderlessButton)
                    .frame(width: 24)
                    .help("Add a known entity")
                }
                Button {
                    addItem()
                } label: {
                    Image(systemName: "plus.circle")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.blue)
                }
                .buttonStyle(.plain)
                .disabled(newItem.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
    }

    private func addItem() {
        let trimmed = newItem.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !items.contains(trimmed) else { return }
        items.append(trimmed)
        newItem = ""
    }
}
