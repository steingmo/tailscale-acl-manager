import SwiftUI

/// Tailscale SSH access rules ("ssh" section): who may SSH where, as which
/// users, with accept or check (re-authentication) action.
struct SSHScreen: View {
    @EnvironmentObject var store: PolicyStore
    @State private var editingRule: SSHRule?
    @State private var adding = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("SSH")
                            .font(.system(size: 16, weight: .bold))
                            .foregroundStyle(Theme.textPrimary)
                        Text("Tailscale SSH rules: who may connect where, and as which users")
                            .font(.system(size: 11.5))
                            .foregroundStyle(Theme.textSecondary)
                    }
                    Spacer()
                    ToolbarButton(label: "Add rule", icon: "terminal") { adding = true }
                }

                if !store.isValid {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(Theme.orange)
                        Text("Fix the policy in the editor to manage SSH rules.")
                            .foregroundStyle(Theme.textSecondary)
                    }
                } else if store.model.sshRules.isEmpty {
                    Text("No SSH rules. Tailscale SSH is disabled until a rule allows it.")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.textSecondary)
                        .padding(.top, 6)
                } else {
                    ForEach(store.model.sshRules) { rule in
                        ruleCard(rule)
                    }
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .background(Theme.background)
        .sheet(item: $editingRule) { rule in
            SSHRuleSheet(rule: rule)
        }
        .sheet(isPresented: $adding) {
            SSHRuleSheet(rule: nil)
        }
    }

    private func ruleCard(_ rule: SSHRule) -> some View {
        let isCheck = rule.action == "check"
        return VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 8) {
                Text(rule.action)
                    .font(.system(size: 10.5, weight: .bold))
                    .foregroundStyle(isCheck ? Theme.orange : Theme.green)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Capsule().fill((isCheck ? Theme.orange : Theme.green).opacity(0.12)))
                    .help(isCheck
                          ? "check: connection requires periodic re-authentication"
                          : "accept: connection is allowed")
                Text("SSH rule #\(rule.index + 1)")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
                Spacer()
                Button("Edit") { editingRule = rule }
                    .font(.system(size: 11))
                Button {
                    store.deleteSSHRule(index: rule.index)
                } label: {
                    Image(systemName: "trash")
                        .font(.system(size: 10.5))
                        .foregroundStyle(Theme.textSecondary)
                }
                .buttonStyle(.plain)
                .help("Delete this rule")
            }
            HStack(spacing: 6) {
                ForEach(rule.src, id: \.self) { EntityChip(name: $0) }
                Image(systemName: "arrow.right")
                    .font(.system(size: 9.5))
                    .foregroundStyle(Theme.textSecondary)
                ForEach(rule.dst, id: \.self) { EntityChip(name: $0) }
            }
            HStack(spacing: 6) {
                Text("as")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.textSecondary)
                ForEach(rule.users, id: \.self) { Chip(text: $0, color: Theme.pink, icon: "person.badge.key") }
            }
        }
        .padding(13)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 9).fill(Theme.panel))
        .overlay(RoundedRectangle(cornerRadius: 9).stroke(Theme.panelBorder, lineWidth: 1))
    }
}

// MARK: - Add/edit sheet

private struct SSHRuleSheet: View {
    var rule: SSHRule? // nil = add

    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var action = "accept"
    @State private var src: [String] = []
    @State private var dst: [String] = []
    @State private var users: [String] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(rule == nil ? "Add SSH rule" : "Edit SSH rule #\((rule?.index ?? 0) + 1)")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)

            VStack(alignment: .leading, spacing: 6) {
                Text("Action")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
                Picker("", selection: $action) {
                    Text("accept").tag("accept")
                    Text("check").tag("check")
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 200)
                Text(action == "check"
                     ? "check requires the user to periodically re-authenticate."
                     : "accept allows the connection without extra verification.")
                    .font(.system(size: 10.5))
                    .foregroundStyle(Theme.textSecondary)
            }

            StringListEditor(
                title: "Sources — who may connect",
                addPrompt: "e.g. group:ops, tag:ci, or an email",
                suggestions: (["autogroup:member"] + store.model.groupOrder
                              + store.model.tagOrder),
                items: $src
            )
            StringListEditor(
                title: "Destinations — which devices",
                addPrompt: "e.g. tag:server or autogroup:self",
                suggestions: (["autogroup:self"] + store.model.tagOrder),
                items: $dst
            )
            StringListEditor(
                title: "SSH users — which accounts on the device",
                addPrompt: "e.g. root, ubuntu, autogroup:nonroot",
                suggestions: ["autogroup:nonroot", "root"],
                items: $users
            )

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(rule == nil ? "Add rule" : "Save") {
                    if let rule {
                        store.updateSSHRule(index: rule.index, action: action,
                                            src: src, dst: dst, users: users)
                    } else {
                        store.addSSHRule(action: action, src: src, dst: dst, users: users)
                    }
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(src.isEmpty || dst.isEmpty || users.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 460)
        .background(Theme.background)
        .onAppear {
            if let rule {
                action = rule.action
                src = rule.src
                dst = rule.dst
                users = rule.users
            }
        }
    }
}
