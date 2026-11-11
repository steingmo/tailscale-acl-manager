import SwiftUI

/// A first-run checklist for setting up a workspace well. Each step reads
/// the real state, so it's also a quick "what's left" check (Help menu).
struct GettingStartedSheet: View {
    @Binding var screen: Screen
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @AppStorage("gettingStartedDone") private var dontShowAgain = false
    @AppStorage(AppSession.lockSettingKey) private var lockApp = false
    @AppStorage(DataEncryption.settingKey) private var encrypted = false

    private struct Step: Identifiable {
        var title: String
        var detail: String
        /// nil: nothing to check (advice).
        var done: Bool?
        var go: Screen?
        var settings = false
        var id: String { title }
    }

    private var steps: [Step] {
        let connected = store.serverClient() != nil
        let tailscale = store.currentWorkspace.kind == .tailscale
        let errors = store.lintIssues.filter { $0.severity == .error }.count
        let security = store.lintIssues.filter(\.security).count
        var list = [
            Step(title: "Connect your Headscale server or Tailscale tailnet",
                 detail: "On the Server screen. For Tailscale, an OAuth client is safest: give it only the scopes you use (policy_file, devices:core, …) — the Server screen shows what it can do.",
                 done: connected, go: .server),
            Step(title: "Load your devices",
                 detail: "Devices make the Access Map, Simulator, push review, and Problems use your real machines.",
                 done: !store.headscaleNodes.isEmpty, go: .server),
            Step(title: "Protect the app and its data",
                 detail: "In Settings: require Touch ID to open the app, encrypt saved policies, and export a password-protected backup.",
                 done: lockApp && encrypted, settings: true),
            Step(title: "Fix problems and review security",
                 detail: errors + security == 0 ? "No errors or security findings."
                    : "\(errors) error\(errors == 1 ? "" : "s") and \(security) security finding\(security == 1 ? "" : "s") to look at.",
                 done: errors == 0 && security == 0, go: .problems),
            Step(title: "Pin important access with tests",
                 detail: "Tests stop a change that breaks access you rely on. Use Generate from current access, or Pin as test in the Simulator.",
                 done: !store.model.tests.isEmpty || !store.model.sshTests.isEmpty, go: .tests),
        ]
        if tailscale {
            list.append(Step(title: "Manage the policy in Git (optional)",
                             detail: "Set up Git… on the Server screen: changes go out as reviewed pull requests, and Tailscale's action applies them.",
                             done: store.isGitOps, go: .server))
        }
        return list
    }

    var body: some View {
        let steps = self.steps
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 3) {
                Text("Getting started")
                    .font(.system(size: 18, weight: .bold))
                    .foregroundStyle(Theme.textPrimary)
                Text(verbatim: "Set up \u{201C}\(store.currentWorkspace.name)\u{201D} — \(steps.filter { $0.done == true }.count) of \(steps.count) done.")
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.textSecondary)
            }
            ForEach(Array(steps.enumerated()), id: \.element.id) { i, step in
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: step.done == true ? "checkmark.circle.fill" : "\(i + 1).circle")
                        .font(.system(size: 15))
                        .foregroundStyle(step.done == true ? Theme.green : Theme.textSecondary)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(step.title)
                            .font(.system(size: 12.5, weight: .semibold))
                            .foregroundStyle(Theme.textPrimary)
                        Text(step.detail)
                            .font(.system(size: 11))
                            .foregroundStyle(Theme.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    if step.settings {
                        SettingsLink { Text("Settings") }.font(.system(size: 11))
                    } else if let go = step.go {
                        Button("Go") {
                            screen = go
                            dismiss()
                        }
                        .font(.system(size: 11))
                    }
                }
            }
            HStack {
                Toggle("Don't show at launch", isOn: $dontShowAgain)
                    .font(.system(size: 11))
                Spacer()
                Text("Help ▸ Getting Started shows this again.")
                    .font(.system(size: 10.5))
                    .foregroundStyle(Theme.textSecondary)
                Button("Done") {
                    dontShowAgain = true
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(22)
        .frame(width: 560)
        .background(Theme.background)
    }
}
