import SwiftUI
import AppKit

/// Moves a Tailscale workspace to GitOps: picks the GitHub repository, opens
/// a pull request adding the policy file and Tailscale's workflow, links the
/// workspace to the file, and lists the steps done on GitHub and Tailscale.
struct GitOpsSetupSheet: View {
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var repo: GitRepo?
    @State private var gitHub: String?
    @State private var branch = "main"
    @State private var fileName = "policy.hujson"
    @State private var hasPolicy = false
    @State private var hasWorkflow = false
    @State private var checking = false
    @State private var working = false
    @State private var error: String?
    @State private var pullRequest: URL?
    @State private var done = false

    private var workflowPath: String { ".github/workflows/tailscale.yml" }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Manage the policy with Git")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            if done { checklist } else { setup }
        }
        .padding(20)
        .frame(width: 560)
        .background(Theme.background)
    }

    // MARK: Step 1

    @ViewBuilder
    private var setup: some View {
        Text("Tailscale's GitHub Action tests every pull request against your tailnet and applies the policy when it's merged. The app then opens pull requests instead of pushing directly.")
            .font(.system(size: 11.5))
            .foregroundStyle(Theme.textSecondary)
            .fixedSize(horizontal: false, vertical: true)
        HStack {
            Button(repo == nil ? "Choose repository folder…" : "Change…", action: chooseFolder)
            if checking { ProgressView().controlSize(.small) }
            if let repo {
                VStack(alignment: .leading, spacing: 1) {
                    Text(verbatim: gitHub ?? "not on GitHub")
                        .font(.system(size: 12, weight: .semibold, design: .monospaced))
                        .foregroundStyle(gitHub == nil ? Theme.red : Theme.textPrimary)
                    Text(verbatim: repo.root.path + " · default branch " + branch)
                        .font(.system(size: 10.5)).foregroundStyle(Theme.textSecondary)
                }
            }
        }
        if repo != nil, gitHub != nil {
            HStack {
                Text("Policy file").font(.system(size: 11.5)).foregroundStyle(Theme.textSecondary)
                TextField("policy.hujson", text: $fileName)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12, design: .monospaced))
                    .frame(width: 220)
                    .onSubmit { Task { await inspect() } }
            }
            status(hasPolicy, done: "\(fileName) is already on \(branch) — it will be used as is.",
                   todo: "\(fileName) will be added with the policy currently on Tailscale.")
            status(hasWorkflow, done: "\(workflowPath) is already on \(branch).",
                   todo: "\(workflowPath) will be added: test on pull requests, apply on merge.")
            if GitTool.path("gh") == nil {
                Label("The GitHub CLI isn't installed, so the app will open GitHub's page for creating the pull request instead. Install it with `brew install gh` for one-step pull requests.",
                      systemImage: "info.circle")
                    .font(.system(size: 10.5)).foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        if let error {
            Text(error).font(.system(size: 11)).foregroundStyle(Theme.red).fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        }
        HStack {
            if working { ProgressView().controlSize(.small) }
            Spacer()
            Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
            Button(hasPolicy && hasWorkflow ? "Use this repository" : "Open setup pull request", action: finish)
                .keyboardShortcut(.defaultAction)
                .disabled(repo == nil || gitHub == nil || fileName.isEmpty || working || checking)
        }
    }

    private func status(_ present: Bool, done: String, todo: String) -> some View {
        Label(present ? done : todo, systemImage: present ? "checkmark.circle" : "plus.circle")
            .font(.system(size: 11.5))
            .foregroundStyle(present ? Theme.green : Theme.textPrimary)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func chooseFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.message = "Choose your local clone of the GitHub repository for the policy"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        error = nil
        checking = true
        Task {
            defer { checking = false }
            guard let found = await GitRepo.containing(url) else {
                error = "That folder isn't in a Git repository. Clone the GitHub repository first (e.g. `gh repo clone owner/tailnet-policy`)."
                repo = nil
                return
            }
            repo = found
            gitHub = await found.gitHubRepo()
            branch = await found.defaultBranch()
            if gitHub == nil { error = "The repository's origin isn't on GitHub, which Tailscale's GitOps action needs." }
            await inspect()
        }
    }

    private func inspect() async {
        guard let repo else { return }
        hasPolicy = await repo.fileOnDefaultBranch(fileName) != nil
        hasWorkflow = await repo.fileOnDefaultBranch(workflowPath) != nil
    }

    private func finish() {
        guard let repo, let client = store.serverClient() else { return }
        working = true
        error = nil
        Task {
            defer { working = false }
            do {
                var files: [String: String] = [:]
                if !hasPolicy { files[fileName] = try await client.getPolicy() }
                if !hasWorkflow { files[workflowPath] = gitOpsWorkflow(policyFile: fileName, branch: branch) }
                if !files.isEmpty {
                    pullRequest = try await repo.openPullRequest(
                        files: files, title: "Manage the tailnet policy with GitOps",
                        body: "Adds \(files.keys.sorted().joined(separator: " and ")) so Tailscale's GitHub Action tests policy changes on pull requests and applies them on merge.\n\nBefore merging, add the TS_OAUTH_ID, TS_AUDIENCE, and TS_TAILNET repository secrets.")
                }
                store.setGitOps(file: repo.root.appendingPathComponent(fileName))
                done = true
            } catch {
                self.error = error.localizedDescription
            }
        }
    }

    // MARK: Step 2

    private var policyURL: String { "https://github.com/\(gitHub ?? "")/blob/\(branch)/\(fileName)" }

    @ViewBuilder
    private var checklist: some View {
        Label("This workspace now uses \(gitHub ?? "the repository"). Reviews open pull requests instead of pushing.",
              systemImage: "checkmark.seal.fill")
            .font(.system(size: 12, weight: .semibold))
            .foregroundStyle(Theme.green)
            .fixedSize(horizontal: false, vertical: true)
        if let pullRequest {
            HStack {
                Text(verbatim: pullRequest.absoluteString).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                Button("Open") { NSWorkspace.shared.open(pullRequest) }
            }
        }
        Text("Finish on GitHub and Tailscale:")
            .font(.system(size: 12, weight: .semibold))
            .foregroundStyle(Theme.textPrimary)
        step(1, "Create a federated identity with the policy_file scope in the Tailscale admin console (Settings → Keys).",
             link: ("Open keys settings", "https://login.tailscale.com/admin/settings/keys"))
        step(2, "Add repository secrets on GitHub (Settings → Secrets and variables → Actions): TS_OAUTH_ID and TS_AUDIENCE from the identity, and TS_TAILNET = \(store.currentWorkspace.tailnet.flatMap { $0 == "-" ? nil : $0 } ?? "your tailnet name").",
             link: gitHub.map { ("Open secrets", "https://github.com/\($0)/settings/secrets/actions") })
        if pullRequest != nil {
            step(3, "Merge the setup pull request once its check passes, then pull it into your clone (git pull) — the app picks up the file.")
        }
        step(pullRequest != nil ? 4 : 3, "In the admin console's settings, under Policy file management, turn on Prevent edits in the admin console, and set External reference to:",
             link: ("Open admin settings", "https://login.tailscale.com/admin/settings"))
        HStack {
            Text(verbatim: policyURL).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
            Button("Copy") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(policyURL, forType: .string)
            }
        }
        .padding(.leading, 22)
        HStack {
            Spacer()
            Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
        }
    }

    private func step(_ n: Int, _ text: String, link: (String, String)? = nil) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(verbatim: "\(n).").font(.system(size: 11.5, weight: .semibold)).foregroundStyle(Theme.textSecondary)
            VStack(alignment: .leading, spacing: 3) {
                Text(text).font(.system(size: 11.5)).foregroundStyle(Theme.textPrimary).fixedSize(horizontal: false, vertical: true)
                if let link, let url = URL(string: link.1) {
                    Button(link.0) { NSWorkspace.shared.open(url) }.buttonStyle(.link).font(.system(size: 11))
                }
            }
        }
    }
}
