import SwiftUI

struct TestsScreen: View {
    @EnvironmentObject var store: PolicyStore
    @State private var showingAddTest = false
    @State private var generated: [ACLTest]?
    @State private var generatedSSH: [SSHTest] = []
    @State private var editingRule: RuleSummary?
    @State private var tailscaleRun: (ok: Bool?, text: String, disagreements: [TestDisagreement])?
    @State private var runningOnTailscale = false

    var body: some View {
        let results = store.testResults
        let ssh = store.sshTestResults
        let passing = results.filter(\.passed).count + ssh.filter(\.passed).count
        let total = results.count + ssh.count

        return ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Tests")
                            .font(.system(size: 16, weight: .bold))
                            .foregroundStyle(Theme.textPrimary)
                        Text(store.isValid
                             ? "\(passing)/\(total) passing"
                             : "Policy is invalid")
                            .font(.system(size: 11.5))
                            .foregroundStyle(Theme.textSecondary)
                    }
                    Spacer()
                    ToolbarButton(label: "Generate from current access", icon: "wand.and.stars") {
                        generatedSSH = generateSSHTests(store.model, sources: generationSources)
                        generated = generateTests(store.model, sources: generationSources)
                    }
                    .disabled(!store.isValid)
                    .help("Save today's allowed and denied results as tests, so edits that change access fail")
                    ToolbarButton(label: "Add test", icon: "checkmark.shield") {
                        showingAddTest = true
                    }
                }

                if store.isValid && total > 0 {
                    banner(passing: passing, total: total)
                    if store.currentWorkspace.kind == .tailscale, store.serverClient() != nil {
                        tailscaleRow(results)
                    }
                    ForEach(results) { result in
                        testCard(result)
                    }
                    if !ssh.isEmpty {
                        Text("SSH tests")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundStyle(Theme.textPrimary)
                            .padding(.top, 6)
                        ForEach(ssh) { sshTestCard($0) }
                    }
                } else if store.isValid {
                    Text("No tests yet. Add one to lock in the behavior you expect.")
                        .foregroundStyle(Theme.textSecondary)
                        .padding(.top, 8)
                } else {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(Theme.orange)
                        Text("Fix the policy in the editor to run tests.")
                            .foregroundStyle(Theme.textSecondary)
                    }
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .background(Theme.background)
        .confirmationDialog(generatedTitle, isPresented: Binding(get: { generated != nil },
                                                                 set: { if !$0 { generated = nil } })) {
            if let generated, !(generated.isEmpty && generatedSSH.isEmpty) {
                Button("Add to existing tests") {
                    store.setGeneratedTests(generated, ssh: generatedSSH, replacingExisting: false)
                }
                Button("Replace all existing tests", role: .destructive) {
                    store.setGeneratedTests(generated, ssh: generatedSSH, replacingExisting: true)
                }
            }
        } message: {
            Text(generationSourceNote + " Each test lists the tag and host ports a source reaches today, and the ports others reach there that it can't; SSH tests list which logins each source gets on each SSH destination. You can undo this with ⌘Z.")
        }
        .sheet(item: $editingRule) { RuleSheet(existing: $0) }
        .onChange(of: store.text) { tailscaleRun = nil }
        .sheet(isPresented: $showingAddTest) {
            AddTestSheet()
        }
    }

    /// Run the same tests in Tailscale's own policy engine and show where it
    /// disagrees with the app.
    private func tailscaleRow(_ results: [TestResult]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Button("Check with Tailscale") { runOnTailscale(results) }
                    .disabled(runningOnTailscale)
                    .help("Run these tests on Tailscale against the editor's policy (nothing is saved)")
                if runningOnTailscale { ProgressView().controlSize(.small) }
                if let run = tailscaleRun {
                    Label(run.text, systemImage: run.ok == true ? "checkmark.seal" : run.ok == false ? "exclamationmark.triangle.fill" : "questionmark.circle")
                        .font(.system(size: 11.5))
                        .foregroundStyle(run.ok == true ? Theme.green : run.ok == false ? Theme.red : Theme.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            ForEach(tailscaleRun?.disagreements ?? []) { d in
                Text(verbatim: "\(d.src): the app says \(d.appPasses ? "pass" : "fail"), Tailscale says \(d.appPasses ? "fail" : "pass")"
                     + (d.errors.isEmpty ? "" : " — \(d.errors.joined(separator: "; "))"))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Theme.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func runOnTailscale(_ results: [TestResult]) {
        guard let client = store.serverClient() else { return }
        let text = store.text
        runningOnTailscale = true
        tailscaleRun = nil
        Task {
            defer { runningOnTailscale = false }
            do {
                guard let report = try await client.validate(text) else { return }
                if let disagreements = compareWithServer(local: results, report: report) {
                    tailscaleRun = disagreements.isEmpty
                        ? (true, "Tailscale agrees with the app on all \(results.count) tests.", [])
                        : (false, "Tailscale disagrees on \(disagreements.count) source\(disagreements.count == 1 ? "" : "s"):", disagreements)
                } else {
                    tailscaleRun = (nil, "Tailscale couldn't run the tests: \(report.message ?? "")", [])
                }
            } catch {
                tailscaleRun = (nil, "Tailscale couldn't run the tests: \(error.localizedDescription)", [])
            }
        }
    }

    /// Your real devices when loaded (each as its tag or user), otherwise
    /// every user and tag in the policy.
    private var generationSources: [String] {
        let fromDevices = store.headscaleNodes.compactMap(\.policyName).uniqued()
        return fromDevices.isEmpty ? store.model.allUsers + store.model.tagOrder : fromDevices
    }

    private var generationSourceNote: String {
        store.headscaleNodes.isEmpty ? "Sources: every user and tag in the policy (load devices to use your real devices)."
            : "Sources: your \(store.headscaleNodes.count) devices, each as its tag or user."
    }

    private var generatedTitle: String {
        guard let generated else { return "" }
        let n = generated.reduce(0) { $0 + $1.accept.count + $1.deny.count }
            + generatedSSH.reduce(0) { $0 + $1.accept.count + $1.check.count + $1.deny.count }
        let count = generated.count + generatedSSH.count
        return count == 0 ? "Nothing to generate — no source reaches any tag or host."
            : "Generate \(count) test\(count == 1 ? "" : "s") with \(n) checks?"
    }

    private func banner(passing: Int, total: Int) -> some View {
        let allPass = passing == total
        return HStack(spacing: 8) {
            Image(systemName: allPass ? "checkmark.shield" : "xmark.shield")
                .font(.system(size: 12.5, weight: .semibold))
            Text(allPass
                 ? "All \(total) tests pass. Safe to commit."
                 : "\(total - passing) of \(total) tests failing.")
                .font(.system(size: 12.5, weight: .semibold))
            Spacer()
        }
        .foregroundStyle(allPass ? Theme.green : Theme.red)
        .padding(11)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill((allPass ? Theme.green : Theme.red).opacity(0.10))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke((allPass ? Theme.green : Theme.red).opacity(0.35), lineWidth: 1)
        )
    }

    private func sshTestCard(_ result: SSHTestResult) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 8) {
                Text(result.passed ? "Pass" : "Fail")
                    .font(.system(size: 10.5, weight: .bold))
                    .foregroundStyle(result.passed ? Theme.green : Theme.red)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Capsule().fill((result.passed ? Theme.green : Theme.red).opacity(0.12)))
                Text("SSH test #\(result.testIndex + 1)")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
                Spacer()
                Chip(text: result.src, color: Theme.green, icon: "person")
                Button { store.deleteSSHTest(index: result.testIndex) } label: {
                    Image(systemName: "trash").font(.system(size: 10.5)).foregroundStyle(Theme.textSecondary)
                }
                .buttonStyle(.plain)
                .help("Delete this SSH test")
            }
            ForEach(result.assertions) { a in
                HStack(spacing: 8) {
                    Image(systemName: a.passed ? "checkmark" : "xmark")
                        .font(.system(size: 10.5, weight: .bold))
                        .foregroundStyle(a.passed ? Theme.green : Theme.red)
                    Chip(text: "\(a.expected.rawValue) \(a.login) on \(a.dst)",
                         color: a.expected == .deny ? Theme.orange : Theme.pink, icon: "terminal")
                    if !a.passed {
                        Text(verbatim: "but SSH rules say \(a.actual.rawValue)")
                            .font(.system(size: 10.5))
                            .foregroundStyle(Theme.red)
                    }
                }
            }
        }
        .padding(13)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 9).fill(Theme.panel))
        .overlay(RoundedRectangle(cornerRadius: 9).stroke(Theme.panelBorder, lineWidth: 1))
    }

    private func testCard(_ result: TestResult) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 8) {
                HStack(spacing: 5) {
                    Circle()
                        .fill(result.passed ? Theme.green : Theme.red)
                        .frame(width: 6, height: 6)
                    Text(result.passed ? "Pass" : "Fail")
                        .font(.system(size: 10.5, weight: .bold))
                }
                .foregroundStyle(result.passed ? Theme.green : Theme.red)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(Capsule().fill((result.passed ? Theme.green : Theme.red).opacity(0.12)))

                Text("Test #\(result.testIndex + 1)")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)

                Spacer()

                Chip(text: result.src, color: Theme.green, icon: "person")

                Button {
                    store.deleteTest(index: result.testIndex)
                } label: {
                    Image(systemName: "trash")
                        .font(.system(size: 10.5))
                        .foregroundStyle(Theme.textSecondary)
                }
                .buttonStyle(.plain)
                .help("Delete this test")
            }

            VStack(alignment: .leading, spacing: 6) {
                ForEach(result.assertions) { assertion in
                    VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Image(systemName: assertion.passed ? "checkmark" : "xmark")
                            .font(.system(size: 10.5, weight: .bold))
                            .foregroundStyle(assertion.passed ? Theme.green : Theme.red)
                        Chip(
                            text: "\(assertion.kind == .accept ? "allow" : "deny") \(assertion.dst)",
                            color: assertion.kind == .accept ? Theme.green : Theme.orange
                        )
                        if !assertion.passed {
                            Text(assertion.kind == .accept
                                 ? "expected to be allowed, but is denied"
                                 : "expected to be denied, but is allowed")
                                .font(.system(size: 10.5))
                                .foregroundStyle(Theme.red)
                        }
                    }
                    if !assertion.passed {
                        let why = explainFailure(store.model, src: result.src, entry: assertion.dst,
                                                 expectAllowed: assertion.kind == .accept)
                        HStack(alignment: .firstTextBaseline, spacing: 6) {
                            Text(verbatim: why.summary)
                                .font(.system(size: 10.5))
                                .foregroundStyle(Theme.textSecondary)
                                .fixedSize(horizontal: false, vertical: true)
                            ForEach(why.rules) { rule in
                                Button("Edit \u{201C}\(rule.name.count > 24 ? String(rule.name.prefix(23)) + "…" : rule.name)\u{201D}") {
                                    editingRule = rule
                                }
                                .font(.system(size: 10.5))
                            }
                        }
                        .padding(.leading, 20)
                    }
                    }
                }
            }
        }
        .padding(13)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 9).fill(Theme.panel))
        .overlay(RoundedRectangle(cornerRadius: 9).stroke(Theme.panelBorder, lineWidth: 1))
    }
}

// MARK: - Add test sheet

private struct AssertionDraft: Identifiable {
    var id = UUID()
    var kind: TestAssertion.Kind = .accept
    var target: String = ""
    var port: String = "443"
}

private struct AddTestSheet: View {
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var src = ""
    @State private var drafts: [AssertionDraft] = [AssertionDraft()]

    private var users: [String] { store.model.allUsers }
    private var targets: [String] {
        (store.model.tagOrder + store.model.hostOrder).uniqued()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Add test")
                .font(.system(size: 17, weight: .bold))
                .foregroundStyle(Theme.textPrimary)

            VStack(alignment: .leading, spacing: 8) {
                Text("Source user")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
                Picker("", selection: $src) {
                    ForEach(users, id: \.self) { Text($0).tag($0) }
                }
                .labelsHidden()
                .frame(width: 280)
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("Assertions")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)

                ForEach($drafts) { $draft in
                    HStack(spacing: 8) {
                        Picker("", selection: $draft.kind) {
                            Text("allow").tag(TestAssertion.Kind.accept)
                            Text("deny").tag(TestAssertion.Kind.deny)
                        }
                        .labelsHidden()
                        .frame(width: 90)

                        Picker("", selection: $draft.target) {
                            Text("Choose…").tag("")
                            ForEach(targets, id: \.self) { Text($0).tag($0) }
                        }
                        .labelsHidden()
                        .frame(width: 190)

                        TextField("port", text: $draft.port)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(size: 12.5, design: .monospaced))
                            .frame(width: 80)

                        Button {
                            drafts.removeAll { $0.id == draft.id }
                        } label: {
                            Image(systemName: "minus.circle")
                                .foregroundStyle(Theme.textSecondary)
                        }
                        .buttonStyle(.plain)
                        .disabled(drafts.count == 1)
                    }
                }

                Button {
                    drafts.append(AssertionDraft())
                } label: {
                    Label("Add assertion", systemImage: "plus")
                        .font(.system(size: 12, weight: .semibold))
                }
                .buttonStyle(.plain)
                .foregroundStyle(Theme.blue)
            }

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Add test") {
                    let accept = drafts
                        .filter { $0.kind == .accept && !$0.target.isEmpty }
                        .map { "\($0.target):\($0.port)" }
                    let deny = drafts
                        .filter { $0.kind == .deny && !$0.target.isEmpty }
                        .map { "\($0.target):\($0.port)" }
                    store.addTest(src: src, accept: accept, deny: deny)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!valid)
            }
        }
        .padding(24)
        .frame(width: 480)
        .background(Theme.background)
        .onAppear {
            if src.isEmpty { src = users.first ?? "" }
        }
    }

    private var valid: Bool {
        !src.isEmpty && drafts.contains {
            !$0.target.isEmpty && Int($0.port) != nil
        }
    }
}
