import SwiftUI

struct TestsScreen: View {
    @EnvironmentObject var store: PolicyStore
    @State private var showingAddTest = false

    var body: some View {
        let results = store.testResults
        let passing = results.filter(\.passed).count

        return ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Tests")
                            .font(.system(size: 16, weight: .bold))
                            .foregroundStyle(Theme.textPrimary)
                        Text(store.isValid
                             ? "\(passing)/\(results.count) passing"
                             : "Policy is invalid")
                            .font(.system(size: 11.5))
                            .foregroundStyle(Theme.textSecondary)
                    }
                    Spacer()
                    ToolbarButton(label: "Add test", icon: "checkmark.shield") {
                        showingAddTest = true
                    }
                }

                if store.isValid && !results.isEmpty {
                    banner(passing: passing, total: results.count)
                    ForEach(results) { result in
                        testCard(result)
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
        .sheet(isPresented: $showingAddTest) {
            AddTestSheet()
        }
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
