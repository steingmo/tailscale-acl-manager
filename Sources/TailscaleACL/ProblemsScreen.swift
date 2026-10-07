import SwiftUI
import UniformTypeIdentifiers

/// Offline policy lint: structure and hygiene issues the admin console
/// won't tell you about until save time — or ever.
struct ProblemsScreen: View {
    @EnvironmentObject var store: PolicyStore
    @State private var converting = false

    var body: some View {
        let issues = store.lintIssues
        let errors = issues.filter { $0.severity == .error }.count

        return ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text("Problems")
                            .font(.system(size: 16, weight: .bold))
                            .foregroundStyle(Theme.textPrimary)
                        Spacer()
                        ToolbarButton(label: "Export audit report…", icon: "checklist") { exportAudit() }
                            .disabled(!store.isValid)
                            .help("A least-privilege review: security findings, temporary access, people, devices, and rule usage")
                    }
                    Text("Structure checks: undefined references, ownerless tags, unused entities, shadowed, expiring, wide-open, and one-person rules, postures, relay servers, invalid values")
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.textSecondary)
                    Text(store.headscaleNodes.isEmpty
                         ? "Connect a server to also check the policy against your real devices."
                         : "Device checks are using \(store.headscaleNodes.count) devices from \(store.serverDisplayName).")
                        .font(.system(size: 10.5))
                        .foregroundStyle(Theme.textSecondary.opacity(0.8))
                }

                if store.isValid, !store.model.rules.isEmpty {
                    HStack(spacing: 10) {
                        Image(systemName: "arrow.triangle.2.circlepath")
                            .foregroundStyle(Theme.blue)
                        Text(verbatim: "\(store.model.rules.count) rule\(store.model.rules.count == 1 ? " uses" : "s use") the legacy ACL syntax. Tailscale recommends grants.")
                            .font(.system(size: 11.5))
                            .foregroundStyle(Theme.textSecondary)
                        Button("Convert to grants…") { converting = true }
                            .font(.system(size: 11))
                        Spacer()
                    }
                }

                if issues.isEmpty {
                    HStack(spacing: 10) {
                        Image(systemName: "checkmark.shield")
                            .font(.system(size: 13, weight: .semibold))
                        Text("No problems found. The policy structure looks clean.")
                            .font(.system(size: 12.5, weight: .semibold))
                        Spacer()
                    }
                    .foregroundStyle(Theme.green)
                    .padding(11)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Theme.green.opacity(0.10)))
                    .overlay(RoundedRectangle(cornerRadius: 8)
                        .stroke(Theme.green.opacity(0.35), lineWidth: 1))
                } else {
                    Text("\(errors) error\(errors == 1 ? "" : "s"), \(issues.count - errors) warning\(issues.count - errors == 1 ? "" : "s")")
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.textSecondary)
                    let security = issues.filter(\.security)
                    let other = issues.filter { !$0.security }
                    if !security.isEmpty {
                        sectionHeader("Security review", icon: "lock.shield",
                                      detail: "Patterns that make the tailnet easier to abuse — worth a look even when everything works.")
                        ForEach(security) { issueCard($0) }
                    }
                    if !other.isEmpty {
                        if !security.isEmpty {
                            sectionHeader("Policy problems", icon: "exclamationmark.triangle", detail: nil)
                        }
                        ForEach(other) { issueCard($0) }
                    }
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .background(Theme.background)
        .sheet(isPresented: $converting) { ConvertToGrantsSheet() }
    }

    private func exportAudit() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "md") ?? .plainText]
        panel.nameFieldStringValue = "\(store.currentWorkspace.name) access audit.md"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            let credential = try? await store.serverClient()?.credentialInfo()
            let report = auditReport(workspace: store.currentWorkspace.name,
                                     server: store.serverClient() == nil ? nil : store.serverDisplayName,
                                     model: store.model, nodes: store.headscaleNodes, traffic: store.traffic,
                                     serverLogins: store.serverLogins, credential: credential ?? nil)
            try? report.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    private func sectionHeader(_ title: String, icon: String, detail: String?) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Label(title, systemImage: icon)
                .font(.system(size: 13, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            if let detail {
                Text(detail).font(.system(size: 10.5)).foregroundStyle(Theme.textSecondary)
            }
        }
        .padding(.top, 6)
    }

    private func issueCard(_ issue: LintIssue) -> some View {
        let isError = issue.severity == .error
        let color = isError ? Theme.red : Theme.orange
        return HStack(alignment: .top, spacing: 10) {
            Image(systemName: isError ? "xmark.octagon.fill" : "exclamationmark.triangle.fill")
                .font(.system(size: 12))
                .foregroundStyle(color)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text(issue.title)
                        .font(.system(size: 12.5, weight: .semibold))
                        .foregroundStyle(Theme.textPrimary)
                    if let line = store.line(of: issue) {
                        Button("Line " + String(line)) { store.editorLineRequest = line }
                            .buttonStyle(.link)
                            .font(.system(size: 11))
                            .help("Show in the Policy Editor")
                    }
                }
                Text(issue.detail)
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                if !issue.fixes.isEmpty {
                    HStack(spacing: 6) {
                        ForEach(issue.fixes) { fix in
                            Button(fix.label) { store.apply(fix.action) }
                                .font(.system(size: 11))
                                .help("Applies the fix to the policy — undo with ⌘Z")
                        }
                    }
                    .padding(.top, 3)
                }
            }
            Spacer()
        }
        .padding(11)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(Theme.panel))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(color.opacity(0.3), lineWidth: 1))
    }
}
