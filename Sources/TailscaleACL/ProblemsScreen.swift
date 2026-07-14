import SwiftUI

/// Offline policy lint: structure and hygiene issues the admin console
/// won't tell you about until save time — or ever.
struct ProblemsScreen: View {
    @EnvironmentObject var store: PolicyStore

    var body: some View {
        let issues = store.lintIssues
        let errors = issues.filter { $0.severity == .error }.count

        return ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Problems")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundStyle(Theme.textPrimary)
                    Text("Structure checks: undefined references, ownerless tags, unused entities, shadowed rules, invalid values")
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.textSecondary)
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
                    ForEach(issues) { issue in
                        issueCard(issue)
                    }
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .background(Theme.background)
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
                Text(issue.title)
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(Theme.textPrimary)
                Text(issue.detail)
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
        .padding(11)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(Theme.panel))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(color.opacity(0.3), lineWidth: 1))
    }
}
