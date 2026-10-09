import SwiftUI
import AppKit
import UniformTypeIdentifiers

/// Periodic sign-off of who has access: every group and rule gets "still
/// needed" or "remove", with who decided and when, exported for auditors.
struct AccessReviewScreen: View {
    @EnvironmentObject var store: PolicyStore
    @AppStorage("reviewerName") private var reviewer = NSFullUserName()
    @State private var filter = Filter.open
    @State private var noting: ReviewItem?
    @State private var noteText = ""
    @State private var confirmingNew = false
    @State private var confirmingApply = false

    enum Filter: String, CaseIterable { case open = "To review", remove = "To remove", all = "All" }

    var body: some View {
        let items = reviewItems(store.model)
        let decided = items.filter { store.review.decisions[$0.key] != nil }.count
        let removals = items.filter { store.review.decisions[$0.key]?.keep == false }
        let shown = items.filter { item in
            let d = store.review.decisions[item.key]
            switch filter {
            case .open: return d == nil
            case .remove: return d?.keep == false
            case .all: return true
            }
        }
        return ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                header
                if !store.isValid {
                    Label("Fix the policy in the editor to review access.", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(Theme.textSecondary)
                } else if store.review.started == nil {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Go through every group and rule and confirm it's still needed. The app keeps who decided what and when, and a changed item comes back for review.")
                            .font(.system(size: 12))
                            .foregroundStyle(Theme.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                        Button("Start review") { store.startNewReview() }
                    }
                } else {
                    progress(decided: decided, total: items.count, removals: removals.count)
                    HStack {
                        Picker("", selection: $filter) {
                            ForEach(Filter.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                        }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                        .frame(width: 280)
                        Spacer()
                        if !removals.isEmpty {
                            Button("Remove \(removals.count) from the policy…") { confirmingApply = true }
                                .font(.system(size: 11))
                        }
                    }
                    if shown.isEmpty {
                        Text(filter == .open ? "Everything is reviewed." : "Nothing here.")
                            .font(.system(size: 12))
                            .foregroundStyle(Theme.textSecondary)
                    }
                    ForEach(shown) { row($0) }
                }
            }
            .padding(16)
            .frame(maxWidth: 900, alignment: .topLeading)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .background(Theme.background)
        .alert("Note for \(noting?.title ?? "")", isPresented: Binding(get: { noting != nil }, set: { if !$0 { noting = nil } })) {
            TextField("Why it's kept or removed", text: $noteText)
            Button("Save") { if let noting { store.setReviewNote(noting, noteText) } }
            Button("Cancel", role: .cancel) {}
        }
        .confirmationDialog("Start a new review?", isPresented: $confirmingNew) {
            Button("Start new review", role: .destructive) { store.startNewReview() }
        } message: {
            Text("Every item goes back to “to review”. Export this review's report first if you need to keep it.")
        }
        .confirmationDialog("Remove \(removals.count) item\(removals.count == 1 ? "" : "s") from the policy?", isPresented: $confirmingApply) {
            Button("Remove in the editor") { store.applyReviewRemovals(items) }
        } message: {
            Text("Rules are deleted. Groups are deleted with every reference to them, and a rule left without sources goes too. Nothing reaches the server until you review and push. ⌘Z undoes it.")
        }
    }

    private var header: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 3) {
                Text("Access Review")
                    .font(.system(size: 16, weight: .bold))
                    .foregroundStyle(Theme.textPrimary)
                Text("Confirm every group and rule is still needed, and keep a record for audits")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.textSecondary)
            }
            Spacer()
            if store.review.started != nil {
                TextField("Reviewer", text: $reviewer)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 160)
                    .help("Recorded with each decision")
                ToolbarButton(label: "Export report…", icon: "doc.text") { export() }
                ToolbarButton(label: "New review…", icon: "arrow.counterclockwise") { confirmingNew = true }
            }
        }
    }

    private func progress(decided: Int, total: Int, removals: Int) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            ProgressView(value: Double(decided), total: Double(max(total, 1)))
            Text(verbatim: "\(decided) of \(total) reviewed"
                 + (removals > 0 ? ", \(removals) to remove" : "")
                 + " · started \(store.review.started!.formatted(date: .abbreviated, time: .omitted))")
                .font(.system(size: 11))
                .foregroundStyle(Theme.textSecondary)
        }
    }

    private func row(_ item: ReviewItem) -> some View {
        let decision = store.review.decisions[item.key]
        return HStack(alignment: .top, spacing: 10) {
            Image(systemName: item.kind == .group ? "person.3" : "arrow.right.circle")
                .foregroundStyle(item.kind == .group ? Theme.green : Theme.blue)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text(verbatim: item.title)
                        .font(.system(size: 12.5, weight: .semibold))
                        .foregroundStyle(Theme.textPrimary)
                    if let line = store.tree?.line(at: item.path) {
                        Button("Line " + String(line)) { store.editorLineRequest = line }
                            .buttonStyle(.link)
                            .font(.system(size: 11))
                    }
                }
                Text(verbatim: item.detail)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
                if let decision {
                    Text(verbatim: (decision.keep ? "Kept" : "To remove") + " by \(decision.by), \(decision.at.formatted(date: .abbreviated, time: .omitted))"
                         + (decision.note.isEmpty ? "" : " — \(decision.note)"))
                        .font(.system(size: 11))
                        .foregroundStyle(decision.keep ? Theme.green : Theme.red)
                }
            }
            Spacer()
            if decision == nil {
                Button("Still needed") { store.decide(item, keep: true, by: reviewer) }
                Button("Remove") { store.decide(item, keep: false, by: reviewer) }
            } else {
                Button("Note…") { noteText = decision?.note ?? ""; noting = item }
                Button("Undo") { store.decide(item, keep: nil, by: reviewer) }
            }
        }
        .font(.system(size: 11))
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8).fill(Theme.panel))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.panelBorder, lineWidth: 1))
    }

    private func export() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "md") ?? .plainText]
        panel.nameFieldStringValue = "\(store.currentWorkspace.name) access review.md"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let report = accessReviewReport(workspace: store.currentWorkspace.name, review: store.review, items: reviewItems(store.model))
        try? report.write(to: url, atomically: true, encoding: .utf8)
    }
}
