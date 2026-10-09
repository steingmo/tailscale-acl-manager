import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct PushCandidate: Identifiable {
    let id = UUID()
    var text: String
    var isRestore: Bool
}

// MARK: - Push review

/// Shows what a push changes for your real devices before it goes live, and
/// saves the server's current policy to history before pushing.
struct PushReviewSheet: View {
    /// Kept in state so the same client (and its Tailscale ETag) is used from
    /// review to push, even if SwiftUI rebuilds this view.
    @State private var client: PolicyServer
    var candidate: PushCandidate
    var onPushed: () -> Void

    init(client: PolicyServer, candidate: PushCandidate, onPushed: @escaping () -> Void) {
        _client = State(initialValue: client)
        self.candidate = candidate
        self.onPushed = onPushed
    }

    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var serverText: String?
    @State private var changes: [AccessChange] = []
    @State private var deviceCount = 0
    @State private var previewNote: String?
    /// Devices whose posture couldn't be checked, when the policy uses postures.
    @State private var postureUnknown = 0
    @State private var candidateErrors: [LintIssue] = []
    /// Tailscale's own verdict: nil not checked, "" passed, otherwise the failure.
    @State private var serverVerdict: String?
    @State private var blocker: String?
    @State private var loading = true
    @State private var pushing = false
    /// The server text as of our last pull/push, when the server has changed since.
    @State private var conflictBase: String?
    @State private var noSyncRecord = false
    @State private var comparing: DiffPresentation?
    /// Both policies as parsed for the review, for replaying real traffic.
    @State private var models: (old: PolicyModel, new: PolicyModel)?
    /// Real connections the old policy allowed that this push would block;
    /// nil until checked.
    @State private var blocked: [TrafficConnection]?
    @State private var trafficError: String?
    @State private var prTitle = ""
    @State private var pullRequest: URL?
    @State private var prError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(candidate.isRestore ? "Review restore on \(host)" : "Review push to \(host)")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)

            if loading {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Comparing with the server's current policy…")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.textSecondary)
                }
            } else if let blocker {
                Label(blocker, systemImage: "xmark.octagon.fill")
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.red)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                if let conflictBase, let serverText {
                    VStack(alignment: .leading, spacing: 6) {
                        Label("The server's policy changed since your last pull or push. Pushing overwrites those changes — cancel and pull first to keep them.",
                              systemImage: "exclamationmark.triangle.fill")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(Theme.orange)
                            .fixedSize(horizontal: false, vertical: true)
                        Button("Show what changed on the server…") {
                            comparing = DiffPresentation(title: "Changes made on the server",
                                                         oldLabel: "at your last pull/push", newLabel: "on the server now",
                                                         old: conflictBase, new: serverText)
                        }
                        .font(.system(size: 11.5))
                    }
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Theme.orange.opacity(0.10)))
                } else if noSyncRecord {
                    Text("No record of a pull in this workspace, so changes made on the server by others can't be detected. Pull once to enable that check.")
                        .font(.system(size: 10.5))
                        .foregroundStyle(Theme.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                summary
                if postureUnknown > 0 {
                    Label("\(postureUnknown) device\(postureUnknown == 1 ? " has" : "s have") no posture attributes loaded, so rules requiring a posture count as allowing \(postureUnknown == 1 ? "it" : "them"). Access lost to a posture isn't shown for \(postureUnknown == 1 ? "it" : "them").",
                          systemImage: "questionmark.diamond")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if !changes.isEmpty { changeList }
                if let serverText, serverText != candidate.text {
                    Button("Show text changes…") {
                        comparing = DiffPresentation(title: "Text changes", oldLabel: "on the server",
                                                     newLabel: candidate.isRestore ? "restored version" : "to be pushed",
                                                     old: serverText, new: candidate.text)
                    }
                    .font(.system(size: 11.5))
                }
                if let serverVerdict {
                    Label(serverVerdict.isEmpty ? "Tailscale's own check passed (policy and its tests)."
                          : "Tailscale's check failed — it will refuse this push: \(serverVerdict)",
                          systemImage: serverVerdict.isEmpty ? "checkmark.seal" : "xmark.octagon.fill")
                        .font(.system(size: 11.5))
                        .foregroundStyle(serverVerdict.isEmpty ? Theme.green : Theme.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if models != nil, store.currentWorkspace.kind == .tailscale { trafficCheck }
                if !candidateErrors.isEmpty {
                    Label("The Problems check reports \(candidateErrors.count) error\(candidateErrors.count == 1 ? "" : "s") in this policy — the server may reject it.",
                          systemImage: "exclamationmark.triangle.fill")
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text("Compares TCP/UDP access between your current devices on every port named in either policy, and SSH logins for root, every account named in either policy, and other non-root users. ICMP isn't compared. The server's current policy is saved to Push history first.")
                    .font(.system(size: 10.5))
                    .foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if store.isGitOps, !loading, blocker == nil {
                if let pullRequest {
                    HStack {
                        Label("Pull request opened. Tailscale's action tests it; merging applies it.", systemImage: "checkmark.seal.fill")
                            .font(.system(size: 11.5, weight: .semibold))
                            .foregroundStyle(Theme.green)
                        Button("Open") { NSWorkspace.shared.open(pullRequest) }
                    }
                } else {
                    HStack {
                        Text("Pull request title").font(.system(size: 11.5)).foregroundStyle(Theme.textSecondary)
                        TextField("Update tailnet policy", text: $prTitle).textFieldStyle(.roundedBorder)
                    }
                }
                if let prError {
                    Text(prError).font(.system(size: 11)).foregroundStyle(Theme.red)
                        .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                }
            }
            HStack {
                if !loading, blocker == nil {
                    Button("Copy as Markdown") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(reviewMarkdown, forType: .string)
                    }
                    .help("For a ticket or pull request, so someone can approve the change before it goes live")
                    Button("Export…") { exportReview() }
                }
                if pushing { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                if store.isGitOps {
                    Button(pullRequest == nil ? "Open pull request" : "Done") {
                        if pullRequest == nil { openPullRequest() } else { dismiss() }
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(loading || pushing || blocker != nil)
                } else {
                    Button(conflictBase != nil ? "Overwrite and push"
                           : candidate.isRestore ? "Restore on server" : "Push to server") { push() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(loading || pushing || blocker != nil)
                }
            }
        }
        .padding(20)
        .frame(width: 560)
        .background(Theme.background)
        .task { await prepare() }
        .sheet(item: $comparing) { DiffSheet(diff: $0) }
    }

    private var host: String { client.displayHost }

    /// Replays recent real traffic (flow logs) against the new policy.
    @ViewBuilder
    private var trafficCheck: some View {
        if let blocked {
            let total = store.traffic?.connections.filter(\.isPortTraffic).count ?? 0
            if blocked.isEmpty {
                Label("None of the \(total) kinds of real connections in the loaded traffic would be blocked.",
                      systemImage: "checkmark.shield")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.green)
            } else {
                let byIP = nodesByAddress(store.headscaleNodes)
                VStack(alignment: .leading, spacing: 3) {
                    Label("This push would block \(blocked.count) kind\(blocked.count == 1 ? "" : "s") of connection that happened recently:",
                          systemImage: "exclamationmark.triangle.fill")
                        .font(.system(size: 11.5, weight: .semibold))
                        .foregroundStyle(Theme.red)
                    ForEach(blocked.prefix(8)) { c in
                        Text(verbatim: "\(trafficName(c.client, nodes: byIP)) → \(trafficName(c.server, nodes: byIP)) \(c.protoName) \(c.port) · \(c.connections)×")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(Theme.textPrimary)
                    }
                    if blocked.count > 8 {
                        Text(verbatim: "…and \(blocked.count - 8) more (in the exported review).")
                            .font(.system(size: 10.5)).foregroundStyle(Theme.textSecondary)
                    }
                }
            }
        } else {
            HStack(spacing: 8) {
                Button(store.traffic == nil ? "Check against the last 7 days of traffic" : "Check against loaded traffic") {
                    Task { await checkTraffic() }
                }
                .font(.system(size: 11.5))
                .disabled(store.trafficProgress != nil)
                if let p = store.trafficProgress {
                    ProgressView().controlSize(.small)
                    Text(p).font(.system(size: 10.5)).foregroundStyle(Theme.textSecondary)
                }
                if let trafficError {
                    Text(trafficError).font(.system(size: 10.5)).foregroundStyle(Theme.red).lineLimit(2)
                }
            }
        }
    }

    private func checkTraffic() async {
        guard let models else { return }
        trafficError = nil
        do {
            if store.traffic == nil { try await store.loadTraffic(days: 7) }
            blocked = trafficBlocked(by: models.new, was: models.old, traffic: store.traffic?.connections ?? [],
                                     nodes: store.headscaleNodes)
        } catch {
            trafficError = error.localizedDescription
        }
    }

    /// This review — summary, access changes, checks, and the text diff — as Markdown.
    private var reviewMarkdown: String {
        var model = (try? HuJSONParser.parse(candidate.text)).map(PolicyModel.init(tree:)) ?? PolicyModel()
        model.userAutogroups = store.model.userAutogroups
        let ev = Evaluator(model: model)
        return pushReviewMarkdown(PushReview(
            workspace: store.currentWorkspace.name, host: host, isRestore: candidate.isRestore,
            serverText: serverText, candidate: candidate.text, changes: changes, deviceCount: deviceCount,
            note: previewNote, verdict: serverVerdict, errors: candidateErrors,
            tests: ev.runTests(), sshTests: ev.runSSHTests(), conflict: conflictBase != nil,
            blockedTraffic: blocked.map { list in
                let byIP = nodesByAddress(store.headscaleNodes)
                return list.map { "\(trafficName($0.client, nodes: byIP)) → \(trafficName($0.server, nodes: byIP)) \($0.protoName) \($0.port) (\($0.connections) connections)" }
            }))
    }

    private func exportReview() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "md") ?? .plainText]
        panel.nameFieldStringValue = "\(store.currentWorkspace.name) change review.md"
        if panel.runModal() == .OK, let url = panel.url {
            try? reviewMarkdown.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    @ViewBuilder
    private var summary: some View {
        if serverText == candidate.text {
            Text("The policy is identical to what's already on the server.")
                .font(.system(size: 12))
                .foregroundStyle(Theme.textSecondary)
        } else if let previewNote {
            Label(previewNote, systemImage: "info.circle")
                .font(.system(size: 12))
                .foregroundStyle(Theme.orange)
                .fixedSize(horizontal: false, vertical: true)
        } else if changes.isEmpty {
            Label("No network access changes between your \(deviceCount) devices.",
                  systemImage: "checkmark.shield")
                .font(.system(size: 12.5, weight: .semibold))
                .foregroundStyle(Theme.green)
        } else {
            Text(changes.count == 1 ? "1 device pair changes access:" : "\(changes.count) device pairs change access:")
                .font(.system(size: 12.5, weight: .semibold))
                .foregroundStyle(Theme.textPrimary)
        }
    }

    private var changeList: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(changes) { change in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(verbatim: "\(change.src) → \(change.dst)")
                            .font(.system(size: 11.5, weight: .semibold, design: .monospaced))
                            .foregroundStyle(Theme.textPrimary)
                        if !change.gained.isEmpty {
                            Text(verbatim: "+ gains \(change.gained.joined(separator: ", "))")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(Theme.green)
                        }
                        if !change.lost.isEmpty {
                            Text(verbatim: "− loses \(change.lost.joined(separator: ", "))")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(Theme.red)
                        }
                        if !change.sshGained.isEmpty {
                            Text(verbatim: "+ gains SSH as \(change.sshGained.joined(separator: ", "))")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(Theme.green)
                        }
                        if !change.sshLost.isEmpty {
                            Text(verbatim: "− loses SSH as \(change.sshLost.joined(separator: ", "))")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(Theme.red)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
                    .background(RoundedRectangle(cornerRadius: 6).fill(Theme.panel))
                }
            }
        }
        .frame(maxHeight: 320)
    }

    private func prepare() async {
        guard let newTree = try? HuJSONParser.parse(candidate.text) else {
            blocker = "This policy doesn't parse, so it can't be pushed."
            loading = false
            return
        }
        var newModel = PolicyModel(tree: newTree)
        newModel.userAutogroups = store.model.userAutogroups
        candidateErrors = lintPolicy(newModel).filter { $0.severity == .error }
        do {
            let current = try await client.getPolicy()
            serverText = current
            if let report = try? await client.validate(candidate.text) {
                serverVerdict = report.passed ? "" : report.summary
            }
            if store.isGitOps {
                // Git is the source of truth; drift shows in the banner instead.
            } else if let last = store.currentWorkspace.lastSyncedPolicy {
                if last != current { conflictBase = last }
            } else {
                noSyncRecord = !current.isEmpty
            }
            var nodes = store.headscaleNodes
            if nodes.isEmpty {
                nodes = try await client.listNodes()
                store.headscaleNodes = nodes
            }
            deviceCount = nodes.count
            if current.isEmpty {
                previewNote = "The server has no policy yet, so there's nothing to compare against."
            } else if let oldTree = try? HuJSONParser.parse(current) {
                var oldModel = PolicyModel(tree: oldTree)
                oldModel.userAutogroups = newModel.userAutogroups
                changes = accessChanges(from: oldModel, to: newModel, nodes: nodes)
                if [oldModel, newModel].contains(where: \.usesPostures) {
                    postureUnknown = nodes.filter { $0.attributes == nil }.count
                }
                models = (oldModel, newModel)
                // Traffic already loaded (Traffic screen): check right away.
                if let traffic = store.traffic {
                    blocked = trafficBlocked(by: newModel, was: oldModel, traffic: traffic.connections, nodes: nodes)
                }
            } else {
                previewNote = "The server's current policy couldn't be parsed here, so no access comparison is available."
            }
        } catch {
            blocker = "Couldn't read the server's current policy, so there would be no rollback copy: \(error.localizedDescription)"
        }
        loading = false
    }

    /// Git mode: the reviewed policy goes to GitHub as a pull request; the
    /// review (access changes, checks, traffic) becomes its description.
    private func openPullRequest() {
        guard let file = store.linkedFileURL else { return }
        pushing = true
        prError = nil
        let title = prTitle.trimmingCharacters(in: .whitespaces).isEmpty
            ? (candidate.isRestore ? "Restore an earlier tailnet policy" : "Update tailnet policy") : prTitle
        Task {
            defer { pushing = false }
            do {
                guard let repo = await GitRepo.containing(file) else {
                    throw GitError(message: "\(file.lastPathComponent) isn't in a Git repository anymore.")
                }
                let url = try await repo.openPullRequest(files: [repo.relativePath(file): candidate.text],
                                                         title: title, body: reviewMarkdown)
                pullRequest = url
                store.snapshot(reason: "pull request opened")
                NSWorkspace.shared.open(url)
            } catch {
                prError = error.localizedDescription
            }
        }
    }

    private func push() {
        let record = PushRecord(date: Date(), server: host,
                                before: serverText ?? "", pushed: candidate.text)
        pushing = true
        Task {
            do {
                try PushHistory.append(record)
            } catch {
                blocker = "Couldn't save the rollback copy, so nothing was pushed: \(error.localizedDescription)"
                pushing = false
                return
            }
            do {
                try await client.setPolicy(candidate.text)
                pushing = false
                onPushed()
                dismiss()
            } catch {
                PushHistory.remove(id: record.id)
                blocker = "The server refused the policy: \(error.localizedDescription)"
                pushing = false
            }
        }
    }
}
