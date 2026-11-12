import Foundation
import Hummingbird
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

// Drafts: each person edits their own copy of a tailnet's policy, checks it
// in every view, reviews what changes, and downloads it to import into the
// tailnet by hand. The server never writes to the tailnet.

/// One person's draft of one tailnet's policy.
struct Draft: Codable {
    var source: String
    /// The live policy when the draft started: if the live one has changed
    /// since, importing the draft would undo that change.
    var base: String
    var text: String
    var started: Date
    var updated: Date
}

/// Drafts as files in <dataDir>/drafts, one per person and tailnet, named by
/// a hash so no user name ends up in a path. Only the service can read them.
final class DraftStore: @unchecked Sendable {
    static let maxSize = 1_000_000
    let directory: URL
    private let lock = NSLock()

    init(dataDir: String, create: Bool) throws {
        directory = URL(fileURLWithPath: dataDir, isDirectory: true).appendingPathComponent("drafts", isDirectory: true)
        if create {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
    }

    private func url(_ user: SignedInUser, _ source: String) -> URL {
        let key = SHA256.hash(data: Data("\(user.id)\n\(source)".utf8)).map { String(format: "%02x", $0) }.joined()
        return directory.appendingPathComponent(key + ".json")
    }

    func load(_ user: SignedInUser, _ source: String) -> Draft? {
        lock.withLock {
            guard let data = FileManager.default.contents(atPath: url(user, source).path) else { return nil }
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            return try? decoder.decode(Draft.self, from: data)
        }
    }

    func save(_ draft: Draft, for user: SignedInUser) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(draft)
        let target = url(user, draft.source)
        let temporary = target.appendingPathExtension("new")
        try lock.withLock {
            guard FileManager.default.createFile(atPath: temporary.path, contents: data, attributes: [.posixPermissions: 0o600]) else {
                throw ConfigError("\(temporary.path): cannot write the draft")
            }
            // rename(2) replaces atomically whether or not there's a draft yet
            // (FileManager.replaceItemAt fails on Linux when there isn't).
            guard rename(temporary.path, target.path) == 0 else {
                throw ConfigError("\(target.path): cannot save the draft (\(String(cString: strerror(errno))))")
            }
        }
    }

    func delete(_ user: SignedInUser, _ source: String) {
        lock.withLock { try? FileManager.default.removeItem(at: url(user, source)) }
    }
}

extension ServerState {
    /// The live snapshot with the policy swapped for the person's draft —
    /// devices, users, and roles stay the live ones.
    func draftSnapshot(_ live: PolicySource.Snapshot, _ draft: Draft) -> PolicySource.Snapshot {
        var s = live
        s.text = draft.text
        s.tree = nil
        s.model = nil
        s.parseError = nil
        do {
            let tree = try HuJSONParser.parse(draft.text)
            var model = PolicyModel(tree: tree)
            model.userAutogroups = live.model?.userAutogroups ?? [:]
            s.tree = tree
            s.model = model
        } catch let error as HuJSONError {
            s.parseError = error
        } catch {
            s.parseError = HuJSONError(message: "\(error)", line: 0)
        }
        return s
    }
}

// MARK: - Replies

struct DraftReply: ResponseEncodable {
    struct ParseError: Encodable { var line: Int; var message: String }
    var exists: Bool
    var text: String?
    var started: Date?
    var updated: Date?
    var valid: Bool
    var error: ParseError?
    /// The live policy changed after the draft started.
    var liveChanged: Bool
    /// The draft differs from the live policy.
    var changed: Bool
}

struct ReviewReply: ResponseEncodable {
    struct Line: Encodable { var kind: String; var text: String }
    struct Change: Encodable { var src: String; var dst: String; var gained: [String]; var lost: [String]; var sshGained: [String]; var sshLost: [String] }
    struct Problem: Encodable { var severity: String; var title: String; var detail: String; var line: Int? }
    var valid: Bool
    var error: DraftReply.ParseError?
    /// Live → draft: what importing the draft would change.
    var diff: [Line]
    /// Base → live, when someone changed the live policy since the draft started.
    var liveDiff: [Line]
    var access: [Change]
    var devicesCompared: Int
    var newProblems: [Problem]
    var fixedProblems: Int
    var testsTotal: Int
    var testsFailing: Int
}

private func lines(_ diff: [DiffLine]) -> [ReviewReply.Line] {
    diff.map { l in
        .init(kind: { switch l.kind { case .same: "same"; case .added: "added"; case .removed: "removed"; case .skipped: "skipped" } }(), text: l.text)
    }
}

// MARK: - Routes

func addDraftRoutes(to api: RouterGroup<AppContext>, state: ServerState) {
    @Sendable func user(_ context: AppContext) throws -> SignedInUser {
        guard let user = context.user else { throw HTTPError(.unauthorized) }
        return user
    }
    @Sendable func reply(_ draft: Draft?, live: PolicySource.Snapshot) -> DraftReply {
        guard let draft else { return DraftReply(exists: false, valid: true, liveChanged: false, changed: false) }
        let s = state.draftSnapshot(live, draft)
        return DraftReply(exists: true, text: draft.text, started: draft.started, updated: draft.updated, valid: s.model != nil,
                          error: s.parseError.map { .init(line: $0.line, message: $0.message) },
                          liveChanged: live.text != draft.base, changed: live.text != draft.text)
    }

    api.get("sources/:source/draft") { _, context -> DraftReply in
        let live = try await state.liveSnapshot(context)
        return reply(state.drafts.load(try user(context), try context.parameters.require("source")), live: live)
    }

    // Start a draft from the live policy (or keep the one there is).
    api.post("sources/:source/draft") { _, context -> DraftReply in
        let live = try await state.liveSnapshot(context)
        let (person, source) = (try user(context), try context.parameters.require("source"))
        if let existing = state.drafts.load(person, source) { return reply(existing, live: live) }
        let draft = Draft(source: source, base: live.text, text: live.text, started: Date(), updated: Date())
        try state.drafts.save(draft, for: person)
        return reply(draft, live: live)
    }

    struct Save: Decodable { var text: String }
    api.put("sources/:source/draft") { request, context -> DraftReply in
        let live = try await state.liveSnapshot(context)
        let (person, source) = (try user(context), try context.parameters.require("source"))
        let body = try await request.decode(as: Save.self, context: context)
        guard body.text.utf8.count <= DraftStore.maxSize else { throw HTTPError(.contentTooLarge, message: "A policy that large isn't supported.") }
        var draft = state.drafts.load(person, source) ?? Draft(source: source, base: live.text, text: live.text, started: Date(), updated: Date())
        draft.text = body.text
        draft.updated = Date()
        try state.drafts.save(draft, for: person)
        return reply(draft, live: live)
    }

    api.delete("sources/:source/draft") { _, context -> HTTPResponse.Status in
        state.drafts.delete(try user(context), try context.parameters.require("source"))
        return .noContent
    }

    api.get("sources/:source/draft/review") { _, context -> ReviewReply in
        let live = try await state.liveSnapshot(context)
        guard let draft = state.drafts.load(try user(context), try context.parameters.require("source")) else {
            throw HTTPError(.notFound, message: "There's no draft to review.")
        }
        let s = state.draftSnapshot(live, draft)
        let liveDiff = live.text == draft.base ? [] : lines(lineDiff(old: draft.base, new: live.text))
        guard let new = s.model else {
            return ReviewReply(valid: false, error: s.parseError.map { .init(line: $0.line, message: $0.message) },
                               diff: lines(lineDiff(old: live.text, new: draft.text)), liveDiff: liveDiff, access: [],
                               devicesCompared: 0, newProblems: [], fixedProblems: 0, testsTotal: 0, testsFailing: 0)
        }
        var access: [ReviewReply.Change] = []
        var oldIssues: [LintIssue] = []
        if let old = live.model {
            access = accessChanges(from: old, to: new, nodes: live.nodes).map {
                .init(src: $0.src, dst: $0.dst, gained: $0.gained, lost: $0.lost, sshGained: $0.sshGained, sshLost: $0.sshLost)
            }
            oldIssues = lintPolicy(old) + lintNodes(old, nodes: live.nodes) + lintUsers(old, logins: live.logins)
        }
        let newIssues = lintPolicy(new) + lintNodes(new, nodes: live.nodes) + lintUsers(new, logins: live.logins)
        let before = Set(oldIssues.map(\.id)), after = Set(newIssues.map(\.id))
        let ev = Evaluator(model: new)
        let results = ev.runTests().map(\.passed) + ev.runSSHTests().map(\.passed)
        return ReviewReply(
            valid: true, error: nil, diff: lines(lineDiff(old: live.text, new: draft.text)), liveDiff: liveDiff, access: access,
            devicesCompared: live.nodes.count,
            newProblems: newIssues.filter { !before.contains($0.id) }.map { i in
                .init(severity: i.severity == .error ? "error" : "warning", title: i.title, detail: i.detail,
                      line: i.line ?? i.path.flatMap { s.tree?.line(at: $0) })
            },
            fixedProblems: before.subtracting(after).count,
            testsTotal: results.count, testsFailing: results.filter { !$0 }.count)
    }

    // The draft as a file, to import into the tailnet by hand.
    api.get("sources/:source/draft/export") { _, context -> Response in
        let source = try context.parameters.require("source")
        guard let draft = state.drafts.load(try user(context), source) else { throw HTTPError(.notFound, message: "There's no draft to export.") }
        guard (try? HuJSONParser.parse(draft.text)) != nil else {
            throw HTTPError(.conflict, message: "The draft has a syntax error; fix it before exporting.")
        }
        let stamp = ISO8601DateFormatter().string(from: Date()).prefix(10)
        var response = Response(status: .ok, headers: [.contentType: "application/octet-stream"],
                                body: .init(byteBuffer: .init(string: draft.text)))
        response.headers[.contentDisposition] = "attachment; filename=\"\(source)-policy-\(stamp).hujson\""
        return response
    }
}
