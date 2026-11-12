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

/// The text as the app writes it (parsed and serialized, comments kept), so
/// comparing two policies shows what changed, not how they're laid out — a
/// Visual Builder edit rewrites the whole draft in this style.
func normalizedPolicy(_ text: String) -> String {
    (try? HuJSONParser.parse(text)).map(HuJSONSerializer.serialize) ?? text
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
                          liveChanged: normalizedPolicy(live.text) != normalizedPolicy(draft.base),
                          changed: normalizedPolicy(live.text) != normalizedPolicy(draft.text))
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

    /// `since`: when the draft the editor started from was saved. A save from
    /// an older copy (another tab, an old page) is refused, not written over newer work.
    struct Save: Decodable { var text: String; var since: Date? }
    api.put("sources/:source/draft") { request, context -> DraftReply in
        let live = try await state.liveSnapshot(context)
        let (person, source) = (try user(context), try context.parameters.require("source"))
        let body = try await request.decode(as: Save.self, context: context)
        guard body.text.utf8.count <= DraftStore.maxSize else { throw HTTPError(.contentTooLarge, message: "A policy that large isn't supported.") }
        var draft = state.drafts.load(person, source) ?? Draft(source: source, base: live.text, text: live.text, started: Date(), updated: Date())
        // Saved to the second, so a second's slack.
        if let since = body.since, draft.updated.timeIntervalSince(since) > 1 {
            throw HTTPError(.conflict, message: "Your draft was changed elsewhere (another tab or window) after this page loaded it. Reload to see it.")
        }
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
        let (liveNow, base, mine) = (normalizedPolicy(live.text), normalizedPolicy(draft.base), normalizedPolicy(draft.text))
        let liveDiff = liveNow == base ? [] : lines(lineDiff(old: base, new: liveNow))
        guard let new = s.model else {
            return ReviewReply(valid: false, error: s.parseError.map { .init(line: $0.line, message: $0.message) },
                               diff: lines(lineDiff(old: liveNow, new: mine)), liveDiff: liveDiff, access: [],
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
            valid: true, error: nil, diff: lines(lineDiff(old: liveNow, new: mine)), liveDiff: liveDiff, access: access,
            devicesCompared: live.nodes.count,
            newProblems: newIssues.filter { !before.contains($0.id) }.map { i in
                .init(severity: i.severity == .error ? "error" : "warning", title: i.title, detail: i.detail,
                      line: i.line ?? i.path.flatMap { s.tree?.line(at: $0) })
            },
            fixedProblems: before.subtracting(after).count,
            testsTotal: results.count, testsFailing: results.filter { !$0 }.count)
    }

    // One edit to the draft (the Visual Builder's), done with the same tree
    // edits as the Mac app, so comments and layout elsewhere survive.
    api.post("sources/:source/draft/edit") { request, context -> DraftReply in
        let live = try await state.liveSnapshot(context)
        let (person, source) = (try user(context), try context.parameters.require("source"))
        let edit = try await request.decode(as: DraftEdit.self, context: context)
        var draft = state.drafts.load(person, source) ?? Draft(source: source, base: live.text, text: live.text, started: Date(), updated: Date())
        guard var tree = try? HuJSONParser.parse(draft.text) else {
            throw HTTPError(.conflict, message: "Your draft has a syntax error; fix it in the Policy view first.")
        }
        try edit.apply(to: &tree)
        draft.text = HuJSONSerializer.serialize(tree)
        draft.updated = Date()
        try state.drafts.save(draft, for: person)
        return reply(draft, live: live)
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

// MARK: - Edits

/// One Visual Builder edit, checked before it touches the draft.
struct DraftEdit: Decodable {
    var op: String
    var kind: String?      // addBox: group, tag, host, ipset
    var name: String?      // a box
    var newName: String?   // rename
    var values: [String]?  // members (groups), owners (tags)
    var address: String?   // hosts, IP sets
    var src: String?
    var dst: String?       // connect: the destination box; setPorts/disconnect: the rule's dst as written
    var ports: String?
    var proto: String?
    var rule: String?      // "grant3", "acl1"
    var asACL: Bool?

    private func need(_ value: String?, _ what: String) throws -> String {
        guard let v = value?.trimmingCharacters(in: .whitespaces), !v.isEmpty, v.count <= 200,
              !v.contains(where: { $0.isNewline }) else { throw HTTPError(.badRequest, message: "Give \(what).") }
        return v
    }

    /// "*", or ports and ranges: "22", "80,443", "8000-8100".
    private func checkedPorts() throws -> String {
        let p = try need(ports, "the ports").replacingOccurrences(of: " ", with: "")
        let ok = p == "*" || p.split(separator: ",", omittingEmptySubsequences: false).allSatisfy { part in
            let ends = part.split(separator: "-", omittingEmptySubsequences: false)
            return (1...2).contains(ends.count) && ends.allSatisfy { Int($0).map { (0...65_535).contains($0) } ?? false }
        }
        guard ok else { throw HTTPError(.badRequest, message: "Ports: *, a port, or a list like 22,443 or 8000-8100.") }
        return p
    }

    private func checkedProto() throws -> String? {
        let p = (proto ?? "").lowercased()
        guard ["", "any", "tcp", "udp"].contains(p) else { throw HTTPError(.badRequest, message: "Protocol: tcp, udp, or any.") }
        return p.isEmpty || p == "any" ? nil : p
    }

    private func ruleIndex() throws -> (grant: Bool, index: Int) {
        let r = try need(rule, "the rule")
        if r.hasPrefix("grant"), let i = Int(r.dropFirst(5)) { return (true, i) }
        if r.hasPrefix("acl"), let i = Int(r.dropFirst(3)) { return (false, i) }
        throw HTTPError(.badRequest, message: "Unknown rule.")
    }

    func apply(to tree: inout JSON) throws {
        switch op {
        case "addBox":
            let kinds: [String: PolicyEntityKind] = ["group": .group, "tag": .tag, "host": .host, "ipset": .ipSet]
            guard let kind = kinds[kind ?? ""] else { throw HTTPError(.badRequest, message: "Kind: group, tag, host, or ipset.") }
            let name = try need(self.name, "a name")
            var address = ""
            if kind == .host || kind == .ipSet {
                address = try need(self.address, "an address")
                guard isAddressLike(address) else { throw HTTPError(.badRequest, message: "\(address) isn't an IP address or range.") }
            }
            PolicyEdit.addEntity(&tree, kind: kind, name: name, address: address)
        case "renameBox":
            PolicyEdit.renameEntity(&tree, from: try need(name, "the box"), to: try need(newName, "the new name"))
        case "deleteBox":
            PolicyEdit.deleteEntity(&tree, try need(name, "the box"))
        case "setMembers":
            let name = try need(self.name, "the box")
            let section = name.hasPrefix("group:") ? "groups" : name.hasPrefix("tag:") ? "tagOwners" : nil
            guard let section else { throw HTTPError(.badRequest, message: "Only groups have members and tags owners.") }
            let list = (values ?? []).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            PolicyEdit.setEntityList(&tree, section: section, key: name, values: list)
        case "setAddress":
            let address = try need(self.address, "an address")
            guard isAddressLike(address) else { throw HTTPError(.badRequest, message: "\(address) isn't an IP address or range.") }
            PolicyEdit.setHostAddress(&tree, name: try need(name, "the host"), address: address)
        case "connect":
            let (src, dst, ports, proto) = (try need(src, "the source"), try need(dst, "the destination"), try checkedPorts(), try checkedProto())
            if asACL == true {
                PolicyEdit.addRule(&tree, src: src, dstTarget: dst, ports: ports, proto: proto)
            } else {
                PolicyEdit.addGrant(&tree, src: src, dstTarget: dst, ports: ports, proto: proto)
            }
        case "setPorts":
            let (r, ports, proto) = (try ruleIndex(), try checkedPorts(), try checkedProto())
            if r.grant {
                PolicyEdit.updateGrantIP(&tree, grantIndex: r.index, ports: ports, proto: proto)
            } else {
                PolicyEdit.updateConnection(&tree, ruleIndex: r.index, oldDst: try need(dst, "the destination"), newPorts: ports, proto: proto)
            }
        case "disconnect":
            let (r, dst) = (try ruleIndex(), try need(dst, "the destination"))
            if r.grant {
                PolicyEdit.removeGrantConnection(&tree, grantIndex: r.index, dst: dst)
            } else {
                PolicyEdit.removeConnection(&tree, ruleIndex: r.index, dst: dst)
            }
        default:
            throw HTTPError(.badRequest, message: "Unknown edit.")
        }
    }
}
