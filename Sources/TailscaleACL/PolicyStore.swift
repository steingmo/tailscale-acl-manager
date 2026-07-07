import SwiftUI
import AppKit
import UniformTypeIdentifiers

@MainActor
final class PolicyStore: ObservableObject {
    @Published var text: String = "" {
        // Typing triggers a short debounce so the parse + evaluation + full
        // app re-render doesn't run on every keystroke.
        didSet { if text != oldValue { scheduleReparse() } }
    }
    @Published private(set) var tree: JSON?
    @Published private(set) var model = PolicyModel()
    @Published private(set) var parseError: HuJSONError?
    @Published private(set) var testResults: [TestResult] = []

    private var parseTask: Task<Void, Never>?

    var evaluator: Evaluator { Evaluator(model: model) }
    var isValid: Bool { parseError == nil && tree != nil }

    init() {
        text = SamplePolicy.text
        reparseNow()
    }

    private func scheduleReparse() {
        parseTask?.cancel()
        parseTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 120_000_000)
            guard !Task.isCancelled else { return }
            self?.reparseNow()
        }
    }

    private func reparseNow() {
        parseTask?.cancel()
        parseTask = nil
        do {
            let parsed = try HuJSONParser.parse(text)
            tree = parsed
            model = PolicyModel(tree: parsed)
            parseError = nil
            testResults = evaluator.runTests()
        } catch let error as HuJSONError {
            parseError = error
        } catch {
            parseError = HuJSONError(message: "\(error)", line: 0)
        }
    }

    /// Apply a structural edit to the tree and regenerate the policy text,
    /// preserving comments captured at parse time. Parses immediately so the
    /// UI reflects the edit without the typing debounce.
    func mutate(_ edit: (inout JSON) -> Void) {
        guard var t = tree else { return }
        edit(&t)
        text = HuJSONSerializer.serialize(t)
        reparseNow()
    }

    func reset() {
        text = SamplePolicy.text
        reparseNow()
    }

    // MARK: - Clipboard / files

    func copyToClipboard() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    func importFromFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json, .text, .plainText, .data]
        panel.allowsOtherFileTypes = true
        panel.message = "Choose a Tailscale ACL policy file (HuJSON)"
        if panel.runModal() == .OK, let url = panel.url,
           let contents = try? String(contentsOf: url, encoding: .utf8) {
            text = contents
            reparseNow()
        }
    }

    func exportToFile() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = "policy.hujson"
        panel.allowsOtherFileTypes = true
        panel.message = "Export the current ACL policy"
        if panel.runModal() == .OK, let url = panel.url {
            try? text.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    // MARK: - Rule editing (used by the visual builder)

    func addRule(src: String, dstTarget: String, ports: String, proto: String?) {
        mutate { tree in
            var members: [JSON.Member] = [
                .init(comments: [], key: "action", value: .string("accept")),
                .init(comments: [], key: "src", value: stringArrayJSON([src])),
                .init(comments: [], key: "dst",
                      value: stringArrayJSON([DestSpec(target: dstTarget, ports: ports).spec])),
            ]
            if let proto, !proto.isEmpty, proto != "any" {
                members.insert(.init(comments: [], key: "proto", value: .string(proto)), at: 1)
            }
            var acls = tree["acls"]?.elements ?? []
            acls.append(JSON.Element(comments: [], value: .object(members)))
            if tree["acls"] == nil {
                tree["acls"] = .array(acls)
            } else {
                tree["acls"]?.elements = acls
            }
        }
    }

    /// Replace one dst entry of a rule (edit ports/protocol of a connection).
    func updateConnection(ruleIndex: Int, oldDst: String, newPorts: String, proto: String?) {
        mutate { tree in
            guard var acls = tree["acls"]?.elements, acls.indices.contains(ruleIndex) else { return }
            var rule = acls[ruleIndex].value
            var dst = rule["dst"]?.stringArray ?? []
            if let i = dst.firstIndex(of: oldDst) {
                dst[i] = DestSpec(target: DestSpec(oldDst).target, ports: newPorts).spec
            }
            rule["dst"] = stringArrayJSON(dst)
            if let proto, !proto.isEmpty, proto != "any" {
                rule["proto"] = .string(proto)
            } else {
                rule["proto"] = nil
            }
            acls[ruleIndex].value = rule
            tree["acls"]?.elements = acls
        }
    }

    /// Remove one dst entry; removes the whole rule if it was the last dst.
    func removeConnection(ruleIndex: Int, dst dstSpec: String) {
        mutate { tree in
            guard var acls = tree["acls"]?.elements, acls.indices.contains(ruleIndex) else { return }
            var rule = acls[ruleIndex].value
            var dst = rule["dst"]?.stringArray ?? []
            dst.removeAll { $0 == dstSpec }
            if dst.isEmpty {
                acls.remove(at: ruleIndex)
            } else {
                rule["dst"] = stringArrayJSON(dst)
                acls[ruleIndex].value = rule
            }
            tree["acls"]?.elements = acls
        }
    }

    // MARK: - Grant editing (modern syntax)

    /// Build grant `ip` entries from a ports string and protocol
    /// ("22,80" + tcp → ["tcp:22", "tcp:80"]).
    nonisolated static func ipEntries(ports: String, proto: String?) -> [String] {
        let parts = ports == "*"
            ? ["*"]
            : ports.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard let proto, proto != "any", !proto.isEmpty else { return parts }
        return parts.map { "\(proto):\($0)" }
    }

    /// Derive (proto, ports) UI fields from grant `ip` entries.
    nonisolated static func splitIPEntries(_ entries: [String]) -> (proto: String, ports: String) {
        var protos = Set<String>()
        var ports: [String] = []
        for e in entries {
            if let colon = e.firstIndex(of: ":") {
                protos.insert(String(e[..<colon]).lowercased())
                ports.append(String(e[e.index(after: colon)...]))
            } else {
                protos.insert("any")
                ports.append(e)
            }
        }
        let proto = protos.count == 1 ? protos.first! : "any"
        return (["tcp", "udp", "any"].contains(proto) ? proto : "any",
                ports.joined(separator: ","))
    }

    func addGrant(src: String, dstTarget: String, ports: String, proto: String?) {
        let entries = Self.ipEntries(ports: ports, proto: proto)
        mutate { tree in
            let members: [JSON.Member] = [
                .init(comments: [], key: "src", value: stringArrayJSON([src])),
                .init(comments: [], key: "dst", value: stringArrayJSON([dstTarget])),
                .init(comments: [], key: "ip", value: stringArrayJSON(entries)),
            ]
            var grants = tree["grants"]?.elements ?? []
            grants.append(JSON.Element(comments: [], value: .object(members)))
            if tree["grants"] == nil {
                tree["grants"] = .array(grants)
            } else {
                tree["grants"]?.elements = grants
            }
        }
    }

    func updateGrantIP(grantIndex: Int, ports: String, proto: String?) {
        let entries = Self.ipEntries(ports: ports, proto: proto)
        mutate { tree in
            guard var grants = tree["grants"]?.elements,
                  grants.indices.contains(grantIndex) else { return }
            var grant = grants[grantIndex].value
            grant["ip"] = stringArrayJSON(entries)
            grants[grantIndex].value = grant
            tree["grants"]?.elements = grants
        }
    }

    /// Remove one dst from a grant; removes the grant when no dst remains.
    func removeGrantConnection(grantIndex: Int, dst dstName: String) {
        mutate { tree in
            guard var grants = tree["grants"]?.elements,
                  grants.indices.contains(grantIndex) else { return }
            var grant = grants[grantIndex].value
            var dst = grant["dst"]?.stringArray ?? []
            dst.removeAll { $0 == dstName }
            if dst.isEmpty {
                grants.remove(at: grantIndex)
            } else {
                grant["dst"] = stringArrayJSON(dst)
                grants[grantIndex].value = grant
            }
            tree["grants"]?.elements = grants
        }
    }

    // MARK: - Entity editing

    enum EntityKind: String, CaseIterable, Identifiable {
        case group = "Group"
        case tag = "Tag"
        case host = "Host"
        case ipSet = "IP set"
        var id: String { rawValue }
    }

    func addEntity(kind: EntityKind, name: String, address: String) {
        let fullName: String
        switch kind {
        case .group: fullName = name.hasPrefix("group:") ? name : "group:\(name)"
        case .tag: fullName = name.hasPrefix("tag:") ? name : "tag:\(name)"
        case .ipSet: fullName = name.hasPrefix("ipset:") ? name : "ipset:\(name)"
        case .host: fullName = name
        }
        mutate { tree in
            switch kind {
            case .group:
                appendMember(&tree, section: "groups", key: fullName, value: .array([]))
            case .tag:
                appendMember(&tree, section: "tagOwners", key: fullName, value: .array([]))
            case .host:
                appendMember(&tree, section: "hosts", key: fullName, value: .string(address))
            case .ipSet:
                appendMember(&tree, section: "ipsets", key: fullName,
                             value: .array([JSON.Element(comments: [], value: .string(address))]))
            }
        }
    }

    /// Replace the string list of a groups/tagOwners entry (members / owners).
    func setEntityList(section: String, key: String, values: [String]) {
        mutate { tree in
            guard var members = tree[section]?.members,
                  let i = members.firstIndex(where: { $0.key == key }) else { return }
            members[i].value = stringArrayJSON(values)
            tree[section] = .object(members)
        }
    }

    /// Change a host's IP address or CIDR.
    func setHostAddress(name: String, address: String) {
        mutate { tree in
            guard var members = tree["hosts"]?.members,
                  let i = members.firstIndex(where: { $0.key == name }) else { return }
            members[i].value = .string(address)
            tree["hosts"] = .object(members)
        }
    }

    /// Rename an entity everywhere: section keys, tag owners, src/dst specs, tests.
    func renameEntity(from oldName: String, to newName: String) {
        guard oldName != newName, !newName.isEmpty else { return }
        mutate { tree in
            rewriteNames(&tree, from: oldName, to: newName)
        }
    }

    /// Delete an entity and clean up every rule/test that references it.
    func deleteEntity(_ name: String) {
        mutate { tree in
            for section in ["groups", "tagOwners", "hosts", "ipsets"] {
                if var members = tree[section]?.members {
                    members.removeAll { $0.key == name }
                    tree[section]?.elements = nil
                    tree[section] = .object(members)
                }
            }
            // Drop the entity from tagOwners owner lists and group members.
            for section in ["groups", "tagOwners"] {
                if var members = tree[section]?.members {
                    for i in members.indices {
                        var values = members[i].value.stringArray
                        values.removeAll { $0 == name }
                        members[i].value = stringArrayJSON(values)
                    }
                    tree[section] = .object(members)
                }
            }
            // Clean acls.
            if var acls = tree["acls"]?.elements {
                for i in acls.indices {
                    var rule = acls[i].value
                    var src = rule["src"]?.stringArray ?? []
                    src.removeAll { $0 == name || $0 == "host:\(name)" }
                    var dst = rule["dst"]?.stringArray ?? []
                    dst.removeAll {
                        let t = DestSpec($0).target
                        return t == name || t == "host:\(name)"
                    }
                    rule["src"] = stringArrayJSON(src)
                    rule["dst"] = stringArrayJSON(dst)
                    acls[i].value = rule
                }
                acls.removeAll {
                    ($0.value["src"]?.stringArray.isEmpty ?? true)
                        || ($0.value["dst"]?.stringArray.isEmpty ?? true)
                }
                tree["acls"] = .array(acls)
            }
            // Clean grants (dst entries are bare targets; via lists too).
            if var grants = tree["grants"]?.elements {
                for i in grants.indices {
                    var grant = grants[i].value
                    for key in ["src", "dst", "via"] where grant[key] != nil {
                        var values = grant[key]?.stringArray ?? []
                        values.removeAll { $0 == name || $0 == "host:\(name)" }
                        if key == "via" && values.isEmpty {
                            grant[key] = nil
                        } else {
                            grant[key] = stringArrayJSON(values)
                        }
                    }
                    grants[i].value = grant
                }
                grants.removeAll {
                    ($0.value["src"]?.stringArray.isEmpty ?? true)
                        || ($0.value["dst"]?.stringArray.isEmpty ?? true)
                }
                tree["grants"] = .array(grants)
            }
            // Clean tests.
            if var tests = tree["tests"]?.elements {
                for i in tests.indices {
                    var test = tests[i].value
                    for key in ["accept", "deny"] {
                        if test[key] != nil {
                            var entries = test[key]?.stringArray ?? []
                            entries.removeAll { DestSpec($0).target == name }
                            if entries.isEmpty {
                                test[key] = nil
                            } else {
                                test[key] = stringArrayJSON(entries)
                            }
                        }
                    }
                    tests[i].value = test
                }
                tests.removeAll { $0.value["src"]?.stringValue == name }
                tree["tests"] = .array(tests)
            }
        }
    }

    // MARK: - Tests

    func addTest(src: String, accept: [String], deny: [String]) {
        mutate { tree in
            var members: [JSON.Member] = [
                .init(comments: [], key: "src", value: .string(src)),
            ]
            if !accept.isEmpty {
                members.append(.init(comments: [], key: "accept", value: stringArrayJSON(accept)))
            }
            if !deny.isEmpty {
                members.append(.init(comments: [], key: "deny", value: stringArrayJSON(deny)))
            }
            var tests = tree["tests"]?.elements ?? []
            tests.append(JSON.Element(comments: [], value: .object(members)))
            if tree["tests"] == nil {
                tree["tests"] = .array(tests)
            } else {
                tree["tests"]?.elements = tests
            }
        }
    }

    func deleteTest(index: Int) {
        mutate { tree in
            guard var tests = tree["tests"]?.elements, tests.indices.contains(index) else { return }
            tests.remove(at: index)
            tree["tests"]?.elements = tests
        }
    }
}

// MARK: - Tree helpers

private func stringArrayJSON(_ strings: [String]) -> JSON {
    .array(strings.map { JSON.Element(comments: [], value: .string($0)) })
}

private func appendMember(_ tree: inout JSON, section: String, key: String, value: JSON) {
    if var members = tree[section]?.members {
        guard !members.contains(where: { $0.key == key }) else { return }
        members.append(JSON.Member(comments: [], key: key, value: value))
        tree[section] = .object(members)
    } else {
        tree[section] = .object([JSON.Member(comments: [], key: key, value: value)])
    }
}

/// Recursively rewrite entity names in keys and string values.
/// Handles bare names ("group:eng") and dst specs with ports ("tag:server:22").
private func rewriteNames(_ tree: inout JSON, from oldName: String, to newName: String) {
    func rewriteString(_ s: String) -> String {
        if s == oldName { return newName }
        if s == "host:\(oldName)" { return "host:\(newName)" }
        let d = DestSpec(s)
        if d.target == oldName && s != d.target {
            return DestSpec(target: newName, ports: d.ports).spec
        }
        if d.target == "host:\(oldName)" && s != d.target {
            return DestSpec(target: "host:\(newName)", ports: d.ports).spec
        }
        return s
    }
    func walk(_ node: inout JSON) {
        switch node {
        case .string(let s):
            node = .string(rewriteString(s))
        case .array(var elements):
            for i in elements.indices { walk(&elements[i].value) }
            node = .array(elements)
        case .object(var members):
            for i in members.indices {
                if members[i].key == oldName { members[i].key = newName }
                walk(&members[i].value)
            }
            node = .object(members)
        default:
            break
        }
    }
    walk(&tree)
}
