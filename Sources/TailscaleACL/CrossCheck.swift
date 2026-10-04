import Foundation

// MARK: - Cross-checking with Tailscale's policy engine

/// Policy tests as HuJSON elements (shared by generated tests and cross-checks).
func testElements(_ tests: [ACLTest]) -> [JSON.Element] {
    tests.map { t in
        var members: [JSON.Member] = [.init(comments: [], key: "src", value: .string(t.src))]
        if !t.accept.isEmpty { members.append(.init(comments: [], key: "accept", value: stringArrayJSON(t.accept))) }
        if !t.deny.isEmpty { members.append(.init(comments: [], key: "deny", value: stringArrayJSON(t.deny))) }
        if let attrs = t.srcPostureAttrs, !attrs.isEmpty {
            // ponytail: values go out as strings (true/false as bools); numeric custom attributes would need their type kept.
            members.insert(.init(comments: [], key: "srcPostureAttrs", value: .object(attrs.sorted { $0.key < $1.key }.map { k, v in
                .init(comments: [], key: k, value: v == "true" || v == "false" ? .bool(v == "true") : .string(v))
            })), at: 1)
        }
        return JSON.Element(comments: [], value: .object(members))
    }
}

func sshTestElements(_ tests: [SSHTest]) -> [JSON.Element] {
    tests.map { t in
        var members: [JSON.Member] = [.init(comments: [], key: "src", value: .string(t.src)),
                                      .init(comments: [], key: "dst", value: stringArrayJSON(t.dst))]
        for (key, logins) in [("accept", t.accept), ("check", t.check), ("deny", t.deny)] where !logins.isEmpty {
            members.append(.init(comments: [], key: key, value: stringArrayJSON(logins)))
        }
        return JSON.Element(comments: [], value: .object(members))
    }
}

/// The policy with its tests replaced, so Tailscale evaluates exactly these
/// cases against the editor's (unsaved) policy.
func policyWithTests(_ text: String, _ tests: [ACLTest]) throws -> String {
    var tree = try HuJSONParser.parse(text)
    tree["tests"] = .array(testElements(tests))
    return HuJSONSerializer.serialize(tree)
}

struct TestDisagreement: Identifiable {
    var src: String
    var appPasses: Bool
    var errors: [String]
    var id: String { src }
}

/// Compare the app's test results with Tailscale's run of the same tests.
/// nil when Tailscale's answer can't be matched per test (e.g. a parse error).
func compareWithServer(local: [TestResult], report: ValidationReport) -> [TestDisagreement]? {
    if report.message != nil && report.failures.isEmpty { return nil }
    let failing = Dictionary(report.failures.map { ($0.user, $0.errors) }, uniquingKeysWith: +)
    var out: [TestDisagreement] = []
    for src in Set(local.map(\.src)).sorted() {
        let appPasses = local.filter { $0.src == src }.allSatisfy(\.passed)
        let serverPasses = failing[src] == nil
        if appPasses != serverPasses {
            out.append(TestDisagreement(src: src, appPasses: appPasses, errors: failing[src] ?? []))
        }
    }
    return out
}

// MARK: - Copying between workspaces

enum CopyOutcome: Equatable {
    case copied
    case alreadyThere
    case failed(String)
}

private let definitionSections = ["groups", "tagOwners", "hosts", "ipsets"]

/// Names a rule refers to (sources, destinations, SSH users excluded).
private func referencedNames(_ rule: JSON, section: String) -> [String] {
    var names = rule["src"]?.stringArray ?? []
    let dst = rule["dst"]?.stringArray ?? []
    names += section == "acls" ? dst.map { DestSpec($0).target } : dst
    names += rule["target"]?.stringArray ?? []
    return names.map { $0.hasPrefix("host:") ? String($0.dropFirst(5)) : $0 }
}

/// Copy the definitions of `names` (and groups their tag owners refer to)
/// from `source` into `target`, only where the target lacks them.
private func copyDefinitions(_ names: [String], from source: JSON, into target: inout JSON) -> Bool {
    var changed = false
    var pending = names
    var seen = Set<String>()
    while let name = pending.popLast() {
        guard seen.insert(name).inserted else { continue }
        for section in definitionSections {
            guard let member = source[section]?.members?.first(where: { $0.key == name }) else { continue }
            var members = target[section]?.members ?? []
            if !members.contains(where: { $0.key == name }) {
                members.append(member)
                target[section] = .object(members)
                changed = true
            }
            if section == "tagOwners" { pending += member.value.stringArray }
        }
    }
    return changed
}

/// Copy rule `index` of `section` (with its comment and the definitions it
/// needs) from `source` into the policy text `targetText`.
func copyRule(section: String, index: Int, from source: JSON,
              into targetText: String) -> (text: String?, outcome: CopyOutcome) {
    guard let rule = source[section]?.elements.flatMap({ $0.indices.contains(index) ? $0[index] : nil }) else {
        return (nil, .failed("rule not found"))
    }
    guard var target = try? HuJSONParser.parse(targetText.isEmpty ? "{}" : targetText) else {
        return (nil, .failed("its policy doesn't parse"))
    }
    let defsChanged = copyDefinitions(referencedNames(rule.value, section: section), from: source, into: &target)
    var list = target[section]?.elements ?? []
    let ruleText = HuJSONSerializer.serialize(rule.value)
    let duplicate = list.contains { HuJSONSerializer.serialize($0.value) == ruleText }
    if !duplicate {
        list.append(rule)
        target[section] = .array(list)
    }
    if duplicate && !defsChanged { return (nil, .alreadyThere) }
    return (HuJSONSerializer.serialize(target), duplicate ? .alreadyThere : .copied)
}

/// Copy entity definitions (groups, tags, hosts, IP sets) into `targetText`.
func copyEntities(_ names: [String], from source: JSON, into targetText: String) -> (text: String?, outcome: CopyOutcome) {
    guard var target = try? HuJSONParser.parse(targetText.isEmpty ? "{}" : targetText) else {
        return (nil, .failed("its policy doesn't parse"))
    }
    return copyDefinitions(names, from: source, into: &target)
        ? (HuJSONSerializer.serialize(target), .copied) : (nil, .alreadyThere)
}

/// Apply a template to another workspace's policy text.
func applyTemplate(_ template: PolicyTemplate, values: [String: String],
                   to targetText: String) -> (text: String?, outcome: CopyOutcome) {
    guard var target = try? HuJSONParser.parse(targetText.isEmpty ? "{}" : targetText) else {
        return (nil, .failed("its policy doesn't parse"))
    }
    template.apply(&target, values)
    return (HuJSONSerializer.serialize(target), .copied)
}
