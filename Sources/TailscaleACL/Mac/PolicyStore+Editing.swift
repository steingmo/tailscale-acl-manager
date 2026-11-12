import Foundation

/// Every structural edit to the policy. Each goes through `mutate`, so it's
/// one undoable step and comments survive.
extension PolicyStore {
    /// Groups whose members include any of `names` (case-insensitive).
    func groups(containing names: [String]) -> [String] {
        let wanted = Set(names.map { $0.lowercased() })
        return model.groupOrder.filter { g in (model.groups[g] ?? []).contains { wanted.contains($0.lowercased()) } }
    }

    /// Add a user to groups (skipping ones they're in) in one undoable step.
    func addUser(_ login: String, toGroups groups: [String]) {
        guard !groups.isEmpty else { return }
        mutate { tree in
            var list = tree["groups"]?.members ?? []
            for g in groups {
                if let i = list.firstIndex(where: { $0.key == g }) {
                    var members = list[i].value.elements ?? []
                    guard !members.contains(where: { $0.value.stringValue?.lowercased() == login.lowercased() }) else { continue }
                    members.append(JSON.Element(comments: [], value: .string(login)))
                    list[i].value = .array(members)
                } else {
                    list.append(JSON.Member(comments: [], key: g, value: stringArrayJSON([login])))
                }
            }
            tree["groups"] = .object(list)
        }
    }

    /// Offboarding: remove every name of a user from all groups and tag
    /// owners in one undoable step. Rules naming them directly are left for
    /// Problems to flag, since editing those changes other people's access.
    func removeUserEverywhere(_ names: [String]) {
        let wanted = Set(names.map { $0.lowercased() })
        mutate { tree in
            for section in ["groups", "tagOwners"] {
                guard var list = tree[section]?.members else { continue }
                for i in list.indices {
                    list[i].value.elements?.removeAll { wanted.contains($0.value.stringValue?.lowercased() ?? "") }
                }
                tree[section] = .object(list)
            }
        }
    }

    /// Narrow a rule to the ports real traffic used (one undoable step).
    func narrowRule(section: String, index: Int, to specs: [String]) {
        mutate { narrowRulePorts(&$0, section: section, index: index, to: specs) }
    }

    /// Rewrite ACL rules as grants in one undoable step.
    func convertToGrants() {
        mutate { convertACLsToGrants(&$0) }
    }

    /// Add a template's rules and definitions in one undoable step.
    func applyTemplate(_ template: PolicyTemplate, values: [String: String]) {
        mutate { template.apply(&$0, values) }
    }

    // MARK: - Rule editing (used by the visual builder)

    func addRule(src: String, dstTarget: String, ports: String, proto: String?) {
        mutate { PolicyEdit.addRule(&$0, src: src, dstTarget: dstTarget, ports: ports, proto: proto) }
    }

    /// Replace one dst entry of a rule (edit ports/protocol of a connection).
    func updateConnection(ruleIndex: Int, oldDst: String, newPorts: String, proto: String?) {
        mutate { PolicyEdit.updateConnection(&$0, ruleIndex: ruleIndex, oldDst: oldDst, newPorts: newPorts, proto: proto) }
    }

    /// Remove one dst entry; removes the whole rule if it was the last dst.
    func removeConnection(ruleIndex: Int, dst dstSpec: String) {
        mutate { PolicyEdit.removeConnection(&$0, ruleIndex: ruleIndex, dst: dstSpec) }
    }

    // MARK: - Grant editing (modern syntax)

    nonisolated static func ipEntries(ports: String, proto: String?) -> [String] { PolicyEdit.ipEntries(ports: ports, proto: proto) }
    nonisolated static func splitIPEntries(_ entries: [String]) -> (proto: String, ports: String) { PolicyEdit.splitIPEntries(entries) }

    func addGrant(src: String, dstTarget: String, ports: String, proto: String?) {
        mutate { PolicyEdit.addGrant(&$0, src: src, dstTarget: dstTarget, ports: ports, proto: proto) }
    }

    func updateGrantIP(grantIndex: Int, ports: String, proto: String?) {
        mutate { PolicyEdit.updateGrantIP(&$0, grantIndex: grantIndex, ports: ports, proto: proto) }
    }

    /// Remove one dst from a grant; removes the grant when no dst remains.
    func removeGrantConnection(grantIndex: Int, dst dstName: String) {
        mutate { PolicyEdit.removeGrantConnection(&$0, grantIndex: grantIndex, dst: dstName) }
    }

    // MARK: - SSH rules

    private func sshMembers(action: String, src: [String], dst: [String],
                            users: [String]) -> [JSON.Member] {
        [
            .init(comments: [], key: "action", value: .string(action)),
            .init(comments: [], key: "src", value: stringArrayJSON(src)),
            .init(comments: [], key: "dst", value: stringArrayJSON(dst)),
            .init(comments: [], key: "users", value: stringArrayJSON(users)),
        ]
    }

    func addSSHRule(action: String, src: [String], dst: [String], users: [String]) {
        mutate { tree in
            var rules = tree["ssh"]?.elements ?? []
            rules.append(JSON.Element(
                comments: [],
                value: .object(sshMembers(action: action, src: src, dst: dst, users: users))
            ))
            if tree["ssh"] == nil {
                tree["ssh"] = .array(rules)
            } else {
                tree["ssh"]?.elements = rules
            }
        }
    }

    func updateSSHRule(index: Int, action: String, src: [String], dst: [String],
                       users: [String]) {
        mutate { tree in
            guard var rules = tree["ssh"]?.elements, rules.indices.contains(index) else { return }
            rules[index].value = .object(sshMembers(action: action, src: src, dst: dst, users: users))
            tree["ssh"]?.elements = rules
        }
    }

    /// Create (index nil) or update one rule in "acls", "grants", or "ssh".
    /// Only the given keys change (nil removes a key), so fields the editor
    /// doesn't show — proto, app, via, srcPosture — are kept. `name` is the
    /// rule's first comment line. `expires` sets ("YYYY-MM-DD") or removes
    /// (.some(nil)) the "expires:" comment; leave it nil to keep it as is.
    func saveRule(section: String, index: Int?, name: String, expires: String?? = nil,
                  fields: [(key: String, value: JSON?)]) {
        mutate { applyRuleEdit(&$0, section: section, index: index, name: name, expires: expires, fields: fields) }
    }

    func deleteRule(section: String, index: Int) {
        mutate { tree in
            guard var list = tree[section]?.elements, list.indices.contains(index) else { return }
            list.remove(at: index)
            tree[section] = .array(list)
        }
    }

    /// Apply a one-click fix from the Problems screen (undoable).
    func apply(_ action: LintFix.Action) {
        switch action {
        case .addTagOwner(let tag):
            addEntity(kind: .tag, name: tag, address: "")
        case .defineGroup(let group):
            addEntity(kind: .group, name: group, address: "")
        case .deleteEntity(let name):
            deleteEntity(name)
        case .deleteRule(let section, let index):
            deleteRule(section: section, index: index)
        case .setSSHCheck(let index):
            mutate { tree in
                guard var rules = tree["ssh"]?.elements, rules.indices.contains(index) else { return }
                rules[index].value["action"] = .string("check")
                tree["ssh"] = .array(rules)
            }
        case .setTagOwners(let tag, let owners):
            mutate { tree in tree["tagOwners"]?[tag] = stringArrayJSON(owners) }
        case .replacePostureCondition(let posture, let index, let text):
            mutate { tree in
                guard var conditions = tree["postures"]?[posture]?.elements, conditions.indices.contains(index) else { return }
                conditions[index].value = .string(text)
                tree["postures"]?[posture] = .array(conditions)
            }
        case .moveToGroup(let section, let indices, let group, let members):
            mutate { tree in
                guard var rules = tree[section]?.elements, let first = indices.min(),
                      indices.allSatisfy(rules.indices.contains) else { return }
                if tree["groups"] == nil { tree["groups"] = .object([]) }
                tree["groups"]?[group] = stringArrayJSON(members)
                rules[first].value["src"] = stringArrayJSON([group])
                for i in indices.sorted(by: >) where i != first { rules.remove(at: i) }
                tree[section]?.elements = rules
            }
        case .removeGroupMember(let group, let member):
            mutate { tree in
                guard var members = tree["groups"]?[group]?.elements else { return }
                members.removeAll { $0.value.stringValue == member }
                tree["groups"]?[group] = .array(members)
            }
        }
    }

    /// Set the approvers for one route (empty removes it); `oldRoute` renames.
    func setRouteApprovers(route: String, approvers: [String], replacing oldRoute: String? = nil) {
        mutate { tree in
            var aa = tree["autoApprovers"] ?? .object([])
            var routes = aa["routes"]?.members ?? []
            if let i = routes.firstIndex(where: { $0.key == (oldRoute ?? route) }) {
                if approvers.isEmpty {
                    routes.remove(at: i)
                } else {
                    routes[i].key = route
                    routes[i].value = stringArrayJSON(approvers)
                }
            } else if !approvers.isEmpty {
                routes.append(JSON.Member(comments: [], key: route, value: stringArrayJSON(approvers)))
            }
            aa["routes"] = routes.isEmpty ? nil : .object(routes)
            tree["autoApprovers"] = (aa.members?.isEmpty ?? true) ? nil : aa
        }
    }

    func setExitNodeApprovers(_ approvers: [String]) {
        mutate { tree in
            var aa = tree["autoApprovers"] ?? .object([])
            aa["exitNode"] = approvers.isEmpty ? nil : stringArrayJSON(approvers)
            tree["autoApprovers"] = (aa.members?.isEmpty ?? true) ? nil : aa
        }
    }

    /// Add generated tests, or replace all existing tests with them.
    func setGeneratedTests(_ tests: [ACLTest], ssh: [SSHTest] = [], replacingExisting: Bool) {
        mutate { tree in
            let existing = replacingExisting ? [] : (tree["tests"]?.elements ?? [])
            let all = existing + testElements(tests)
            tree["tests"] = all.isEmpty ? nil : .array(all)
            if !ssh.isEmpty || replacingExisting {
                let existingSSH = replacingExisting ? [] : (tree["sshTests"]?.elements ?? [])
                let allSSH = existingSSH + sshTestElements(ssh)
                tree["sshTests"] = allSSH.isEmpty ? nil : .array(allSSH)
            }
        }
    }

    func deleteSSHTest(index: Int) {
        deleteRule(section: "sshTests", index: index)
    }

    func deleteSSHRule(index: Int) {
        mutate { tree in
            guard var rules = tree["ssh"]?.elements, rules.indices.contains(index) else { return }
            rules.remove(at: index)
            tree["ssh"]?.elements = rules
        }
    }

    // MARK: - Entity editing

    typealias EntityKind = PolicyEntityKind

    func addEntity(kind: EntityKind, name: String, address: String) {
        mutate { PolicyEdit.addEntity(&$0, kind: kind, name: name, address: address) }
    }

    /// Replace the string list of a groups/tagOwners entry (members / owners).
    func setEntityList(section: String, key: String, values: [String]) {
        mutate { PolicyEdit.setEntityList(&$0, section: section, key: key, values: values) }
    }

    /// Change a host's IP address or CIDR.
    func setHostAddress(name: String, address: String) {
        mutate { PolicyEdit.setHostAddress(&$0, name: name, address: address) }
    }

    /// Rename an entity everywhere: section keys, tag owners, src/dst specs, tests.
    func renameEntity(from oldName: String, to newName: String) {
        guard oldName != newName, !newName.isEmpty else { return }  // no rewrite of the text for nothing
        mutate { PolicyEdit.renameEntity(&$0, from: oldName, to: newName) }
    }

    /// Delete an entity and clean up every rule/test that references it.
    func deleteEntity(_ name: String) {
        mutate { PolicyEdit.deleteEntity(&$0, name) }
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

/// Create (index nil) or update one rule in `tree`: its fields (nil removes a
/// key), its name (first comment), and its expiry comment. Pure, so the rule
/// sheet can preview a rule before saving it.
func applyRuleEdit(_ tree: inout JSON, section: String, index: Int?, name: String, expires: String?? = nil,
                   fields: [(key: String, value: JSON?)]) {
    var list = tree[section]?.elements ?? []
    let existing = index.flatMap { list.indices.contains($0) ? $0 : nil }
    var element = existing.map { list[$0] } ?? JSON.Element(comments: [], value: .object([]))
    for field in fields { element.value[field.key] = field.value }
    var expiry = element.comments.filter { RuleExpiry.date(in: $0) != nil }
    if let expires { expiry = expires.map { [RuleExpiry.comment(for: $0)] } ?? [] }
    element.comments.removeAll { RuleExpiry.date(in: $0) != nil }
    let trimmed = name.trimmingCharacters(in: .whitespaces)
    if element.comments.isEmpty {
        if !trimmed.isEmpty { element.comments = [trimmed] }
    } else if trimmed.isEmpty {
        element.comments.removeFirst()
    } else {
        element.comments[0] = trimmed
    }
    element.comments += expiry
    if let existing { list[existing] = element } else { list.append(element) }
    tree[section] = .array(list)
}
