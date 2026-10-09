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
        mutate { tree in
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
            // Clean ssh rules.
            if var ssh = tree["ssh"]?.elements {
                for i in ssh.indices {
                    var rule = ssh[i].value
                    for key in ["src", "dst"] where rule[key] != nil {
                        var values = rule[key]?.stringArray ?? []
                        values.removeAll { $0 == name || $0 == "host:\(name)" }
                        rule[key] = stringArrayJSON(values)
                    }
                    ssh[i].value = rule
                }
                ssh.removeAll {
                    ($0.value["src"]?.stringArray.isEmpty ?? true)
                        || ($0.value["dst"]?.stringArray.isEmpty ?? true)
                }
                tree["ssh"] = .array(ssh)
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

func stringArrayJSON(_ strings: [String]) -> JSON {
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
