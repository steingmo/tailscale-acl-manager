import Foundation

// Edits to a policy tree: plain functions over the parsed HuJSON, so comments
// survive, shared by the Mac app (PolicyStore's methods wrap them in mutate)
// and the web service's drafts.

enum PolicyEntityKind: String, CaseIterable, Identifiable {
    case group = "Group"
    case tag = "Tag"
    case host = "Host"
    case ipSet = "IP set"
    var id: String { rawValue }
}

enum PolicyEdit {
    /// Build grant `ip` entries from a ports string and protocol
    /// ("22,80" + tcp → ["tcp:22", "tcp:80"]).
    static func ipEntries(ports: String, proto: String?) -> [String] {
        let parts = ports == "*"
            ? ["*"]
            : ports.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard let proto, proto != "any", !proto.isEmpty else { return parts }
        return parts.map { "\(proto):\($0)" }
    }

    /// Derive (proto, ports) UI fields from grant `ip` entries.
    static func splitIPEntries(_ entries: [String]) -> (proto: String, ports: String) {
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

    static func addRule(_ tree: inout JSON, src: String, dstTarget: String, ports: String, proto: String?) {
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

    /// Replace one dst entry of a rule (edit ports/protocol of a connection).
    static func updateConnection(_ tree: inout JSON, ruleIndex: Int, oldDst: String, newPorts: String, proto: String?) {
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

    /// Remove one dst entry; removes the whole rule if it was the last dst.
    static func removeConnection(_ tree: inout JSON, ruleIndex: Int, dst dstSpec: String) {
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

    static func addGrant(_ tree: inout JSON, src: String, dstTarget: String, ports: String, proto: String?) {
        let entries = PolicyEdit.ipEntries(ports: ports, proto: proto)
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

    static func updateGrantIP(_ tree: inout JSON, grantIndex: Int, ports: String, proto: String?) {
        let entries = PolicyEdit.ipEntries(ports: ports, proto: proto)
        guard var grants = tree["grants"]?.elements,
              grants.indices.contains(grantIndex) else { return }
        var grant = grants[grantIndex].value
        grant["ip"] = stringArrayJSON(entries)
        grants[grantIndex].value = grant
        tree["grants"]?.elements = grants
    }

    /// Remove one dst from a grant; removes the grant when no dst remains.
    static func removeGrantConnection(_ tree: inout JSON, grantIndex: Int, dst dstName: String) {
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

    static func addEntity(_ tree: inout JSON, kind: PolicyEntityKind, name: String, address: String) {
        let fullName: String
        switch kind {
        case .group: fullName = name.hasPrefix("group:") ? name : "group:\(name)"
        case .tag: fullName = name.hasPrefix("tag:") ? name : "tag:\(name)"
        case .ipSet: fullName = name.hasPrefix("ipset:") ? name : "ipset:\(name)"
        case .host: fullName = name
        }
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

    /// Replace the string list of a groups/tagOwners entry (members / owners).
    static func setEntityList(_ tree: inout JSON, section: String, key: String, values: [String]) {
        guard var members = tree[section]?.members,
              let i = members.firstIndex(where: { $0.key == key }) else { return }
        members[i].value = stringArrayJSON(values)
        tree[section] = .object(members)
    }

    /// Change a host's IP address or CIDR.
    static func setHostAddress(_ tree: inout JSON, name: String, address: String) {
        guard var members = tree["hosts"]?.members,
              let i = members.firstIndex(where: { $0.key == name }) else { return }
        members[i].value = .string(address)
        tree["hosts"] = .object(members)
    }

    /// Rename an entity everywhere: section keys, tag owners, src/dst specs, tests.
    static func renameEntity(_ tree: inout JSON, from oldName: String, to newName: String) {
        guard oldName != newName, !newName.isEmpty else { return }
        rewriteNames(&tree, from: oldName, to: newName)
    }

    /// Delete an entity and clean up every rule/test that references it.
    static func deleteEntity(_ tree: inout JSON, _ name: String) {
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

// MARK: - Tree helpers

func appendMember(_ tree: inout JSON, section: String, key: String, value: JSON) {
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
func rewriteNames(_ tree: inout JSON, from oldName: String, to newName: String) {
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

