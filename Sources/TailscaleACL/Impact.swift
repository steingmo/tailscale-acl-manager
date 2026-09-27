import Foundation

/// How network access between two real nodes differs between two policies.
struct AccessChange: Identifiable {
    var src: String
    var dst: String
    var gained: [String]
    var lost: [String]

    var id: String { "\(src)→\(dst)" }
}

/// Port label used for "any port not named explicitly in either policy".
let otherPortsLabel = "other ports"

/// Diff node-to-node access between `old` and `new`.
/// ponytail: probes only ports named in either policy (singles and range
/// endpoints) plus one unnamed port standing in for "everything else", on
/// TCP/UDP. A change strictly inside a range, ICMP-only rules, and SSH rules
/// are not detected; exhaustive port-interval diffing would cover them.
func accessChanges(from old: PolicyModel, to new: PolicyModel,
                   nodes: [HeadscaleNode]) -> [AccessChange] {
    var named = mentionedPorts(old).union(mentionedPorts(new))
    let unnamed = (1...65535).first { !named.contains($0) } ?? 0
    named.insert(unnamed)
    let probes = named.sorted()

    let before = Evaluator(model: old)
    let after = Evaluator(model: new)
    func label(_ p: Int) -> String { p == unnamed ? otherPortsLabel : String(p) }

    var changes: [AccessChange] = []
    for s in nodes {
        for d in nodes where d.id != s.id {
            var gained: [String] = []
            var lost: [String] = []
            for p in probes {
                let was = before.evaluate(sourceIDs: s.identities, destIDs: d.identities, port: p).allowed
                let now = after.evaluate(sourceIDs: s.identities, destIDs: d.identities, port: p).allowed
                if now && !was { gained.append(label(p)) }
                if was && !now { lost.append(label(p)) }
            }
            if !gained.isEmpty || !lost.isEmpty {
                changes.append(AccessChange(src: s.displayName, dst: d.displayName,
                                            gained: gained, lost: lost))
            }
        }
    }
    return changes
}

/// Every port number named in ACL dst specs or grant ip entries.
private func mentionedPorts(_ m: PolicyModel) -> Set<Int> {
    var specs = m.rules.flatMap { $0.dst.map { DestSpec($0).ports } }
    specs += m.grants.flatMap { $0.ip.map { $0.split(separator: ":").last.map(String.init) ?? $0 } }
    var ports = Set<Int>()
    for spec in specs {
        for part in spec.split(separator: ",") {
            for bound in part.split(separator: "-") {
                if let n = Int(bound.trimmingCharacters(in: .whitespaces)), (1...65535).contains(n) {
                    ports.insert(n)
                }
            }
        }
    }
    return ports
}
