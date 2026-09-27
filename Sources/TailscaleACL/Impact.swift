import Foundation

/// How network access between two real nodes differs between two policies.
struct AccessChange: Identifiable {
    var src: String
    var dst: String
    var gained: [String]
    var lost: [String]
    var sshGained: [String] = []
    var sshLost: [String] = []

    var id: String { "\(src)→\(dst)" }
}

/// Port label used for "any port not named explicitly in either policy".
let otherPortsLabel = "other ports"
/// SSH login label used for "any non-root account not named in either policy".
let otherLoginsLabel = "other users"

/// Diff node-to-node access between `old` and `new`.
/// ponytail: probes only ports named in either policy (singles and range
/// endpoints) plus one unnamed port standing in for "everything else", on
/// TCP/UDP; SSH is probed for root, every login named in either policy, and
/// one unnamed non-root login. A change strictly inside a port range, ICMP-only
/// rules, and accept↔check action changes are not detected.
func accessChanges(from old: PolicyModel, to new: PolicyModel,
                   nodes: [HeadscaleNode]) -> [AccessChange] {
    var named = mentionedPorts(old).union(mentionedPorts(new))
    let unnamed = (1...65535).first { !named.contains($0) } ?? 0
    named.insert(unnamed)
    let probes = named.sorted()

    let before = Evaluator(model: old)
    let after = Evaluator(model: new)
    func label(_ p: Int) -> String { p == unnamed ? otherPortsLabel : String(p) }

    var logins = Set((old.sshRules + new.sshRules).flatMap(\.users).filter { !$0.hasPrefix("autogroup:") })
    logins.insert("root")
    let unnamedLogin = "tailscale-acl-probe-user"
    let loginProbes = logins.sorted() + [unnamedLogin]
    func sshOK(_ ev: Evaluator, _ s: HeadscaleNode, _ d: HeadscaleNode, _ login: String) -> Bool {
        ev.sshNetworkAllowed(sourceIDs: s.identities, destIDs: d.identities)
            && !ev.evaluateSSH(sourceIDs: s.identities, destIDs: d.identities, login: login).isEmpty
    }

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
            var sshGained: [String] = []
            var sshLost: [String] = []
            for login in loginProbes {
                let was = sshOK(before, s, d, login)
                let now = sshOK(after, s, d, login)
                let name = login == unnamedLogin ? otherLoginsLabel : login
                if now && !was { sshGained.append(name) }
                if was && !now { sshLost.append(name) }
            }
            if !gained.isEmpty || !lost.isEmpty || !sshGained.isEmpty || !sshLost.isEmpty {
                changes.append(AccessChange(src: s.displayName, dst: d.displayName,
                                            gained: gained, lost: lost,
                                            sshGained: sshGained, sshLost: sshLost))
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
