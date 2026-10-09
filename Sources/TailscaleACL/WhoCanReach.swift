import SwiftUI
import AppKit
import UniformTypeIdentifiers

/// One way someone reaches the target: through which source entry of which rule.
struct ReachAccess: Identifiable {
    var rule: String          // "Grant #14", or the rule's comment
    var section: String
    var index: Int
    var through: String       // the matching source, e.g. "group:mgmt-vpn"
    var ports: String         // "All", "TCP:3389", "SSH as root"
    var notes: [String]       // posture, via, expiry
    var id: String { "\(section)\(index)-\(through)-\(ports)" }
}

/// Someone (a person, or a tag / device / address for machine sources) and
/// every way they reach the target.
struct ReachEntry: Identifiable {
    var who: String
    var isPerson: Bool
    var access: [ReachAccess]
    var id: String { who }
}

/// The addresses and names the target stands for, so a rule to a covering
/// range ("10.114.32.0/24" for ipset:RDS) counts as reaching (part of) it.
func reachTargetIDs(_ target: String, _ m: PolicyModel, nodes: [HeadscaleNode]) -> [String] {
    if let node = nodes.first(where: { $0.displayName == target || $0.name == target }) { return node.identities }
    var ids = [target]
    ids += addressPrefixes(target, m, internet: false).map { String($0.split(separator: "/")[0]) }
    if target.hasPrefix("tag:") {
        ids += nodes.filter { $0.allTags.contains(target) }.flatMap { $0.ipAddresses ?? [] }
    }
    return ids.uniqued()
}

/// Everyone who can reach `target` (a device, host, IP, IP set, or tag), with
/// the rule, source, and ports of each path. Groups and autogroups expand to
/// the people in them; machine sources (tags, addresses) are listed as is.
func whoCanReach(_ target: String, _ m: PolicyModel, nodes: [HeadscaleNode], accounts: [ServerAccount]) -> [ReachEntry] {
    let ev = Evaluator(model: m)
    let destIDs = reachTargetIDs(target, m, nodes: nodes)
    func reaches(_ t: String) -> Bool { destIDs.contains { ev.targetMatches(target: t, destID: $0) } }

    // Everyone the policy or the server knows about.
    var people = Set(accounts.filter { !$0.isShared }.map(\.login))
    for members in m.groups.values { people.formUnion(members.filter { $0.contains("@") }) }
    for src in m.rules.flatMap(\.src) + m.grants.flatMap(\.src) + m.sshRules.flatMap(\.src) where src.contains("@") && !src.contains(":") {
        people.insert(src)
    }
    func expand(_ src: String) -> (people: [String], machines: [String]) {
        switch src {
        case "*", "autogroup:danger-all":
            return (people.sorted(), ["autogroup:tagged"])
        case "autogroup:member", "autogroup:members":
            return (people.sorted(), [])
        case "autogroup:tagged":
            return ([], ["autogroup:tagged"])
        default:
            if src.hasPrefix("group:") { return ((m.groups[src] ?? []).filter { $0.contains("@") }, []) }
            if src.contains("@") && !src.contains(":") { return ([src], []) }
            if src.hasPrefix("autogroup:") {
                return (people.filter { m.userAutogroups[$0.lowercased()]?.contains(src) == true }.sorted(), [])
            }
            return ([], [src])   // tag, host, IP, IP set
        }
    }
    func notes(_ posture: [String], _ via: [String], _ expires: String?) -> [String] {
        let required = posture.isEmpty ? m.defaultSrcPosture : posture
        return (required.isEmpty ? [] : ["if " + required.joined(separator: " or ")])
            + (via.isEmpty ? [] : ["via " + via.joined(separator: ", ")])
            + (expires.map { ["expires " + $0] } ?? [])
    }

    var byWho: [String: ReachEntry] = [:]
    func add(_ srcs: [String], _ access: (String) -> ReachAccess) {
        for src in srcs {
            let (p, machines) = expand(src)
            for who in p { byWho[who, default: ReachEntry(who: who, isPerson: true, access: [])].access.append(access(src)) }
            for who in machines { byWho[who, default: ReachEntry(who: who, isPerson: false, access: [])].access.append(access(src)) }
        }
    }
    for r in m.rules where r.action == "accept" {
        let ports = r.dst.map(DestSpec.init).filter { reaches($0.target) }.map(\.ports).uniqued()
        guard !ports.isEmpty else { continue }
        add(r.src) { ReachAccess(rule: r.comments.first ?? "Rule #\(r.index + 1)", section: "acls", index: r.index, through: $0,
                                 ports: ports == ["*"] ? "All" : (r.proto.map { $0.uppercased() + ":" } ?? "") + ports.joined(separator: ", "),
                                 notes: notes(r.srcPosture, [], r.expires)) }
    }
    for i in m.grants.indices {
        let g = m.grants[i]
        guard !g.ip.isEmpty, g.dst.contains(where: reaches) else { continue }
        add(g.src) { ReachAccess(rule: g.comments.first ?? "Grant #\(g.index + 1)", section: "grants", index: g.index, through: $0,
                                 ports: g.ip == ["*"] ? "All" : g.ip.map { $0.uppercased() }.joined(separator: ", "),
                                 notes: notes(g.srcPosture, g.via, g.expires)) }
    }
    for s in m.sshRules where s.dst.contains(where: reaches) {
        add(s.src) { ReachAccess(rule: s.comments.first ?? "SSH rule #\(s.index + 1)", section: "ssh", index: s.index, through: $0,
                                 ports: "SSH as " + s.users.joined(separator: ", ") + (s.action == "check" ? " (check)" : ""),
                                 notes: s.expires.map { ["expires " + $0] } ?? []) }
    }
    return byWho.values.sorted { ($0.isPerson ? 0 : 1, $0.who) < ($1.isPerson ? 0 : 1, $1.who) }
}

/// CSV with one line per path: who, through, rule, access, conditions.
func whoCanReachCSV(_ target: String, _ entries: [ReachEntry]) -> String {
    func field(_ s: String) -> String { "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\"" }
    var lines = ["who,kind,through,rule,access,conditions"]
    for e in entries {
        for a in e.access {
            lines.append([e.who, e.isPerson ? "person" : "machine", a.through, a.rule, a.ports, a.notes.joined(separator: "; ")]
                .map(field).joined(separator: ","))
        }
    }
    return lines.joined(separator: "\n") + "\n"
}

/// "Who can reach this?" as a searchable, exportable list (Access Map).
struct WhoCanReachSheet: View {
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State var target: String
    @State private var filter = ""

    private var suggestions: [String] {
        let m = store.model
        let all = m.hostOrder + m.ipsetOrder + m.tagOrder + store.headscaleNodes.map(\.displayName)
        let q = target.lowercased()
        return all.filter { q.isEmpty || $0.lowercased().contains(q) }.filter { $0 != target }.prefix(10).map { $0 }
    }

    var body: some View {
        let entries = target.isEmpty ? [] : whoCanReach(target, store.model, nodes: store.headscaleNodes, accounts: store.serverAccounts)
        let shown = entries.filter { filter.isEmpty || $0.who.localizedCaseInsensitiveContains(filter)
            || $0.access.contains { $0.through.localizedCaseInsensitiveContains(filter) } }
        let people = shown.filter(\.isPerson)
        let machines = shown.filter { !$0.isPerson }
        VStack(alignment: .leading, spacing: 10) {
            Text("Who can reach this?")
                .font(.system(size: 16, weight: .bold))
            TextField("Device, host, IP, IP set, or tag", text: $target)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 12, design: .monospaced))
            if !suggestions.isEmpty {
                FlowLayout(spacing: 5) {
                    ForEach(suggestions, id: \.self) { s in
                        Button(s) { target = s }
                            .buttonStyle(.plain)
                            .font(.system(size: 10.5, design: .monospaced))
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background(RoundedRectangle(cornerRadius: 4).fill(Theme.panel))
                    }
                }
            }
            if !target.isEmpty {
                HStack {
                    Text(verbatim: "\(people.count) \(people.count == 1 ? "person" : "people")"
                         + (machines.isEmpty ? "" : ", \(machines.count) machine source\(machines.count == 1 ? "" : "s")")
                         + " can reach all or part of \(target).")
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.textSecondary)
                    Spacer()
                    TextField("Filter", text: $filter).textFieldStyle(.roundedBorder).frame(width: 160)
                }
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(people + machines) { entry in row(entry) }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(minHeight: 260)
            HStack {
                Text("People come from groups, rules, and the server's users. Ports are for the whole rule.")
                    .font(.system(size: 10.5))
                    .foregroundStyle(Theme.textSecondary)
                Spacer()
                Button("Export CSV…") { export(entries) }.disabled(entries.isEmpty)
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 720, height: 560)
        .background(Theme.background)
    }

    private func row(_ entry: ReachEntry) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: entry.isPerson ? "person" : "server.rack")
                .foregroundStyle(entry.isPerson ? Theme.green : Theme.purple)
                .frame(width: 16)
            Text(verbatim: entry.who)
                .font(.system(size: 12, weight: .semibold, design: .monospaced))
                .foregroundStyle(Theme.textPrimary)
                .frame(width: 210, alignment: .leading)
                .textSelection(.enabled)
            VStack(alignment: .leading, spacing: 2) {
                ForEach(entry.access) { a in
                    Text(verbatim: ([a.ports, a.rule] + (a.through == entry.who ? [] : ["through " + a.through]) + a.notes)
                        .joined(separator: " · "))
                        .font(.system(size: 11))
                        .foregroundStyle(a.notes.contains { $0.hasPrefix("if ") } ? Theme.orange : Theme.textSecondary)
                }
            }
        }
        .padding(.vertical, 3)
    }

    private func export(_ entries: [ReachEntry]) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.commaSeparatedText]
        panel.nameFieldStringValue = "Who can reach \(target.replacingOccurrences(of: ":", with: " ")).csv"
        if panel.runModal() == .OK, let url = panel.url {
            try? whoCanReachCSV(target, entries).write(to: url, atomically: true, encoding: .utf8)
        }
    }
}
