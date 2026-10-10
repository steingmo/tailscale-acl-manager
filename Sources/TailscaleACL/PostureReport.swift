import SwiftUI
import AppKit
import UniformTypeIdentifiers

/// One device checked against a posture, for rolling it out.
struct PostureCheck: Identifiable {
    enum Status { case fails, unknown, passes }
    var device: HeadscaleNode
    var owner: String
    var status: Status
    /// Why it fails, each with what to do about it.
    var reasons: [String]
    var id: String { device.id }
}

/// Devices the posture applies to: sources of rules that require it (or of
/// rules without their own srcPosture when defaultSrcPosture does). nil when
/// no rule requires it yet — then every person's device is checked.
func postureScope(_ m: PolicyModel, posture: String, nodes: [HeadscaleNode]) -> [HeadscaleNode]? {
    var sources: [[String]] = []
    for r in m.rules where r.action == "accept" && (r.srcPosture.isEmpty ? m.defaultSrcPosture : r.srcPosture).contains(posture) {
        sources.append(r.src)
    }
    for g in m.grants where (g.srcPosture.isEmpty ? m.defaultSrcPosture : g.srcPosture).contains(posture) {
        sources.append(g.src)
    }
    guard !sources.isEmpty else { return nil }
    let ev = Evaluator(model: m)
    let specs = sources.flatMap { $0 }
    return nodes.filter { n in specs.contains { spec in n.identities.contains { ev.sourceMatches(spec: spec, sourceID: $0) } } }
}

/// What a person can do about a failing condition, for known attributes.
private func postureHint(_ attribute: String, _ value: String?) -> String? {
    switch (attribute, value) {
    case (let a, nil) where a.hasPrefix("huntress:"):
        return "Install or repair the Huntress agent — the device isn't matched in Huntress (check that Device Identity Collection is on)."
    case ("huntress:firewallStatus", "Disabled"): return "Turn on the firewall."
    case ("huntress:firewallStatus", _): return "Huntress has isolated this device — contact IT."
    case ("huntress:defenderStatus", "Unhealthy"): return "Open Windows Security and fix Microsoft Defender."
    case ("huntress:defenderStatus", "Unmanaged"): return "Microsoft Defender isn't managed by Huntress — ask IT to enroll it."
    case ("huntress:defenderPolicyStatus", _): return "Defender's policy isn't applied yet — restart the device, or ask IT."
    case ("node:tsVersion", _): return "Update Tailscale."
    case ("node:os", _): return "This kind of device isn't allowed for this access."
    default: return nil
    }
}

/// The posture checked on every device in scope (or every person's device).
func postureReport(_ m: PolicyModel, posture: String, nodes: [HeadscaleNode], allPeople: Bool = false) -> [PostureCheck] {
    let conditions = m.postures[posture] ?? []
    let scoped = allPeople ? nil : postureScope(m, posture: posture, nodes: nodes)
    let devices = scoped ?? nodes.filter { $0.allTags.isEmpty }
    let order: [PostureCheck.Status: Int] = [.fails: 0, .unknown: 1, .passes: 2]
    return devices.map { node in
        let owner = node.allTags.isEmpty ? (node.user?.email ?? node.user?.name ?? "unknown") : node.allTags.joined(separator: ", ")
        guard node.attributes != nil else {
            return PostureCheck(device: node, owner: owner, status: .unknown, reasons: ["Posture attributes aren't loaded for this device."])
        }
        let attrs = node.postureAttributes
        var reasons: [String] = []
        var notInHuntress: [String] = []   // one reason for all of them
        for text in conditions {
            guard let c = PostureCondition(text) else { reasons.append("\"\(text)\" isn't a valid condition."); continue }
            guard c.evaluate(attrs, complete: true) == false else { continue }
            let value = attrs[c.attribute]
            if value == nil, c.attribute.hasPrefix("huntress:") { notInHuntress.append(c.attribute); continue }
            let fact = value.map { "\(c.attribute) is \($0), needs \(c.op) \(c.values.joined(separator: ", "))" } ?? "\(c.attribute) isn't set"
            reasons.append(postureHint(c.attribute, value).map { "\($0) (\(fact))" } ?? fact)
        }
        if !notInHuntress.isEmpty {
            let fact = notInHuntress.joined(separator: ", ") + (notInHuntress.count == 1 ? " isn't set" : " aren't set")
            reasons.insert("\(postureHint(notInHuntress[0], nil)!) (\(fact))", at: 0)
        }
        return PostureCheck(device: node, owner: owner, status: reasons.isEmpty ? .passes : .fails, reasons: reasons)
    }
    .sorted { (order[$0.status]!, $0.owner, $0.device.displayName) < (order[$1.status]!, $1.owner, $1.device.displayName) }
}

func postureReportCSV(_ checks: [PostureCheck]) -> String {
    func field(_ s: String) -> String { "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\"" }
    let rows = checks.map { c in
        [c.device.displayName, c.owner, c.device.os ?? "", "\(c.status)", c.reasons.joined(separator: "; ")].map(field).joined(separator: ",")
    }
    return (["device,owner,os,status,reasons"] + rows).joined(separator: "\n") + "\n"
}

/// One ready-to-send note per person whose devices fail, in Markdown.
func postureNotes(_ checks: [PostureCheck], posture: String) -> String {
    let failing = Dictionary(grouping: checks.filter { $0.status == .fails && $0.device.allTags.isEmpty }, by: \.owner)
    var out = ["# Device check: \(posture)", ""]
    for owner in failing.keys.sorted() {
        out += ["## \(owner)", "",
                "Hi — soon your device needs to pass the company's security check to keep its access through Tailscale. "
                + "Today it doesn't. Please fix the following, or contact IT:", ""]
        for c in failing[owner]! {
            out.append("- **\(c.device.displayName)**: " + c.reasons.joined(separator: " "))
        }
        out.append("")
    }
    if failing.isEmpty { out.append("Every person's device passes.") }
    return out.joined(separator: "\n") + "\n"
}

/// Rolling out a posture: who would fail it, why, and what they can do (Devices).
struct PostureReportSheet: View {
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State var posture: String
    @State private var allPeople = false

    var body: some View {
        let m = store.model
        let scoped = postureScope(m, posture: posture, nodes: store.headscaleNodes) != nil
        let checks = postureReport(m, posture: posture, nodes: store.headscaleNodes, allPeople: allPeople)
        let count = { (s: PostureCheck.Status) in checks.filter { $0.status == s }.count }
        VStack(alignment: .leading, spacing: 10) {
            Text("Posture rollout").font(.system(size: 16, weight: .bold))
            HStack {
                Picker("", selection: $posture) {
                    ForEach(m.postureOrder, id: \.self) { Text($0).tag($0) }
                }
                .labelsHidden()
                .frame(width: 260)
                if scoped {
                    Toggle("All people's devices", isOn: $allPeople).font(.system(size: 11.5))
                }
                Spacer()
            }
            Text(verbatim: (m.postures[posture] ?? []).joined(separator: "  ·  "))
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(Theme.textSecondary)
            Text(verbatim: (scoped && !allPeople ? "Devices that rules requiring \(posture) apply to" : "Every person's device (no rule requires \(posture) yet)")
                 + ": \(count(.fails)) fail, \(count(.unknown)) unknown, \(count(.passes)) pass.")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(count(.fails) > 0 ? Theme.orange : Theme.green)
            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(checks) { row($0) }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(minHeight: 260)
            HStack {
                Text("Fix the failing devices first, then require the posture; the push review shows who'd still lose access.")
                    .font(.system(size: 10.5))
                    .foregroundStyle(Theme.textSecondary)
                Spacer()
                Button("Export CSV…") { save(postureReportCSV(checks), "csv", .commaSeparatedText) }
                Button("Export notes…") { save(postureNotes(checks, posture: posture), "md", UTType(filenameExtension: "md") ?? .plainText) }
                    .disabled(count(.fails) == 0)
                    .help("A message per person: which device fails and what to do")
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 760, height: 580)
        .background(Theme.background)
    }

    private func row(_ c: PostureCheck) -> some View {
        let color = c.status == .passes ? Theme.green : c.status == .fails ? Theme.red : Theme.textSecondary
        return HStack(alignment: .top, spacing: 8) {
            Image(systemName: c.status == .passes ? "checkmark.circle.fill" : c.status == .fails ? "xmark.octagon.fill" : "questionmark.circle")
                .foregroundStyle(color)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(verbatim: c.device.displayName).font(.system(size: 12, weight: .semibold, design: .monospaced))
                    Text(verbatim: c.owner).font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                    if let os = c.device.os { Text(verbatim: os).font(.system(size: 10.5)).foregroundStyle(Theme.textSecondary) }
                }
                if c.status != .passes {
                    ForEach(c.reasons, id: \.self) {
                        Text($0).font(.system(size: 11)).foregroundStyle(c.status == .fails ? Theme.orange : Theme.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
    }

    private func save(_ text: String, _ ext: String, _ type: UTType) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [type]
        panel.nameFieldStringValue = "\(posture.replacingOccurrences(of: ":", with: " ")) rollout.\(ext)"
        if panel.runModal() == .OK, let url = panel.url { try? text.write(to: url, atomically: true, encoding: .utf8) }
    }
}
