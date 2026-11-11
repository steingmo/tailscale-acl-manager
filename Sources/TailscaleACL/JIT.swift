import SwiftUI

// Just-in-time access, the way Tailscale does it: a posture that is one
// custom device attribute being set, rules that require that posture, and
// the attribute put on a device with an expiry — Tailscale removes it then,
// and the access with it. Nothing is pushed and nothing has to be running
// when the time is up. Headscale has no posture attributes, so no JIT.

/// Letters, numbers, underscores, and colons after "custom:", 128 at most.
func isCustomAttributeKey(_ key: String) -> Bool {
    key.hasPrefix("custom:") && key.count > 7 && key.count <= 128
        && key.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "_" || $0 == ":") }
}

/// A posture that holds exactly while one custom attribute has one value,
/// e.g. "posture:jit-prod": ["custom:jitProd == true"].
struct JITPosture: Identifiable, Equatable {
    var name: String
    var key: String
    var value: PostureValue
    var id: String { name }
    /// "jit-prod" for "posture:jit-prod".
    var shortName: String { name.hasPrefix("posture:") ? String(name.dropFirst(8)) : name }
}

/// The policy's JIT postures, in policy order. A posture with further
/// conditions isn't one: setting the attribute alone wouldn't grant it.
func jitPostures(_ m: PolicyModel) -> [JITPosture] {
    m.postureOrder.compactMap { name in
        guard let conditions = m.postures[name], conditions.count == 1, let c = PostureCondition(conditions[0]),
              c.op == "==", isCustomAttributeKey(c.attribute),
              let operand = conditions[0].range(of: "==").map({ String(conditions[0][$0.upperBound...]) }) else { return nil }
        return JITPosture(name: name, key: c.attribute, value: PostureValue(operand: operand))
    }
}

/// What a JIT posture unlocks: one sentence per rule that requires it.
func jitUnlocks(_ m: PolicyModel, _ posture: JITPosture) -> [String] {
    func requires(_ own: [String]) -> Bool { (own.isEmpty ? m.defaultSrcPosture : own).contains(posture.name) }
    return m.grants.filter { requires($0.srcPosture) }.compactMap { ruleExplanation(m, kind: .grant, index: $0.index) }
        + m.rules.filter { requires($0.srcPosture) }.compactMap { ruleExplanation(m, kind: .acl, index: $0.index) }
}

/// Temporary access a device holds right now.
struct JITGrant: Identifiable {
    var node: HeadscaleNode
    var posture: JITPosture
    /// nil: the attribute was set without an expiry, so it stays until removed.
    var expires: Date?
    var id: String { node.id + posture.name }
}

func activeJIT(_ nodes: [HeadscaleNode], _ postures: [JITPosture], now: Date = Date()) -> [JITGrant] {
    nodes.flatMap { node in
        postures.compactMap { posture -> JITGrant? in
            guard node.attributes?[posture.key] == posture.value.text else { return nil }
            let expires = node.attributeExpiries?[posture.key].flatMap { ISO8601DateFormatter().date(from: $0) }
            // Tailscale removes it within minutes of the expiry; until the next refresh it may still be listed.
            if let expires, expires <= now { return nil }
            return JITGrant(node: node, posture: posture, expires: expires)
        }
    }
    .sorted { ($0.expires ?? .distantFuture) < ($1.expires ?? .distantFuture) }
}

/// "2 h 5 min", "45 min", "3 days".
func jitTimeLeft(_ expires: Date, now: Date = Date()) -> String {
    let minutes = max(Int(expires.timeIntervalSince(now) / 60), 0)
    if minutes >= 2 * 1_440 { return "\(minutes / 1_440) days" }
    if minutes >= 60 { return "\(minutes / 60) h" + (minutes % 60 > 0 ? " \(minutes % 60) min" : "") }
    return "\(minutes) min"
}

extension PolicyStore {
    /// Sets the posture's attribute on the device until `until`; the server
    /// removes it then. The device's attributes are updated from the answer.
    func grantJIT(_ posture: JITPosture, to node: HeadscaleNode, until: Date, reason: String) async throws {
        guard let client = serverClient() else { return }
        let workspace = currentWorkspaceID
        let result = try await client.setPostureAttribute(nodeID: node.id, key: posture.key, value: posture.value,
                                                          expiry: until, comment: reason)
        applyPosture(result, to: node.id, in: workspace)
    }

    func revokeJIT(_ posture: JITPosture, from node: HeadscaleNode) async throws {
        guard let client = serverClient() else { return }
        let workspace = currentWorkspaceID
        try await client.removePostureAttribute(nodeID: node.id, key: posture.key)
        var left = DevicePosture(attributes: node.attributes ?? [:], expiries: node.attributeExpiries ?? [:])
        left.attributes[posture.key] = nil
        left.expiries[posture.key] = nil
        applyPosture(left, to: node.id, in: workspace)
    }

    private func applyPosture(_ posture: DevicePosture, to nodeID: String, in workspace: UUID) {
        guard workspace == currentWorkspaceID, let i = headscaleNodes.firstIndex(where: { $0.id == nodeID }) else { return }
        headscaleNodes[i].attributes = posture.attributes
        headscaleNodes[i].attributeExpiries = posture.expiries
        saveServerCache()
    }
}

// MARK: - Server screen panel

/// Who holds temporary access now, and the way to give or end it.
struct JITPanel: View {
    @EnvironmentObject var store: PolicyStore
    @State private var granting = false
    @State private var showingTemplates = false
    @State private var error: String?
    @State private var busy: String?

    var body: some View {
        let postures = jitPostures(store.model)
        let grants = activeJIT(store.headscaleNodes, postures)
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Temporary access")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(Theme.textPrimary)
                Spacer()
                if !postures.isEmpty {
                    ToolbarButton(label: "Grant access…", icon: "clock.badge.checkmark") { granting = true }
                        .disabled(store.headscaleNodes.isEmpty)
                }
            }
            Text("Just-in-time access: a device gets what a rule allows only for a few hours, and Tailscale takes it away again by itself.")
                .font(.system(size: 11))
                .foregroundStyle(Theme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            if postures.isEmpty {
                HStack(spacing: 8) {
                    Text("The policy has no rule that can be unlocked temporarily yet.")
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.textSecondary)
                    Button("Set up…") { showingTemplates = true }
                        .font(.system(size: 11))
                        .help("The “Just-in-time access” template adds a posture and requires it for the destinations you name")
                }
            } else if grants.isEmpty {
                Text("Nobody holds temporary access right now.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.textSecondary)
            }
            ForEach(grants) { grant in
                HStack(spacing: 8) {
                    Image(systemName: "clock").foregroundStyle(Theme.orange).font(.system(size: 11))
                    Text(verbatim: grant.node.displayName)
                        .font(.system(size: 12, weight: .semibold, design: .monospaced))
                        .foregroundStyle(Theme.textPrimary)
                    Chip(text: grant.posture.shortName, color: Theme.orange)
                    Text(verbatim: grant.expires.map {
                        "until \($0.formatted(date: .omitted, time: .shortened)) (\(jitTimeLeft($0)) left)"
                    } ?? "no expiry — stays until ended")
                        .font(.system(size: 11))
                        .foregroundStyle(grant.expires == nil ? Theme.red : Theme.textSecondary)
                    Spacer()
                    Button("End now") { end(grant) }
                        .font(.system(size: 11))
                        .disabled(busy != nil)
                }
            }
            if let error {
                Text(verbatim: error).font(.system(size: 11)).foregroundStyle(Theme.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 9).fill(Theme.panel))
        .overlay(RoundedRectangle(cornerRadius: 9).stroke(Theme.panelBorder, lineWidth: 1))
        .sheet(isPresented: $granting) { JITSheet() }
        .sheet(isPresented: $showingTemplates) { TemplatesSheet(initial: "jit") }
    }

    private func end(_ grant: JITGrant) {
        busy = grant.id
        error = nil
        Task {
            do { try await store.revokeJIT(grant.posture, from: grant.node) } catch { self.error = error.localizedDescription }
            busy = nil
        }
    }
}

// MARK: - Grant sheet

/// Give one device what a JIT posture unlocks, for a while.
struct JITSheet: View {
    var device: HeadscaleNode?
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var nodeID = ""
    @State private var postureName = ""
    @State private var hours = 4.0
    @State private var reason = ""
    @State private var working = false
    @State private var error: String?

    private static let durations: [(label: String, hours: Double)] = [
        ("30 minutes", 0.5), ("1 hour", 1), ("4 hours", 4), ("8 hours", 8), ("1 day", 24), ("1 week", 168),
    ]

    var body: some View {
        let postures = jitPostures(store.model)
        let posture = postures.first { $0.name == postureName }
        let node = store.headscaleNodes.first { $0.id == nodeID }
        let until = Date().addingTimeInterval(hours * 3_600)
        VStack(alignment: .leading, spacing: 12) {
            Text("Grant temporary access")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            Form {
                Picker("Device", selection: $nodeID) {
                    ForEach(store.headscaleNodes.sorted { $0.displayName < $1.displayName }) { n in
                        Text(verbatim: n.displayName + (n.user?.name.map { " (\($0))" } ?? "")).tag(n.id)
                    }
                }
                Picker("Access", selection: $postureName) {
                    ForEach(postures) { Text(verbatim: $0.shortName).tag($0.name) }
                }
                Picker("For", selection: $hours) {
                    ForEach(Self.durations, id: \.hours) { Text($0.label).tag($0.hours) }
                }
                TextField("Reason", text: $reason, prompt: Text("Ticket or why — goes to Tailscale's audit log"))
            }
            if let posture {
                let unlocks = jitUnlocks(store.model, posture)
                VStack(alignment: .leading, spacing: 4) {
                    Text(unlocks.isEmpty ? "No rule requires \(posture.name) yet, so this unlocks nothing."
                         : "While \(posture.key) is set on the device:")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(unlocks.isEmpty ? Theme.orange : Theme.textSecondary)
                    ForEach(unlocks, id: \.self) {
                        Text(verbatim: $0).font(.system(size: 11.5)).foregroundStyle(Theme.textPrimary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Text("The rules still decide who: this device only gains what its user or tags already match.")
                        .font(.system(size: 10.5))
                        .foregroundStyle(Theme.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 7).fill(Theme.panel))
            }
            if let error {
                Text(verbatim: error).font(.system(size: 11)).foregroundStyle(Theme.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                if working { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Grant until \(until.formatted(date: hours >= 24 ? .abbreviated : .omitted, time: .shortened))") {
                    guard let posture, let node else { return }
                    // From now, not from when the sheet was drawn.
                    grant(posture, node, Date().addingTimeInterval(hours * 3_600))
                }
                .keyboardShortcut(.defaultAction)
                .disabled(posture == nil || node == nil || working)
            }
        }
        .padding(20)
        .frame(width: 520)
        .background(Theme.background)
        .onAppear {
            nodeID = device?.id ?? store.headscaleNodes.sorted { $0.displayName < $1.displayName }.first?.id ?? ""
            postureName = postures.first?.name ?? ""
        }
    }

    private func grant(_ posture: JITPosture, _ node: HeadscaleNode, _ until: Date) {
        working = true
        error = nil
        Task {
            do {
                try await store.grantJIT(posture, to: node, until: until, reason: reason.trimmingCharacters(in: .whitespaces))
                dismiss()
            } catch let failure as ServerError where failure.status == 403 || failure.status == 401 {
                error = "Tailscale refused: the API key or OAuth client needs the devices:posture_attributes scope."
            } catch {
                self.error = error.localizedDescription
            }
            working = false
        }
    }
}
