import Foundation

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
