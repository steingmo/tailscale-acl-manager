import Foundation

// MARK: - Flow log records

/// One ConnectionCounts entry from Tailscale's network flow logs. Each
/// device logs its own view: its address is `src`, and both ends of a
/// connection log it. Only successful connections are logged.
struct FlowRecord: Decodable {
    enum Kind: String { case virtual, subnet, exit }

    var kind: Kind = .virtual
    var proto: Int
    var src: String
    var dst: String
    var txBytes: Int
    var rxBytes: Int
    var end: Date?

    private enum CodingKeys: String, CodingKey { case proto, src, dst, txBytes, rxBytes }

    init(kind: Kind, proto: Int, src: String, dst: String, txBytes: Int = 0, rxBytes: Int = 0, end: Date? = nil) {
        (self.kind, self.proto, self.src, self.dst, self.txBytes, self.rxBytes, self.end) = (kind, proto, src, dst, txBytes, rxBytes, end)
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        // proto is an IANA number; tolerate a string too.
        proto = (try? c.decode(Int.self, forKey: .proto))
            ?? (try? c.decode(String.self, forKey: .proto)).flatMap { ["tcp": 6, "udp": 17, "icmp": 1][$0.lowercased()] ?? Int($0) } ?? 0
        src = try c.decodeIfPresent(String.self, forKey: .src) ?? ""
        dst = try c.decodeIfPresent(String.self, forKey: .dst) ?? ""
        txBytes = try c.decodeIfPresent(Int.self, forKey: .txBytes) ?? 0
        rxBytes = try c.decodeIfPresent(Int.self, forKey: .rxBytes) ?? 0
    }
}

/// "100.64.0.1:443" or "[fd7a::1]:443" → (address, port).
func splitHostPort(_ s: String) -> (ip: String, port: Int)? {
    if s.hasPrefix("["), let close = s.range(of: "]:") {
        return Int(s[close.upperBound...]).map { (String(s[s.index(after: s.startIndex)..<close.lowerBound]), $0) }
    }
    guard let colon = s.lastIndex(of: ":"), let port = Int(s[s.index(after: colon)...]) else { return nil }
    return (String(s[..<colon]), port)
}

// MARK: - Connections

/// Who connected to what: one row per client → server:port, with the
/// server being the side on the lower port (the service).
struct TrafficConnection: Identifiable, Hashable {
    var client: String
    var server: String
    var port: Int
    var proto: Int
    var kind: FlowRecord.Kind
    /// Distinct client ports seen — roughly the number of connections.
    var connections = 0
    var bytes = 0
    var lastSeen: Date?

    var id: String { "\(client)>\(server):\(port)/\(proto)/\(kind.rawValue)" }
    var protoName: String { [6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"][proto] ?? "proto \(proto)" }
    /// The port in grant ip syntax, e.g. "tcp:443".
    var ipSpec: String { "\(proto == 17 ? "udp" : "tcp"):\(port)" }
    /// TCP or UDP: the kinds of traffic port-based rules decide.
    var isPortTraffic: Bool { proto == 6 || proto == 17 }
}

/// Builds connections from flow records, across fetched chunks.
struct TrafficAccumulator {
    private var rows: [String: TrafficConnection] = [:]
    private var clientPorts: [String: Set<Int>] = [:]

    var connections: [TrafficConnection] {
        rows.values.sorted { ($0.connections, $0.bytes) > ($1.connections, $1.bytes) }
    }

    mutating func add(_ records: [FlowRecord]) {
        for r in records {
            guard let a = splitHostPort(r.src), let b = splitHostPort(r.dst) else { continue }
            // The service listens on the lower port; ICMP has none (0 = 0).
            let logIsClient = a.port >= b.port
            let (client, server) = logIsClient ? (a, b) : (b, a)
            var row = TrafficConnection(client: client.ip, server: server.ip, port: server.port, proto: r.proto, kind: r.kind)
            let key = row.id
            if let existing = rows[key] { row = existing }
            clientPorts[key, default: []].insert(client.port)
            row.connections = clientPorts[key]?.count ?? 0
            // Both ends log a connection; count bytes from the client's records only.
            if logIsClient { row.bytes += r.txBytes + r.rxBytes }
            if let end = r.end, end > (row.lastSeen ?? .distantPast) { row.lastSeen = end }
            rows[key] = row
        }
    }
}

/// Network traffic loaded for the current workspace.
struct TrafficSummary {
    var start: Date
    var end: Date
    var connections: [TrafficConnection]
}

// MARK: - Analysis

/// How the policy names an address: a device's identities, or the address
/// itself (subnet and internet hosts).
func trafficIdentities(_ ip: String, nodes: [String: HeadscaleNode]) -> [String] {
    nodes[ip]?.identities ?? [ip]
}

func nodesByAddress(_ nodes: [HeadscaleNode]) -> [String: HeadscaleNode] {
    var out: [String: HeadscaleNode] = [:]
    for n in nodes { for ip in n.ipAddresses ?? [] { out[ip] = n } }
    return out
}

/// The rules (as summaries) that allow a connection under `m`.
func rulesAllowing(_ c: TrafficConnection, _ m: PolicyModel, nodes: [String: HeadscaleNode]) -> [RuleMatch] {
    guard c.isPortTraffic else { return [] }
    return Evaluator(model: m, proto: c.proto).evaluate(sourceIDs: trafficIdentities(c.client, nodes: nodes),
                                        destIDs: trafficIdentities(c.server, nodes: nodes), port: c.port).matches
}

/// Per rule: how much traffic it carried and on which ports.
struct RuleUsage: Identifiable {
    var kind: RuleMatch.Kind
    var index: Int
    var connections = 0
    /// "tcp:443" → connections, in grant ip syntax.
    var ports: [String: Int] = [:]
    var id: String { "\(kind)-\(index)" }
    var section: String { kind == .grant ? "grants" : "acls" }
}

/// Which grants and ACLs real traffic used. Rules with no entry carried
/// nothing in the period. A connection allowed by several rules counts for
/// each, since any of them would keep it working.
func ruleUsage(_ traffic: [TrafficConnection], _ m: PolicyModel, nodes: [HeadscaleNode]) -> [String: RuleUsage] {
    let byIP = nodesByAddress(nodes)
    var usage: [String: RuleUsage] = [:]
    for c in traffic {
        var counted = Set<String>()
        for match in rulesAllowing(c, m, nodes: byIP) {
            // A rule can match one connection through several src/dst pairs.
            let key = "\(match.kind)-\(match.ruleIndex)"
            guard counted.insert(key).inserted else { continue }
            var u = usage[key] ?? RuleUsage(kind: match.kind, index: match.ruleIndex)
            u.connections += c.connections
            u.ports[c.ipSpec, default: 0] += c.connections
            usage[key] = u
        }
    }
    return usage
}

/// Real connections the old policy allowed that the new one would block —
/// what a push would break.
func trafficBlocked(by new: PolicyModel, was old: PolicyModel, traffic: [TrafficConnection],
                    nodes: [HeadscaleNode]) -> [TrafficConnection] {
    let byIP = nodesByAddress(nodes)
    return traffic.filter { c in
        c.isPortTraffic && !rulesAllowing(c, old, nodes: byIP).isEmpty && rulesAllowing(c, new, nodes: byIP).isEmpty
    }
}

/// "amy-laptop" for a device address, the address otherwise.
func trafficName(_ ip: String, nodes: [String: HeadscaleNode]) -> String {
    nodes[ip]?.displayName ?? ip
}

func formatBytes(_ n: Int) -> String {
    ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .binary)
}
