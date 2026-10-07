import Foundation
import Network

// Custom relay (DERP) servers from the policy's "derpMap". Field meanings
// follow Tailscale's tailcfg: regions are keyed by their RegionID, IPv4/IPv6
// "none" turns that family off, DERPPort 0 means 443, STUNPort 0 means 3478
// and -1 turns STUN off. Keys are matched without case, like Tailscale does.

struct DERPNode {
    var name: String
    var regionID: Int?
    var hostName: String
    var ipv4: String?
    var ipv6: String?
    var derpPort: Int
    var stunPort: Int
    var stunOnly: Bool
    /// Lint path, e.g. "derpMap.regions[900].Nodes[0]".
    var path: String

    var httpsPort: Int { derpPort == 0 ? 443 : derpPort }
    var stunPortUsed: Int? { stunPort == -1 ? nil : stunPort == 0 ? 3478 : stunPort }
    /// The fixed IPv4 address, when one is given (not empty or "none").
    var fixedIPv4: String? { ipv4.flatMap { ipBytes($0)?.count == 4 ? $0 : nil } }
}

struct DERPRegion {
    var key: String
    /// nil when the region is set to null (removes a Tailscale region).
    var regionID: Int?
    var code: String
    var name: String
    var nodes: [DERPNode]
    var removed: Bool
    var path: String
}

/// Case-insensitive member lookup, returning the key as written.
private func member(_ json: JSON?, _ key: String) -> (key: String, value: JSON)? {
    json?.members?.first { $0.key.lowercased() == key.lowercased() }.map { ($0.key, $0.value) }
}

private func intValue(_ json: JSON?) -> Int? {
    if case .number(let d)? = json { return Int(exactly: d) }
    return nil
}

func parseDERPMap(_ tree: JSON) -> [DERPRegion] {
    guard let map = member(tree, "derpMap"), let regions = member(map.value, "regions"),
          let entries = regions.value.members else { return [] }
    let base = "\(map.key).\(regions.key)"
    return entries.map { entry in
        let path = "\(base)[\(entry.key)]"
        if case .null = entry.value {
            return DERPRegion(key: entry.key, regionID: Int(entry.key), code: "", name: "", nodes: [], removed: true, path: path)
        }
        let r = entry.value
        let nodesMember = member(r, "nodes")
        let nodes = (nodesMember?.value.elements ?? []).enumerated().map { i, e in
            let n = e.value
            func str(_ k: String) -> String? { member(n, k)?.value.stringValue }
            var stunOnly = false
            if case .bool(let b)? = member(n, "stunOnly")?.value { stunOnly = b }
            return DERPNode(name: str("name") ?? "", regionID: intValue(member(n, "regionID")?.value),
                            hostName: str("hostName") ?? "", ipv4: str("ipv4"), ipv6: str("ipv6"),
                            derpPort: intValue(member(n, "derpPort")?.value) ?? 0,
                            stunPort: intValue(member(n, "stunPort")?.value) ?? 0,
                            stunOnly: stunOnly, path: "\(path).\(nodesMember?.key ?? "Nodes")[\(i)]")
        }
        return DERPRegion(key: entry.key, regionID: intValue(member(r, "regionID")?.value),
                          code: member(r, "regionCode")?.value.stringValue ?? "",
                          name: member(r, "regionName")?.value.stringValue ?? "",
                          nodes: nodes, removed: false, path: path)
    }
}

/// Mistakes in "derpMap" that Tailscale accepts quietly or rejects on save.
func lintDERP(_ regions: [DERPRegion]) -> [LintIssue] {
    var issues: [LintIssue] = []
    func add(_ severity: LintIssue.Severity, _ title: String, _ detail: String, _ path: String) {
        issues.append(LintIssue(severity: severity, title: title, detail: detail, path: path))
    }
    for r in regions where !r.removed {
        let label = "DERP region \(r.key)"
        guard let id = r.regionID else {
            add(.error, "\(label) has no RegionID", "Each region needs a RegionID, the same number as its key.", r.path)
            continue
        }
        if String(id) != r.key {
            add(.error, "\(label) has RegionID \(id)", "Regions are keyed by their RegionID; the key and RegionID must be the same number.", r.path)
        }
        if !(900...999).contains(id) {
            add(.warning, "\(label) uses Tailscale's region ID", "IDs 900–999 are for your own regions; \(id) replaces Tailscale's region with that ID.", r.path)
        }
        if r.code.isEmpty {
            add(.warning, "\(label) has no RegionCode", "Give it a short code, e.g. \"myregion\"; clients show it in netcheck.", r.path)
        }
        if r.nodes.isEmpty {
            add(.error, "\(label) has no servers", "Add at least one entry to Nodes.", r.path)
        }
        for n in r.nodes {
            let name = n.name.isEmpty ? "a server" : n.name
            if n.hostName.isEmpty {
                add(.error, "DERP server \(name) has no HostName", "Clients connect to the HostName over HTTPS, and its TLS certificate must match it.", n.path)
            }
            if let nid = n.regionID, nid != id {
                add(.error, "DERP server \(name) is in the wrong region", "Its RegionID is \(nid), but it's listed in region \(id).", n.path)
            }
            for (family, value, size) in [("IPv4", n.ipv4, 4), ("IPv6", n.ipv6, 16)] {
                guard let value, !value.isEmpty, value.lowercased() != "none" else { continue }
                if ipBytes(value)?.count != size {
                    add(.warning, "DERP server \(name) has an invalid \(family)", "\"\(value)\" isn't an \(family) address, so \(family) isn't used. Use an address, or \"none\" to turn it off.", n.path)
                } else if !isPublicAddress(value) {
                    add(.warning, "DERP server \(name) has a private \(family)", "\(value) isn't reachable from the internet; DERP servers need a public address.", n.path)
                }
            }
            if !(0...65535).contains(n.derpPort) {
                add(.error, "DERP server \(name) has an invalid DERPPort", "\(n.derpPort) isn't a port (0 means 443).", n.path)
            }
            if !(-1...65535).contains(n.stunPort) {
                add(.error, "DERP server \(name) has an invalid STUNPort", "\(n.stunPort) isn't a port (0 means 3478, -1 turns STUN off).", n.path)
            }
        }
    }
    return issues
}

// MARK: - Live check

struct DERPCheckStep: Identifiable {
    var name: String
    var ok: Bool
    var detail: String
    var id: String { name }
}

/// DNS, HTTPS (/derp/probe, which also checks the certificate) and STUN.
func checkDERPNode(_ n: DERPNode) async -> [DERPCheckStep] {
    var steps: [DERPCheckStep] = []
    let resolved = await resolveIPv4(n.hostName)
    if resolved.isEmpty {
        steps.append(.init(name: "DNS", ok: n.fixedIPv4 != nil,
                           detail: n.fixedIPv4 == nil ? "\(n.hostName) doesn't resolve." : "\(n.hostName) doesn't resolve; clients use \(n.fixedIPv4!) from the policy."))
    } else if let fixed = n.fixedIPv4, !resolved.contains(fixed) {
        steps.append(.init(name: "DNS", ok: false,
                           detail: "\(n.hostName) resolves to \(resolved.joined(separator: ", ")), but the policy says \(fixed)."))
    } else {
        steps.append(.init(name: "DNS", ok: true, detail: "\(n.hostName) → \(resolved.joined(separator: ", "))"))
    }

    if !n.stunOnly {
        let url = URL(string: "https://\(n.hostName)\(n.httpsPort == 443 ? "" : ":\(n.httpsPort)")/derp/probe")
        var req = url.map { URLRequest(url: $0, timeoutInterval: 8) }
        req?.httpMethod = "GET"
        do {
            guard let req else { throw URLError(.badURL) }
            let (_, response) = try await URLSession(configuration: .ephemeral).data(for: req)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            steps.append(.init(name: "HTTPS", ok: status == 200,
                               detail: status == 200 ? "DERP answers on port \(n.httpsPort), certificate valid." : "Port \(n.httpsPort) answered HTTP \(status), not a DERP server."))
        } catch {
            steps.append(.init(name: "HTTPS", ok: false, detail: "Port \(n.httpsPort): \(error.localizedDescription)"))
        }
    }

    if let port = n.stunPortUsed {
        let host = n.fixedIPv4 ?? n.hostName
        let ok = await stunProbe(host: host, port: port)
        steps.append(.init(name: "STUN", ok: ok,
                           detail: ok ? "UDP \(port) answers." : "No STUN answer on UDP \(port) within 3 s (blocked by a firewall?)."))
    }
    return steps
}

private func resolveIPv4(_ host: String) async -> [String] {
    await Task.detached {
        var hints = addrinfo(ai_flags: 0, ai_family: AF_INET, ai_socktype: SOCK_STREAM, ai_protocol: 0,
                             ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var result: UnsafeMutablePointer<addrinfo>?
        guard !host.isEmpty, getaddrinfo(host, nil, &hints, &result) == 0 else { return [String]() }
        defer { freeaddrinfo(result) }
        var out: [String] = []
        var p = result
        while let info = p {
            if let addr = info.pointee.ai_addr {
                var sin = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                inet_ntop(AF_INET, &sin.sin_addr, &buf, socklen_t(INET_ADDRSTRLEN))
                out.append(String(cString: buf))
            }
            p = info.pointee.ai_next
        }
        return out.uniqued()
    }.value
}

/// A STUN binding request (RFC 5389) the way Tailscale sends it: DERP
/// servers ignore requests without SOFTWARE "tailnode" and a FINGERPRINT.
func stunBindingRequest(transactionID: [UInt8]) -> Data {
    var b: [UInt8] = [0x00, 0x01, 0x00, 20, 0x21, 0x12, 0xA4, 0x42] + transactionID
    b += [0x80, 0x22, 0x00, 0x08] + Array("tailnode".utf8)
    let fp = crc32(b) ^ 0x5354_554E
    b += [0x80, 0x28, 0x00, 0x04, UInt8(fp >> 24), UInt8(fp >> 16 & 0xFF), UInt8(fp >> 8 & 0xFF), UInt8(fp & 0xFF)]
    return Data(b)
}

/// CRC-32 (IEEE), as STUN fingerprints use.
func crc32(_ bytes: [UInt8]) -> UInt32 {
    var crc: UInt32 = 0xFFFF_FFFF
    for byte in bytes {
        crc ^= UInt32(byte)
        for _ in 0..<8 { crc = crc & 1 == 1 ? (crc >> 1) ^ 0xEDB8_8320 : crc >> 1 }
    }
    return ~crc
}

/// A binding success response (0x0101) to our transaction.
func isSTUNBindingSuccess(_ data: Data, transactionID: [UInt8]) -> Bool {
    let b = [UInt8](data)
    return b.count >= 20 && b[0] == 0x01 && b[1] == 0x01
        && b[4...7].elementsEqual([0x21, 0x12, 0xA4, 0x42]) && b[8..<20].elementsEqual(transactionID)
}

private func stunProbe(host: String, port: Int) async -> Bool {
    guard let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else { return false }
    let txID = (0..<12).map { _ in UInt8.random(in: 0...255) }
    let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .udp)
    let queue = DispatchQueue(label: "stun-probe")
    return await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
        var done = false
        func finish(_ ok: Bool) {   // always on `queue`
            guard !done else { return }
            done = true
            conn.cancel()
            cont.resume(returning: ok)
        }
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                conn.send(content: stunBindingRequest(transactionID: txID), completion: .contentProcessed { _ in })
                conn.receiveMessage { data, _, _, _ in
                    finish(data.map { isSTUNBindingSuccess($0, transactionID: txID) } ?? false)
                }
            case .failed, .cancelled:
                finish(false)
            default: break
            }
        }
        conn.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 3) { finish(false) }
    }
}
