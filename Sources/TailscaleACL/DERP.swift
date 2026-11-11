import Foundation

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
