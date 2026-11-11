import SwiftUI

/// The policy's custom relay (DERP) servers, with a live check of each:
/// DNS, HTTPS with the certificate, and STUN (Routes screen).
struct DERPPanel: View {
    var regions: [DERPRegion]
    @State private var results: [String: [DERPCheckStep]] = [:]   // node path → steps
    @State private var checking = false

    var body: some View {
        let nodes = regions.filter { !$0.removed }.flatMap { r in r.nodes.map { (r, $0) } }
        let removed = regions.filter(\.removed).map(\.key)
        ServerPanel {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Relay servers (DERP)")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundStyle(Theme.textPrimary)
                    Text("Your own relays from derpMap. The check runs from this Mac: DNS, HTTPS with the certificate, and STUN.")
                        .font(.system(size: 10.5))
                        .foregroundStyle(Theme.textSecondary)
                }
                Spacer()
                if checking { ProgressView().controlSize(.small) }
                Button("Check") { check(nodes.map(\.1)) }
                    .font(.system(size: 11))
                    .disabled(checking || nodes.isEmpty)
            }
            if !removed.isEmpty {
                Text(verbatim: "Tailscale region\(removed.count == 1 ? "" : "s") turned off: \(removed.joined(separator: ", "))")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.textSecondary)
            }
            ForEach(nodes, id: \.1.path) { region, node in
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Chip(text: "\(region.key) \(region.code)", color: Theme.purple, icon: "antenna.radiowaves.left.and.right")
                        Text(verbatim: node.hostName.isEmpty ? node.name : node.hostName)
                            .font(.system(size: 12, weight: .semibold, design: .monospaced))
                            .foregroundStyle(Theme.textPrimary)
                        Text(verbatim: details(node))
                            .font(.system(size: 10.5, design: .monospaced))
                            .foregroundStyle(Theme.textSecondary)
                        Spacer()
                    }
                    ForEach(results[node.path] ?? []) { step in
                        HStack(alignment: .top, spacing: 6) {
                            Image(systemName: step.ok ? "checkmark.circle.fill" : "xmark.octagon.fill")
                                .foregroundStyle(step.ok ? Theme.green : Theme.red)
                            Text(step.name).font(.system(size: 11, weight: .semibold)).frame(width: 46, alignment: .leading)
                            Text(step.detail).font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                                .fixedSize(horizontal: false, vertical: true)
                                .textSelection(.enabled)
                        }
                        .padding(.leading, 4)
                    }
                }
            }
        }
    }

    private func details(_ n: DERPNode) -> String {
        var parts: [String] = []
        if let ip = n.ipv4, !ip.isEmpty { parts.append("IPv4 \(ip)") }
        if let ip = n.ipv6, !ip.isEmpty { parts.append("IPv6 \(ip)") }
        if !n.stunOnly { parts.append("HTTPS \(n.httpsPort)") }
        parts.append(n.stunPortUsed.map { "STUN \($0)" } ?? "STUN off")
        return parts.joined(separator: " · ")
    }

    private func check(_ nodes: [DERPNode]) {
        checking = true
        results = [:]
        Task {
            await withTaskGroup(of: (String, [DERPCheckStep]).self) { group in
                for n in nodes { group.addTask { (n.path, await checkDERPNode(n)) } }
                for await (path, steps) in group { results[path] = steps }
            }
            checking = false
        }
    }
}
