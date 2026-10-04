import SwiftUI

/// Real traffic from Tailscale's network flow logs: who connects to what,
/// and which rules that traffic actually uses.
struct TrafficScreen: View {
    @EnvironmentObject var store: PolicyStore
    @State private var days = 7
    @State private var tab = Tab.connections
    @State private var filter = ""
    @State private var error: String?

    enum Tab: String, CaseIterable { case connections = "Connections", usage = "Rule usage" }

    private static let rowLimit = 300

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                header
                if let traffic = store.traffic {
                    Picker("", selection: $tab) {
                        ForEach(Tab.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .frame(width: 260)
                    if tab == .connections { connections(traffic) } else { usage(traffic) }
                } else if store.currentWorkspace.kind != .tailscale {
                    note("Network flow logs come from Tailscale. Headscale doesn't record traffic.")
                } else if store.serverClient() == nil {
                    note("Connect this workspace to Tailscale on the Server screen to load traffic.")
                } else {
                    note("Load the flow logs to see real connections. Flow logging must be on for the tailnet, and an OAuth client needs the logs:network:read scope.")
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .background(Theme.background)
        .onAppear(perform: takeFilterRequest)
        .onChange(of: store.trafficFilterRequest) { takeFilterRequest() }
    }

    private func takeFilterRequest() {
        guard let request = store.trafficFilterRequest else { return }
        filter = request
        tab = .connections
        store.trafficFilterRequest = nil
    }

    private var header: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 3) {
                Text("Traffic")
                    .font(.system(size: 16, weight: .bold))
                    .foregroundStyle(Theme.textPrimary)
                Text(store.traffic.map { t in
                    "\(t.connections.count) connection types between \(t.start.formatted(date: .abbreviated, time: .shortened)) and \(t.end.formatted(date: .abbreviated, time: .shortened)), from Tailscale's flow logs. Only successful connections are logged."
                } ?? "Real connections from Tailscale's network flow logs")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let error {
                    Text(error).font(.system(size: 11)).foregroundStyle(Theme.red).fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer()
            if let progress = store.trafficProgress {
                ProgressView().controlSize(.small)
                Text(progress).font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
            }
            Picker("", selection: $days) {
                Text("Last 24 hours").tag(1)
                Text("Last 7 days").tag(7)
                Text("Last 30 days").tag(30)
            }
            .labelsHidden()
            .frame(width: 140)
            ToolbarButton(label: store.traffic == nil ? "Load" : "Reload", icon: "arrow.down.circle") { load() }
                .disabled(store.trafficProgress != nil || store.serverClient() == nil
                          || store.currentWorkspace.kind != .tailscale)
        }
    }

    private func load() {
        error = nil
        Task {
            do {
                if store.headscaleNodes.isEmpty { try? await store.refreshNodes() }
                try await store.loadTraffic(days: days)
            } catch {
                self.error = (error as? ServerError).map { e in
                    e.status == 403 || e.status == 401
                        ? e.message + " — an OAuth client needs the logs:network:read scope."
                        : e.message
                } ?? error.localizedDescription
            }
        }
    }

    // MARK: Connections

    private func connections(_ traffic: TrafficSummary) -> some View {
        let byIP = nodesByAddress(store.headscaleNodes)
        let raw = filter.trimmingCharacters(in: .whitespaces)
        let q = raw.lowercased()
        let ev = store.evaluator
        // A policy name (group:x, tag:y, ipset:z, a user, a CIDR) matches by policy
        // semantics; anything else matches names, addresses, and ports as text.
        let isSelector = raw.contains(":") || raw.contains("@") || isAddressLike(raw)
        let rows = traffic.connections.filter { c in
            if q.isEmpty { return true }
            let ids = trafficIdentities(c.client, nodes: byIP) + trafficIdentities(c.server, nodes: byIP)
            if isSelector, ids.contains(where: { ev.sourceMatches(spec: raw, sourceID: $0) || ev.targetMatches(target: raw, destID: $0) }) {
                return true
            }
            return [c.client, c.server, String(c.port), trafficName(c.client, nodes: byIP), trafficName(c.server, nodes: byIP)]
                .contains { $0.lowercased().contains(q) }
        }
        return VStack(alignment: .leading, spacing: 6) {
            TextField("Filter by device, user, tag, IP, or port", text: $filter)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 360)
            Text(verbatim: rows.count > Self.rowLimit ? "Showing the busiest \(Self.rowLimit) of \(rows.count)." : "\(rows.count) shown.")
                .font(.system(size: 10.5))
                .foregroundStyle(Theme.textSecondary)
            ForEach(rows.prefix(Self.rowLimit)) { row($0, byIP) }
        }
    }

    private func row(_ c: TrafficConnection, _ byIP: [String: HeadscaleNode]) -> some View {
        let matches = rulesAllowing(c, store.model, nodes: byIP)
        let rules = ruleSummaries(store.model, sourceIDs: nil).filter { r in
            matches.contains { ($0.kind == .grant ? "grants" : "acls") == r.section && $0.ruleIndex == r.index }
        }
        return HStack(spacing: 8) {
            endpoint(c.client, byIP)
            Image(systemName: "arrow.right").font(.system(size: 9.5)).foregroundStyle(Theme.textSecondary)
            endpoint(c.server, byIP)
            Chip(text: c.proto == 1 || c.proto == 58 ? c.protoName : "\(c.protoName) \(c.port)", color: Theme.orange)
            if c.kind != .virtual {
                Text(c.kind == .subnet ? "subnet" : "exit node").font(.system(size: 10)).foregroundStyle(Theme.textSecondary)
            }
            Spacer()
            if !c.isPortTraffic {
                EmptyView()
            } else if rules.isEmpty {
                Text("no rule in the editor allows this")
                    .font(.system(size: 10.5, weight: .semibold))
                    .foregroundStyle(Theme.red)
                    .help("The server's policy allowed it, but the policy in the editor would block it")
            } else {
                Text(verbatim: rules.map(\.name).joined(separator: ", "))
                    .font(.system(size: 10.5))
                    .foregroundStyle(Theme.textSecondary)
                    .lineLimit(1)
                    .frame(maxWidth: 220, alignment: .trailing)
            }
            Text(verbatim: "\(c.connections)×  \(formatBytes(c.bytes))")
                .font(.system(size: 10.5, design: .monospaced))
                .foregroundStyle(Theme.textSecondary)
                .frame(width: 120, alignment: .trailing)
        }
        .padding(.vertical, 3)
        .padding(.horizontal, 8)
        .background(RoundedRectangle(cornerRadius: 6).fill(Theme.panel))
    }

    private func endpoint(_ ip: String, _ byIP: [String: HeadscaleNode]) -> some View {
        let name = trafficName(ip, nodes: byIP)
        let who = byIP[ip]?.policyName
        return VStack(alignment: .leading, spacing: 0) {
            Text(verbatim: name)
                .font(.system(size: 11.5, weight: .semibold, design: .monospaced))
                .foregroundStyle(Theme.textPrimary)
            if let who, who != name {
                Text(verbatim: who).font(.system(size: 9.5)).foregroundStyle(Theme.textSecondary)
            } else if byIP[ip] == nil {
                let sets = store.model.ipsetOrder.filter { store.evaluator.ipsetContains($0, ip: ip) }
                    + store.model.hostOrder.filter { cidrContains(cidr: store.model.hosts[$0] ?? "", ip: ip) }
                if !sets.isEmpty {
                    Text(verbatim: sets.prefix(2).joined(separator: ", ")).font(.system(size: 9.5)).foregroundStyle(Theme.textSecondary)
                }
            }
        }
        .textSelection(.enabled)
    }

    // MARK: Rule usage

    private func usage(_ traffic: TrafficSummary) -> some View {
        let used = ruleUsage(traffic.connections, store.model, nodes: store.headscaleNodes)
        let rules = ruleSummaries(store.model, sourceIDs: nil).filter { $0.kind != .ssh }
        let unused = rules.filter { used["\($0.kind == .grant ? RuleMatch.Kind.grant : .acl)-\($0.index)"] == nil }
        let period = store.traffic.map { Int(($0.end.timeIntervalSince($0.start) / 86_400).rounded()) } ?? days
        return VStack(alignment: .leading, spacing: 10) {
            Text(verbatim: unused.isEmpty ? "Every rule carried traffic in the last \(period) day\(period == 1 ? "" : "s")."
                 : "\(unused.count) rule\(unused.count == 1 ? "" : "s") carried no traffic in the last \(period) day\(period == 1 ? "" : "s")")
                .font(.system(size: 13, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            if !unused.isEmpty {
                Text("Candidates for removal — but check first: rarely used access (monthly jobs, break-glass accounts) may simply not have happened in this period, and logs only cover devices with flow logging.")
                    .font(.system(size: 10.5))
                    .foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(unused) { ruleLine($0, detail: "\($0.sources.joined(separator: ", ")) → \($0.destinations.joined(separator: ", ")) · \($0.badge)") }
            }
            Text("Ports used by each rule")
                .font(.system(size: 13, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
                .padding(.top, 6)
            ForEach(rules.filter { used["\($0.kind == .grant ? RuleMatch.Kind.grant : .acl)-\($0.index)"] != nil }) { r in
                let u = used["\(r.kind == .grant ? RuleMatch.Kind.grant : .acl)-\(r.index)"]!
                let ports = u.ports.sorted { $0.value > $1.value }
                VStack(alignment: .leading, spacing: 2) {
                    ruleLine(r, detail: "\(u.connections) connections · " + ports.prefix(8).map { "\($0.key) (\($0.value))" }.joined(separator: ", ")
                             + (ports.count > 8 ? ", …" : ""))
                    if broad(r), ports.count <= 6 {
                        Text(verbatim: "Allows \(r.badge.lowercased() == "all" ? "every port" : r.badge) but only used \(ports.map(\.key).sorted().joined(separator: ", ")) — narrow its ip to those?")
                            .font(.system(size: 10.5, weight: .semibold))
                            .foregroundStyle(Theme.orange)
                            .padding(.leading, 12)
                    }
                }
            }
        }
    }

    /// Wildcards or port ranges: worth narrowing if traffic uses few ports.
    private func broad(_ r: RuleSummary) -> Bool {
        r.badge == "All" || r.badge.contains("*") || r.badge.contains("-")
    }

    private func ruleLine(_ r: RuleSummary, detail: String) -> some View {
        HStack(spacing: 8) {
            Circle().fill(r.kind == .grant ? Theme.green : Theme.blue).frame(width: 6, height: 6)
            Text(verbatim: r.name)
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(Theme.textPrimary)
            if let line = store.tree?.line(at: "\(r.section)[\(r.index)]") {
                Button("Line " + String(line)) { store.editorLineRequest = line }
                    .buttonStyle(.link)
                    .font(.system(size: 10.5))
            }
            Text(verbatim: detail)
                .font(.system(size: 10.5, design: .monospaced))
                .foregroundStyle(Theme.textSecondary)
                .lineLimit(1)
            Spacer()
        }
    }

    private func note(_ text: String) -> some View {
        Label(text, systemImage: "info.circle")
            .font(.system(size: 12))
            .foregroundStyle(Theme.textSecondary)
            .fixedSize(horizontal: false, vertical: true)
    }
}
