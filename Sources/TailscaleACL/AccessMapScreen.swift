import SwiftUI
import AppKit

/// Focused map in the style of NetBird's control center: pick one device,
/// user, group, or tag and see every rule that applies to it fanning out to
/// what it can reach.
struct AccessMapScreen: View {
    @EnvironmentObject var store: PolicyStore
    /// The IP set card under the pointer, whose addresses are shown.
    @State private var hoveredSet: String?
    @State private var kind: Kind = .group
    @State private var selection = ""
    @State private var picking = false
    @State private var editing: RuleSummary?
    @State private var adding = false
    @State private var direction: Direction = .reaches
    @State private var editingTags: HeadscaleNode?
    @State private var showingTemplates = false

    enum Kind: Hashable { case device, user, group, tag, host, ipset }
    enum Direction: Hashable { case reaches, reachedBy }

    /// Renders just the map (no header or scrolling), for image export.
    private var imageOnly = false

    init() {}

    /// A map pinned to one entity, for image export.
    init(focus kind: Kind, _ selection: String, direction: Direction = .reaches) {
        _kind = State(initialValue: kind)
        _selection = State(initialValue: selection)
        _direction = State(initialValue: direction)
        imageOnly = true
    }

    // MARK: - Layout constants

    private let cardSize = CGSize(width: 240, height: 54)
    private let pillSize = CGSize(width: 380, height: 32)
    private let destSize = CGSize(width: 230, height: 46)
    private let pillX: CGFloat = 360
    private let destX: CGFloat = 860
    private let pillRow: CGFloat = 52
    private let destRow: CGFloat = 60
    private var canvasWidth: CGFloat { destX + destSize.width + 24 }

    var body: some View {
        if imageOnly {
            map.background(Theme.background)
        } else {
            screen
        }
    }

    private var screen: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Access Map")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundStyle(Theme.textPrimary)
                    Text(direction == .reaches
                         ? "Pick a device, user, group, or tag to see every rule that applies to it and what it can reach"
                         : "Pick a device, server, tag, or IP set to see everyone who can reach it, and through which rules")
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.textSecondary)
                }
                Spacer()
                if store.isValid {
                    if store.currentWorkspace.kind == .tailscale, !selection.isEmpty {
                        ToolbarButton(label: "Traffic", icon: "chart.bar.xaxis") {
                            store.trafficFilterRequest = node.map { $0.ipAddresses?.first ?? $0.displayName } ?? selection
                        }
                        .help("Real connections for \(node?.displayName ?? selection) from Tailscale's flow logs")
                    }
                    ToolbarButton(label: "Templates", icon: "square.grid.2x2") { showingTemplates = true }
                }
                if store.isValid && !items.isEmpty {
                    ToolbarButton(label: "Export image", icon: "photo") { exportImage() }
                }
                if let node, store.serverClient() != nil {
                    ToolbarButton(label: "Edit tags…", icon: "tag") { editingTags = node }
                }
                if store.isValid && !items.isEmpty {
                    ToolbarButton(label: "Add rule", icon: "plus") { adding = true }
                }
            }
            .padding(.horizontal, 16)
            .padding(.top, 12)

            HStack(spacing: 12) {
                PillTabs(tabs: [(Direction.reaches, "Reaches", "arrow.right"),
                                (Direction.reachedBy, "Reached by", "arrow.left")],
                         selection: $direction)
                PillTabs(tabs: tabs, selection: $kind)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            if store.isValid, direction == .reaches, !selection.isEmpty, !items.isEmpty {
                routeSummary
                    .padding(.horizontal, 16)
                    .padding(.bottom, 8)
            }

            if !store.isValid {
                notice("Fix the policy in the editor to see the access map.")
            } else if items.isEmpty {
                notice(kind == .device
                       ? "Connect a Headscale or Tailscale server on the Server screen to map your devices."
                       : "The policy has no \(kindName)s. Use Templates to add common setups.")
            } else {
                ScrollView([.horizontal, .vertical]) { map }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Theme.background)
        .onAppear(perform: validateSelection)
        .onChange(of: kind) { validateSelection() }
        .onChange(of: store.currentWorkspaceID) { validateSelection() }
        .onChange(of: store.headscaleNodes.count) { validateSelection() }
        .onAppear(perform: applyFocusRequest)
        .onChange(of: store.mapFocusRequest) { applyFocusRequest() }
        .sheet(item: $editing) { RuleSheet(existing: $0) }
        .sheet(isPresented: $adding) {
            direction == .reaches
                ? RuleSheet(existing: nil, prefillSource: policyName)
                : RuleSheet(existing: nil, prefillDestination: policyName)
        }
        .sheet(item: $editingTags) { DeviceTagsSheet(node: $0) }
        .sheet(isPresented: $showingTemplates) { TemplatesSheet() }
    }

    private var tabs: [(value: Kind, label: String, icon: String)] {
        var t: [(value: Kind, label: String, icon: String)] = []
        if !store.headscaleNodes.isEmpty { t.append((.device, "Device", "desktopcomputer")) }
        t.append((.user, "User", "person"))
        t.append((.group, "Group", "person.2"))
        t.append((.tag, "Tag", "tag"))
        if !store.model.hostOrder.isEmpty { t.append((.host, "Host", "server.rack")) }
        if !store.model.ipsetOrder.isEmpty { t.append((.ipset, "IP set", "square.stack.3d.up")) }
        return t
    }

    private var kindName: String {
        switch kind {
        case .device: return "device"
        case .user: return "user"
        case .group: return "group"
        case .tag: return "tag"
        case .host: return "host"
        case .ipset: return "IP set"
        }
    }

    private var items: [String] {
        switch kind {
        case .device: return store.headscaleNodes.map(\.id)
        case .user: return store.model.allUsers
        case .group: return store.model.groupOrder
        case .tag: return store.model.tagOrder
        case .host: return store.model.hostOrder
        case .ipset: return store.model.ipsetOrder
        }
    }

    private func validateSelection() {
        if !tabs.contains(where: { $0.value == kind }) { kind = .group }
        if !items.contains(selection) { selection = items.first ?? "" }
    }

    private func exportImage() {
        let image = AccessMapScreen(focus: kind, selection, direction: direction).environmentObject(store)
        guard let png = renderPNG(image) else { return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.png]
        panel.nameFieldStringValue = "\(title(selection).replacingOccurrences(of: ":", with: "-")) access map.png"
        if panel.runModal() == .OK, let url = panel.url { try? png.write(to: url) }
    }

    /// Focus the map on an entity name ("node:<id>" for a device).
    private func focus(_ name: String) {
        if name.hasPrefix("node:") {
            kind = .device
            selection = String(name.dropFirst(5))
            return
        }
        kind = name.hasPrefix("group:") ? .group : name.hasPrefix("tag:") ? .tag
            : name.hasPrefix("ipset:") ? .ipset : store.model.hosts[name] != nil ? .host : .user
        selection = name
    }

    private func applyFocusRequest() {
        guard let name = store.mapFocusRequest else { return }
        store.mapFocusRequest = nil
        focus(name)
    }

    private var node: HeadscaleNode? {
        kind == .device ? store.headscaleNodes.first { $0.id == selection } : nil
    }

    private func title(_ item: String) -> String {
        kind == .device ? (store.headscaleNodes.first { $0.id == item }?.displayName ?? item) : item
    }

    /// Identities the focused entity matches as in the policy.
    private var focusIDs: [String] { node?.identities ?? [selection] }

    /// How a new rule refers to the focused entity: a device by its tag or user.
    private var policyName: String { node?.policyName ?? selection }

    private func color(_ kind: RuleSummary.Kind) -> Color {
        switch kind {
        case .acl: return Theme.lineBlue
        case .grant: return Theme.lineGreen
        case .ssh: return Theme.pink
        }
    }

    // MARK: - Rules

    private var pills: [RuleSummary] {
        direction == .reaches ? ruleSummaries(store.model, sourceIDs: focusIDs)
            : ruleSummaries(store.model, sourceIDs: nil, destIDs: focusIDs)
    }

    /// The far column: what the rules reach, or who they let in.
    private func endpoints(_ pill: RuleSummary) -> [String] {
        direction == .reaches ? pill.destinations : pill.sources
    }

    // MARK: - Map

    private var map: some View {
        let pills = self.pills
        let dests = pills.flatMap(endpoints).uniqued()
        let top: CGFloat = 28 // room for the column labels
        let height = max(CGFloat(pills.count) * pillRow, CGFloat(dests.count) * destRow, 140) + 40 + top
        let mid = top + (height - top) / 2
        let cardCenter = CGPoint(x: 24 + cardSize.width / 2, y: mid)
        func pillY(_ i: Int) -> CGFloat {
            mid + (CGFloat(i) - CGFloat(pills.count - 1) / 2) * pillRow
        }
        func destY(_ i: Int) -> CGFloat {
            mid + (CGFloat(i) - CGFloat(dests.count - 1) / 2) * destRow
        }
        let dash = StrokeStyle(lineWidth: 1.5, dash: [5, 4])

        return ZStack(alignment: .topLeading) {
            DotGrid()

            ForEach([(pillX, "RULES"), (destX, direction == .reaches ? "REACHES" : "CAN REACH IT")], id: \.1) { x, label in
                Text(label)
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
                    .position(x: x + 60, y: 12)
            }

            ForEach(Array(pills.enumerated()), id: \.element.id) { i, pill in
                ConnectionCurve(from: CGPoint(x: 24 + cardSize.width, y: cardCenter.y),
                                to: CGPoint(x: pillX, y: pillY(i)))
                    .stroke(color(pill.kind).opacity(0.85), style: dash)
                ForEach(endpoints(pill), id: \.self) { d in
                    if let j = dests.firstIndex(of: d) {
                        ConnectionCurve(from: CGPoint(x: pillX + pillSize.width, y: pillY(i)),
                                        to: CGPoint(x: destX, y: destY(j)))
                            .stroke(color(pill.kind).opacity(0.85), style: dash)
                    }
                }
            }

            sourceCard
                .frame(width: cardSize.width, height: cardSize.height)
                .position(cardCenter)

            if pills.isEmpty {
                Text(direction == .reaches ? "No rules apply to \(title(selection))."
                     : "Nothing can reach \(title(selection)).")
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.textSecondary)
                    .position(x: pillX + pillSize.width / 2, y: mid)
            }

            ForEach(Array(pills.enumerated()), id: \.element.id) { i, pill in
                pillView(pill)
                    .frame(width: pillSize.width, height: pillSize.height)
                    .position(x: pillX + pillSize.width / 2, y: pillY(i))
            }

            ForEach(Array(dests.enumerated()), id: \.element) { j, d in
                destCard(d)
                    .frame(width: destSize.width, height: destSize.height)
                    .position(x: destX + destSize.width / 2, y: destY(j))
            }
        }
        .frame(width: canvasWidth, height: height, alignment: .topLeading)
        .padding(.horizontal, 16)
        .padding(.bottom, 16)
    }

    /// Exit-node use and subnet routes for the focused entity.
    private var routeSummary: some View {
        let access = routeAccess(store.model, sourceIDs: focusIDs, nodes: store.headscaleNodes)
        let loaded = !store.headscaleNodes.isEmpty
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: "globe").font(.system(size: 11)).foregroundStyle(Theme.pink).frame(width: 16)
                Text("Exit nodes").font(.system(size: 11.5, weight: .semibold)).foregroundStyle(Theme.textPrimary)
                if !access.exitNode {
                    Text("not allowed — no rule reaches autogroup:internet")
                        .font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                } else {
                    Text(access.exitVia.isEmpty ? "allowed, any exit node" : "allowed via \(access.exitVia.joined(separator: ", "))")
                        .font(.system(size: 11, weight: .semibold)).foregroundStyle(Theme.green)
                    if loaded {
                        if access.exitNodes.isEmpty {
                            Text("— but no matching device is an approved exit node")
                                .font(.system(size: 11)).foregroundStyle(Theme.orange)
                        } else {
                            ForEach(access.exitNodes, id: \.self) { Chip(text: $0, color: Theme.pink, icon: "arrow.up.right.circle") }
                        }
                    }
                }
            }
            if loaded {
                HStack(spacing: 6) {
                    Image(systemName: "point.3.connected.trianglepath.dotted").font(.system(size: 11))
                        .foregroundStyle(Theme.orange).frame(width: 16)
                    Text("Subnet routes").font(.system(size: 11.5, weight: .semibold)).foregroundStyle(Theme.textPrimary)
                    if access.subnets.isEmpty {
                        Text("none of the approved subnet routes").font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                    }
                    ForEach(access.subnets, id: \.route) { s in
                        Chip(text: s.routers.isEmpty ? "\(s.route) (no router for its via tag)"
                             : "\(s.route) via \(s.routers.joined(separator: ", "))",
                             color: s.routers.isEmpty ? Theme.red : Theme.orange)
                    }
                }
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(Theme.panel))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.panelBorder, lineWidth: 1))
    }

    private var sourceCard: some View {
        Button { picking = true } label: {
            HStack(spacing: 10) {
                iconSquare(kind == .device ? "desktopcomputer" : Theme.entityIcon(selection),
                           color: kind == .device || kind == .user ? Theme.textPrimary : Theme.entityColor(selection))
                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: title(selection))
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(Theme.textPrimary)
                        .lineLimit(1)
                    Text(verbatim: sourceSubtitle)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Theme.textSecondary)
                        .lineLimit(1)
                }
                Spacer(minLength: 4)
                Image(systemName: "chevron.up.chevron.down")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
            }
            .padding(.horizontal, 10)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(RoundedRectangle(cornerRadius: 10).fill(Theme.panel))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(Theme.panelBorder, lineWidth: 1))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .popover(isPresented: $picking, arrowEdge: .bottom) {
            ScrollView {
                VStack(alignment: .leading, spacing: 1) {
                    ForEach(items, id: \.self) { item in
                        Button {
                            selection = item
                            picking = false
                        } label: {
                            HStack(spacing: 7) {
                                if let n = kind == .device ? store.headscaleNodes.first(where: { $0.id == item }) : nil {
                                    Circle()
                                        .fill(n.online == true ? Theme.green : Theme.textSecondary.opacity(0.4))
                                        .frame(width: 7, height: 7)
                                }
                                Text(verbatim: title(item))
                                    .font(.system(size: 12, weight: item == selection ? .semibold : .regular))
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 5)
                                .background(RoundedRectangle(cornerRadius: 5)
                                    .fill(item == selection ? Color.white.opacity(0.08) : .clear))
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(6)
            }
            .frame(width: 260, height: min(CGFloat(items.count) * 27 + 12, 360))
        }
    }

    private var sourceSubtitle: String {
        if let node { return [node.ipAddresses?.first, node.statusText].compactMap { $0 }.joined(separator: " · ") }
        switch kind {
        case .group:
            let n = store.model.groups[selection]?.count ?? 0
            return "\(n) member\(n == 1 ? "" : "s")"
        case .tag:
            let n = store.headscaleNodes.filter { $0.allTags.contains(selection) }.count
            return store.headscaleNodes.isEmpty ? "tag" : "\(n) device\(n == 1 ? "" : "s")"
        case .host:
            return store.model.hosts[selection] ?? "host"
        case .ipset:
            let n = store.model.ipsets[selection]?.count ?? 0
            return "\(n) entr\(n == 1 ? "y" : "ies")"
        default:
            return "user"
        }
    }

    private func pillView(_ pill: RuleSummary) -> some View {
        Button { editing = pill } label: { pillLabel(pill) }
            .buttonStyle(.plain)
            .help(([pill.name] + pill.notes).joined(separator: " · ") + " — click to edit")
    }

    private func pillLabel(_ pill: RuleSummary) -> some View {
        HStack(spacing: 0) {
            HStack(spacing: 7) {
                Circle().fill(color(pill.kind)).frame(width: 7, height: 7)
                Text(verbatim: pill.name)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(Theme.textPrimary)
                    .lineLimit(1)
                if !pill.notes.isEmpty {
                    Image(systemName: "info.circle")
                        .font(.system(size: 10))
                        .foregroundStyle(Theme.textSecondary)
                }
            }
            .padding(.horizontal, 10)
            Spacer(minLength: 0)
            Text(verbatim: pill.badge)
                .font(.system(size: 10.5, design: .monospaced))
                .foregroundStyle(Theme.textSecondary)
                .lineLimit(1)
                .frame(maxWidth: 120)
                .padding(.horizontal, 8)
                .frame(maxHeight: .infinity)
                .overlay(Rectangle().fill(Theme.panelBorder).frame(width: 1), alignment: .leading)
        }
        .background(Capsule().fill(Theme.panel))
        .overlay(Capsule().stroke(Theme.panelBorder, lineWidth: 1))
        .contentShape(Capsule())
    }

    private func destCard(_ name: String) -> some View {
        let m = store.model
        let focusable = name.hasPrefix("group:") || name.hasPrefix("tag:") || name.contains("@")
            || m.hosts[name] != nil || m.ipsets[name] != nil
        let isSet = m.ipsets[name] != nil
        return Button {
            if focusable { focus(name) }
        } label: {
            HStack(spacing: 9) {
                iconSquare(Theme.entityIcon(name), color: Theme.entityColor(name))
                VStack(alignment: .leading, spacing: 1) {
                    Text(verbatim: name)
                        .font(.system(size: 12, weight: .semibold, design: .monospaced))
                        .foregroundStyle(Theme.textPrimary)
                        .lineLimit(1)
                    Text(verbatim: destSubtitle(name))
                        .font(.system(size: 10.5))
                        .foregroundStyle(Theme.textSecondary)
                        .lineLimit(1)
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 9)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(RoundedRectangle(cornerRadius: 10).fill(Theme.panel))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(Theme.panelBorder, lineWidth: 1))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(isSet ? "" : focusable ? "Click to focus the map on \(name)" : name)
        // IP sets list their addresses as soon as the pointer is over them.
        .onHover { inside in
            if inside, isSet { hoveredSet = name } else if hoveredSet == name { hoveredSet = nil }
        }
        .popover(isPresented: Binding(get: { hoveredSet == name }, set: { if !$0, hoveredSet == name { hoveredSet = nil } }),
                 arrowEdge: .leading) {
            ipsetPopover(name)
        }
    }

    /// An IP set's entries in order; nested sets and hosts are expanded.
    private func ipsetPopover(_ name: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(verbatim: name)
                .font(.system(size: 12, weight: .bold, design: .monospaced))
                .foregroundStyle(Theme.textPrimary)
                .padding(.bottom, 3)
            ForEach(Array(store.model.ipsetLines(name).enumerated()), id: \.offset) { _, line in
                HStack(spacing: 6) {
                    Image(systemName: line.remove ? "minus.circle" : "plus.circle")
                        .font(.system(size: 10))
                        .foregroundStyle(line.remove ? Theme.red : Theme.green)
                    Text(verbatim: line.text)
                        .font(.system(size: 11.5, design: .monospaced))
                        .foregroundStyle(line.remove ? Theme.textSecondary : Theme.textPrimary)
                }
                .padding(.leading, CGFloat(line.depth) * 16)
            }
            if store.model.ipsetLines(name).contains(where: \.remove) {
                Text("Entries apply top to bottom; − removes addresses added above it.")
                    .font(.system(size: 10))
                    .foregroundStyle(Theme.textSecondary)
                    .padding(.top, 4)
            }
        }
        .padding(12)
        .frame(minWidth: 220, alignment: .leading)
        .textSelection(.enabled)
    }


    private func destSubtitle(_ name: String) -> String {
        let m = store.model
        if name == "*" { return "everything" }
        if name == "autogroup:internet" { return "internet via exit node" }
        if name == "autogroup:self" { return "the user's own devices" }
        if let ip = m.hosts[name] { return ip }
        if let set = m.ipsets[name] { return "\(set.count) entr\(set.count == 1 ? "y" : "ies") — hover to list" }
        if let members = m.groups[name] { return "\(members.count) member\(members.count == 1 ? "" : "s")" }
        if !store.headscaleNodes.isEmpty, name.hasPrefix("tag:") || name.contains("@") {
            let ev = store.evaluator
            let matching = store.headscaleNodes.filter { n in
                n.identities.contains { ev.targetMatches(target: name, destID: $0) }
            }
            let online = matching.filter { $0.online == true }.count
            return matching.isEmpty ? "no devices" : "\(online) of \(matching.count) device\(matching.count == 1 ? "" : "s") online"
        }
        if name.hasPrefix("tag:") { return "tag" }
        if name.hasPrefix("autogroup:") { return "autogroup" }
        return isAddressLike(name) ? "address" : "user"
    }

    private func iconSquare(_ icon: String, color: Color) -> some View {
        Image(systemName: icon)
            .font(.system(size: 12, weight: .medium))
            .foregroundStyle(color)
            .frame(width: 30, height: 30)
            .background(RoundedRectangle(cornerRadius: 7).fill(Color.white.opacity(0.06)))
    }

    private func notice(_ text: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "info.circle")
                .foregroundStyle(Theme.textSecondary)
            Text(text)
                .foregroundStyle(Theme.textSecondary)
        }
        .padding(16)
    }
}

extension PolicyModel {
    /// An IP set's entries for display, in order: nested IP sets are
    /// expanded (indented by depth) and host: entries show their address.
    func ipsetLines(_ name: String, depth: Int = 0,
                    visiting: Set<String> = []) -> [(text: String, remove: Bool, depth: Int)] {
        guard !visiting.contains(name) else { return [] }
        var out: [(text: String, remove: Bool, depth: Int)] = []
        for raw in ipsets[name] ?? [] {
            guard let e = IPSetEntry(raw) else {
                out.append(("\(raw)  (invalid)", false, depth))
                continue
            }
            if e.target.hasPrefix("host:"), let ip = hosts[String(e.target.dropFirst(5))] {
                out.append(("\(e.target)  \(ip)", e.remove, depth))
            } else {
                out.append((e.target, e.remove, depth))
                if e.target.hasPrefix("ipset:") {
                    // Inside "remove ipset:x", its additions are removals.
                    out += ipsetLines(e.target, depth: depth + 1, visiting: visiting.union([name]))
                        .map { ($0.text, $0.remove != e.remove, $0.depth) }
                }
            }
        }
        return out
    }
}
