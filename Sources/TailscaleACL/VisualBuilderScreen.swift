import SwiftUI
import AppKit
import UniformTypeIdentifiers

/// One drawn line on the canvas: a (rule-or-grant, src, dst) triple.
private struct Connection: Identifiable {
    var kind: RuleMatch.Kind
    var ruleIndex: Int
    var src: String
    var dst: String   // ACL: full dst spec incl. ports; grant: bare target
    var ip: [String]  // grant ip entries; empty for ACLs

    var id: String { "\(kind)|\(ruleIndex)|\(src)|\(dst)" }
    var dstTarget: String { kind == .acl ? DestSpec(dst).target : dst }
    var ports: String {
        kind == .acl ? DestSpec(dst).ports : PolicyStore.splitIPEntries(ip).ports
    }
    var proto: String? {
        kind == .acl ? nil : PolicyStore.splitIPEntries(ip).proto
    }
}

private enum NodeSide { case source, dest }

private struct Node: Identifiable {
    var side: NodeSide
    var name: String
    var id: String { (side == .source ? "S|" : "D|") + name }
}

private let nodeSize = CGSize(width: 190, height: 38)
private let rowSpacing: CGFloat = 58
private let canvasWidth: CGFloat = 920

struct VisualBuilderScreen: View {
    @EnvironmentObject var store: PolicyStore

    @State private var positions: [String: CGPoint] = [:]
    @State private var dragOrigin: CGPoint?
    @State private var wireFrom: Node?
    @State private var wirePoint: CGPoint?
    @State private var editingConnection: Connection?
    @State private var hoveredConnection: String?
    @State private var creating: (src: String, dst: String)?
    @State private var showingAddBox = false
    @State private var renamingNode: Node?

    private var sourceNodes: [Node] {
        var names = store.model.sourceSpecs
        let used = Set(store.model.rules.flatMap(\.src))
        if !names.contains("*") && used.contains("*") { names.insert("*", at: 0) }
        if !names.contains("*") { names.insert("*", at: 0) }
        if !names.contains("autogroup:members") {
            names.insert("autogroup:members", at: 1)
        }
        return names.uniqued().map { Node(side: .source, name: $0) }
    }

    private var destNodes: [Node] {
        var names = store.model.destTargets
        if !names.contains("*") { names.insert("*", at: 0) }
        return names.uniqued().map { Node(side: .dest, name: $0) }
    }

    private var connections: [Connection] {
        var result: [Connection] = []
        for rule in store.model.rules where rule.action == "accept" {
            for src in rule.src {
                for dst in rule.dst {
                    result.append(Connection(kind: .acl, ruleIndex: rule.index,
                                             src: src, dst: dst, ip: []))
                }
            }
        }
        for grant in store.model.grants {
            for src in grant.src {
                for dst in grant.dst {
                    result.append(Connection(kind: .grant, ruleIndex: grant.index,
                                             src: src, dst: dst, ip: grant.ip))
                }
            }
        }
        return result
    }

    private var canvasHeight: CGFloat {
        CGFloat(max(sourceNodes.count, destNodes.count)) * rowSpacing + 90
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            legend
            ScrollView([.horizontal, .vertical]) {
                canvas
                    .frame(width: canvasWidth, height: canvasHeight, alignment: .topLeading)
                    .padding(.horizontal, 16)
                    .padding(.bottom, 20)
            }
        }
        .background(Theme.background)
        .sheet(item: $editingConnection) { conn in
            ConnectionSheet(
                title: conn.kind == .grant ? "Edit access (grant)" : "Edit access (ACL)",
                src: conn.src,
                dstTarget: conn.dstTarget,
                initialPorts: conn.ports,
                initialProto: conn.kind == .grant
                    ? (conn.proto ?? "any")
                    : store.model.rules.first(where: { $0.index == conn.ruleIndex })?.proto ?? "any",
                showRemove: true,
                allowTypeChoice: false,
                initialIsGrant: conn.kind == .grant,
                onSave: { ports, proto, _ in
                    if conn.kind == .grant {
                        store.updateGrantIP(grantIndex: conn.ruleIndex,
                                            ports: ports, proto: proto)
                    } else {
                        store.updateConnection(ruleIndex: conn.ruleIndex, oldDst: conn.dst,
                                               newPorts: ports, proto: proto)
                    }
                },
                onRemove: {
                    if conn.kind == .grant {
                        store.removeGrantConnection(grantIndex: conn.ruleIndex, dst: conn.dst)
                    } else {
                        store.removeConnection(ruleIndex: conn.ruleIndex, dst: conn.dst)
                    }
                }
            )
        }
        .sheet(isPresented: Binding(
            get: { creating != nil },
            set: { if !$0 { creating = nil } }
        )) {
            if let creating {
                ConnectionSheet(
                    title: "Grant access",
                    src: creating.src,
                    dstTarget: creating.dst,
                    initialPorts: "",
                    initialProto: "any",
                    showRemove: false,
                    allowTypeChoice: true,
                    initialIsGrant: true,
                    onSave: { ports, proto, isGrant in
                        let p = ports.isEmpty ? "*" : ports
                        if isGrant {
                            store.addGrant(src: creating.src, dstTarget: creating.dst,
                                           ports: p, proto: proto)
                        } else {
                            store.addRule(src: creating.src, dstTarget: creating.dst,
                                          ports: p, proto: proto)
                        }
                    },
                    onRemove: {}
                )
            }
        }
        .sheet(isPresented: $showingAddBox) {
            AddBoxSheet()
        }
        .sheet(item: $renamingNode) { node in
            EditEntitySheet(name: node.name)
        }
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                Text("Visual Builder")
                    .font(.system(size: 16, weight: .bold))
                    .foregroundStyle(Theme.textPrimary)
                Text("Drag boxes to arrange · drag from a source dot to a destination to grant access · click a line to edit or remove it")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.textSecondary)
            }
            Spacer()
            ToolbarButton(label: "Add box", icon: "plus") { showingAddBox = true }
            ToolbarButton(label: "Export", icon: "square.and.arrow.down") { exportPNG() }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private var legend: some View {
        HStack(spacing: 5) {
            Text("Sources")
                .font(.system(size: 11.5, weight: .semibold))
                .foregroundStyle(Theme.textPrimary)
            Image(systemName: "arrow.right")
                .font(.system(size: 9.5, weight: .semibold))
                .foregroundStyle(Theme.textSecondary)
            Text("Destinations")
                .font(.system(size: 11.5, weight: .semibold))
                .foregroundStyle(Theme.textPrimary)
            Text("·")
                .foregroundStyle(Theme.textSecondary)
            Circle().fill(Theme.blue).frame(width: 7, height: 7)
            Text("ACL")
                .font(.system(size: 11))
                .foregroundStyle(Theme.textSecondary)
            Circle().fill(Theme.green).frame(width: 7, height: 7)
            Text("grant")
                .font(.system(size: 11))
                .foregroundStyle(Theme.textSecondary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color.white.opacity(0.05)))
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Theme.panelBorder, lineWidth: 1))
        .padding(.horizontal, 16)
        .padding(.bottom, 6)
    }

    // MARK: - Canvas

    private var canvas: some View {
        ZStack(alignment: .topLeading) {
            // Connection curves.
            ForEach(connections) { conn in
                let from = dotPoint(for: Node(side: .source, name: conn.src))
                let to = dotPoint(for: Node(side: .dest, name: conn.dstTarget))
                let color = conn.kind == .grant ? Theme.green : Theme.blue
                let active = hoveredConnection == conn.id || editingConnection?.id == conn.id

                ConnectionCurve(from: from, to: to)
                    .stroke(color.opacity(active ? 1 : 0.75),
                            lineWidth: active ? 3.5 : 1.5)
                if active {
                    // Mark both endpoints so it's obvious what the line connects.
                    Circle().fill(color).frame(width: 8, height: 8).position(from)
                    Circle().fill(color).frame(width: 8, height: 8).position(to)
                }
                ConnectionCurve(from: from, to: to)
                    .stroke(Color.clear, lineWidth: 12)
                    .contentShape(ConnectionCurve(from: from, to: to).path(in: CGRect(
                        x: 0, y: 0, width: canvasWidth, height: canvasHeight
                    )).strokedPath(.init(lineWidth: 12)))
                    .onTapGesture { editingConnection = conn }
                    .onHover { hoveredConnection = $0 ? conn.id : nil }
                    .help("\(conn.src) → \(conn.dst) — click to edit")
            }

            // In-progress wire while dragging.
            if let wireFrom, let wirePoint {
                ConnectionCurve(from: dotPoint(for: wireFrom), to: wirePoint)
                    .stroke(Theme.green.opacity(0.9),
                            style: StrokeStyle(lineWidth: 2, dash: [6, 4]))
            }

            // Nodes.
            ForEach(sourceNodes) { node in
                nodeView(node)
            }
            ForEach(destNodes) { node in
                nodeView(node)
            }
        }
        .coordinateSpace(name: "canvas")
    }

    private func nodeView(_ node: Node) -> some View {
        let center = position(of: node)
        return NodeBox(
            node: node,
            isWireTarget: wireFrom != nil && node.side == .dest
                && wirePoint.map { nodeFrame(node).contains($0) } == true,
            onEdit: canDelete(node) ? { renamingNode = node } : nil,
            onDelete: canDelete(node) ? { store.deleteEntity(node.name) } : nil,
            onWireDrag: node.side == .source ? { point, ended in
                wireFrom = node
                wirePoint = point
                if ended {
                    if let target = destNodes.first(where: { nodeFrame($0).contains(point) }) {
                        creating = (src: node.name, dst: target.name)
                    }
                    wireFrom = nil
                    wirePoint = nil
                }
            } : nil
        )
        .frame(width: nodeSize.width, height: nodeSize.height)
        .position(center)
        .gesture(
            DragGesture(coordinateSpace: .named("canvas"))
                .onChanged { value in
                    if dragOrigin == nil { dragOrigin = position(of: node) }
                    if let origin = dragOrigin {
                        positions[node.id] = CGPoint(
                            x: origin.x + value.translation.width,
                            y: origin.y + value.translation.height
                        )
                    }
                }
                .onEnded { _ in dragOrigin = nil }
        )
    }

    private func canDelete(_ node: Node) -> Bool {
        node.name.hasPrefix("group:") || node.name.hasPrefix("tag:")
            || store.model.hosts[node.name] != nil
    }

    // MARK: - Geometry

    private func defaultPosition(of node: Node) -> CGPoint {
        let list = node.side == .source ? sourceNodes : destNodes
        let index = list.firstIndex(where: { $0.id == node.id }) ?? 0
        let x: CGFloat = node.side == .source
            ? nodeSize.width / 2 + 16
            : canvasWidth - nodeSize.width / 2 - 16
        let y = CGFloat(index) * rowSpacing + nodeSize.height / 2 + 22
        return CGPoint(x: x, y: y)
    }

    private func position(of node: Node) -> CGPoint {
        positions[node.id] ?? defaultPosition(of: node)
    }

    private func nodeFrame(_ node: Node) -> CGRect {
        let c = position(of: node)
        return CGRect(x: c.x - nodeSize.width / 2, y: c.y - nodeSize.height / 2,
                      width: nodeSize.width, height: nodeSize.height)
    }

    private func dotPoint(for node: Node) -> CGPoint {
        let c = position(of: node)
        return CGPoint(
            x: node.side == .source ? c.x + nodeSize.width / 2 : c.x - nodeSize.width / 2,
            y: c.y
        )
    }

    // MARK: - Export

    private func exportPNG() {
        let content = canvas
            .frame(width: canvasWidth, height: canvasHeight)
            .background(Theme.background)
            .environmentObject(store)
        let renderer = ImageRenderer(content: content)
        renderer.scale = 2
        guard let nsImage = renderer.nsImage,
              let tiff = nsImage.tiffRepresentation,
              let rep = NSBitmapImageRep(data: tiff),
              let png = rep.representation(using: .png, properties: [:]) else { return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.png]
        panel.nameFieldStringValue = "acl-diagram.png"
        if panel.runModal() == .OK, let url = panel.url {
            try? png.write(to: url)
        }
    }
}

// MARK: - Node box

private struct NodeBox: View {
    var node: Node
    var isWireTarget: Bool
    var onEdit: (() -> Void)?
    var onDelete: (() -> Void)?
    var onWireDrag: ((CGPoint, Bool) -> Void)?

    @State private var hovering = false

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 8)
                .fill(Theme.panel)
            RoundedRectangle(cornerRadius: 8)
                .stroke(isWireTarget ? Theme.green : Theme.panelBorder,
                        lineWidth: isWireTarget ? 2 : 1)

            HStack {
                EntityChip(name: node.name)
                Spacer()
            }
            .padding(.horizontal, 9)

            if hovering, let onEdit {
                VStack {
                    HStack {
                        Spacer()
                        Button(action: onEdit) {
                            Image(systemName: "pencil")
                                .font(.system(size: 8, weight: .semibold))
                                .foregroundStyle(Theme.textPrimary)
                                .padding(4)
                                .background(Circle().fill(Color.white.opacity(0.12)))
                        }
                        .buttonStyle(.plain)
                        .help("Edit name and contents")
                    }
                    Spacer()
                }
                .padding(3)
            }

            // Connection dot.
            HStack {
                if node.side == .dest {
                    dot(filled: false)
                        .offset(x: -6)
                    Spacer()
                } else {
                    Spacer()
                    dot(filled: true)
                        .offset(x: 6)
                        .gesture(
                            onWireDrag.map { handler in
                                DragGesture(coordinateSpace: .named("canvas"))
                                    .onChanged { handler($0.location, false) }
                                    .onEnded { handler($0.location, true) }
                            }
                        )
                        .help("Drag to a destination to grant access")
                }
            }
        }
        .onHover { hovering = $0 }
        .contextMenu {
            if let onEdit {
                Button("Edit…", action: onEdit)
            }
            if let onDelete {
                Button("Delete \(node.name)", role: .destructive, action: onDelete)
            }
        }
    }

    private func dot(filled: Bool) -> some View {
        Circle()
            .fill(filled ? Color(hex: 0x2E86F5) : Color.clear)
            .overlay(Circle().stroke(filled ? Color(hex: 0x77B4FF) : Theme.textSecondary, lineWidth: 1.5))
            .frame(width: 11, height: 11)
    }
}

private struct ConnectionCurve: Shape {
    var from: CGPoint
    var to: CGPoint

    func path(in rect: CGRect) -> Path {
        var path = Path()
        path.move(to: from)
        let dx = max(40, abs(to.x - from.x) * 0.45)
        path.addCurve(
            to: to,
            control1: CGPoint(x: from.x + dx, y: from.y),
            control2: CGPoint(x: to.x - dx, y: to.y)
        )
        return path
    }
}

// MARK: - Sheets

private struct QuickPort: Identifiable {
    var label: String
    var port: Int
    var id: Int { port }
}

private let quickPorts: [QuickPort] = [
    .init(label: "SSH", port: 22),
    .init(label: "DNS", port: 53),
    .init(label: "HTTP", port: 80),
    .init(label: "HTTPS", port: 443),
    .init(label: "RDP", port: 3389),
    .init(label: "MySQL", port: 3306),
    .init(label: "PostgreSQL", port: 5432),
    .init(label: "Redis", port: 6379),
]

private struct ConnectionSheet: View {
    var title: String
    var src: String
    var dstTarget: String
    var initialPorts: String
    var initialProto: String
    var showRemove: Bool
    var allowTypeChoice: Bool
    var initialIsGrant: Bool
    var onSave: (String, String, Bool) -> Void
    var onRemove: () -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var ports = ""
    @State private var proto = "any"
    @State private var isGrant = true

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(title)
                .font(.system(size: 17, weight: .bold))
                .foregroundStyle(Theme.textPrimary)

            HStack(spacing: 8) {
                EntityChip(name: src)
                Image(systemName: "arrow.right")
                    .foregroundStyle(Theme.textSecondary)
                EntityChip(name: dstTarget)
            }

            if allowTypeChoice {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Rule syntax")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(Theme.textSecondary)
                    Picker("", selection: $isGrant) {
                        Text("Grant (modern)").tag(true)
                        Text("ACL (legacy)").tag(false)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .frame(width: 260)
                }
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("Protocol")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
                Picker("", selection: $proto) {
                    Text("Any").tag("any")
                    Text("TCP").tag("tcp")
                    Text("UDP").tag("udp")
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 220)
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("Ports")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
                let columns = [GridItem(.adaptive(minimum: 100), spacing: 6)]
                LazyVGrid(columns: columns, alignment: .leading, spacing: 6) {
                    ForEach(quickPorts) { qp in
                        let active = portSet.contains(String(qp.port))
                        Button {
                            togglePort(qp.port)
                        } label: {
                            // verbatim: port numbers must never get locale
                            // grouping separators (3389, not 3.389)
                            Text(verbatim: "\(qp.label) \(qp.port)")
                                .font(.system(size: 11.5, weight: .medium))
                                .padding(.horizontal, 8)
                                .padding(.vertical, 5)
                                .frame(maxWidth: .infinity)
                                .background(
                                    RoundedRectangle(cornerRadius: 6)
                                        .fill(active ? Theme.green.opacity(0.2) : Color.white.opacity(0.06))
                                )
                                .overlay(
                                    RoundedRectangle(cornerRadius: 6)
                                        .stroke(active ? Theme.green : Theme.panelBorder, lineWidth: 1)
                                )
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(active ? Theme.green : Theme.textPrimary)
                    }
                }
                TextField("Custom, e.g. 22,80,8000-8100 or * for all", text: $ports)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12.5, design: .monospaced))
            }

            HStack {
                if showRemove {
                    Button(role: .destructive) {
                        onRemove()
                        dismiss()
                    } label: {
                        Text("Remove access")
                    }
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(showRemove ? "Save" : "Grant access") {
                    onSave(ports.trimmingCharacters(in: .whitespaces), proto, isGrant)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(ports.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 460)
        .background(Theme.background)
        .onAppear {
            ports = initialPorts
            proto = initialProto
            isGrant = initialIsGrant
        }
    }

    private var portSet: Set<String> {
        Set(ports.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) })
    }

    private func togglePort(_ port: Int) {
        var parts = ports.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && $0 != "*" }
        if let i = parts.firstIndex(of: String(port)) {
            parts.remove(at: i)
        } else {
            parts.append(String(port))
        }
        ports = parts.joined(separator: ",")
    }
}

private struct AddBoxSheet: View {
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var kind: PolicyStore.EntityKind = .group
    @State private var name = ""
    @State private var address = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Add box")
                .font(.system(size: 17, weight: .bold))
                .foregroundStyle(Theme.textPrimary)

            Picker("Kind", selection: $kind) {
                ForEach(PolicyStore.EntityKind.allCases) { k in
                    Text(k.rawValue).tag(k)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            TextField(placeholderName, text: $name)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 12.5, design: .monospaced))

            if kind == .host || kind == .ipSet {
                TextField(kind == .host ? "IP address, e.g. 100.64.0.9" : "CIDR, e.g. 10.1.0.0/24",
                          text: $address)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12.5, design: .monospaced))
            }

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Add") {
                    store.addEntity(kind: kind, name: name.trimmingCharacters(in: .whitespaces),
                                    address: address.trimmingCharacters(in: .whitespaces))
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!valid)
            }
        }
        .padding(24)
        .frame(width: 420)
        .background(Theme.background)
    }

    private var placeholderName: String {
        switch kind {
        case .group: return "Name, e.g. group:design or just design"
        case .tag: return "Name, e.g. tag:monitoring or just monitoring"
        case .host: return "Name, e.g. build-server"
        case .ipSet: return "Name, e.g. lab-net"
        }
    }

    private var valid: Bool {
        let n = name.trimmingCharacters(in: .whitespaces)
        if n.isEmpty { return false }
        if kind == .host || kind == .ipSet {
            return !address.trimmingCharacters(in: .whitespaces).isEmpty
        }
        return true
    }
}

/// Full entity editor: rename, plus the entity's contents — group members,
/// tag owners, or a host's IP/CIDR.
private struct EditEntitySheet: View {
    var name: String
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var newName = ""
    @State private var items: [String] = []
    @State private var newItem = ""
    @State private var address = ""

    private enum Kind { case group, tag, host }
    private var kind: Kind {
        if name.hasPrefix("group:") { return .group }
        if name.hasPrefix("tag:") { return .tag }
        return .host
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Edit \(name)")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)

            VStack(alignment: .leading, spacing: 6) {
                Text("Name")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
                TextField("Name", text: $newName)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12, design: .monospaced))
                Text("Renaming updates every reference in groups, tag owners, rules, and tests.")
                    .font(.system(size: 10.5))
                    .foregroundStyle(Theme.textSecondary)
            }

            switch kind {
            case .group:
                listEditor(title: "Members",
                           addPrompt: "Add member, e.g. erika@example.com",
                           suggestions: [])
            case .tag:
                listEditor(title: "Owners — who may apply this tag",
                           addPrompt: "Add owner, e.g. group:ops or an email",
                           suggestions: store.model.groupOrder + ["autogroup:admin"])
            case .host:
                VStack(alignment: .leading, spacing: 6) {
                    Text("IP address / CIDR")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(Theme.textSecondary)
                    TextField("e.g. 100.64.0.9 or 10.1.0.0/24", text: $address)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 12, design: .monospaced))
                }
            }

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!valid)
            }
        }
        .padding(20)
        .frame(width: 440)
        .background(Theme.background)
        .onAppear {
            newName = name
            switch kind {
            case .group: items = store.model.groups[name] ?? []
            case .tag: items = store.model.tagOwners[name] ?? []
            case .host: address = store.model.hosts[name] ?? ""
            }
        }
    }

    private func listEditor(title: String, addPrompt: String,
                            suggestions: [String]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Theme.textSecondary)

            ForEach(items.indices, id: \.self) { i in
                HStack(spacing: 6) {
                    TextField("", text: Binding(
                        get: { i < items.count ? items[i] : "" },
                        set: { if i < items.count { items[i] = $0 } }
                    ))
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12, design: .monospaced))
                    Button {
                        items.remove(at: i)
                    } label: {
                        Image(systemName: "minus.circle")
                            .font(.system(size: 11))
                            .foregroundStyle(Theme.textSecondary)
                    }
                    .buttonStyle(.plain)
                    .help("Remove")
                }
            }

            HStack(spacing: 6) {
                TextField(addPrompt, text: $newItem)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12, design: .monospaced))
                    .onSubmit { addItem() }
                if !suggestions.isEmpty {
                    Menu {
                        ForEach(suggestions.filter { !items.contains($0) }, id: \.self) { s in
                            Button(s) { items.append(s) }
                        }
                    } label: {
                        Image(systemName: "chevron.down.circle")
                            .font(.system(size: 11))
                    }
                    .menuStyle(.borderlessButton)
                    .frame(width: 24)
                    .help("Add a known entity")
                }
                Button {
                    addItem()
                } label: {
                    Image(systemName: "plus.circle")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.blue)
                }
                .buttonStyle(.plain)
                .disabled(newItem.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
    }

    private func addItem() {
        let trimmed = newItem.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !items.contains(trimmed) else { return }
        items.append(trimmed)
        newItem = ""
    }

    private var valid: Bool {
        let n = newName.trimmingCharacters(in: .whitespaces)
        if n.isEmpty { return false }
        if kind == .host && address.trimmingCharacters(in: .whitespaces).isEmpty {
            return false
        }
        return true
    }

    private func save() {
        // Apply content edits under the current name first, then rename.
        let cleaned = items
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        switch kind {
        case .group:
            store.setEntityList(section: "groups", key: name, values: cleaned)
        case .tag:
            store.setEntityList(section: "tagOwners", key: name, values: cleaned)
        case .host:
            store.setHostAddress(name: name,
                                 address: address.trimmingCharacters(in: .whitespaces))
        }

        var n = newName.trimmingCharacters(in: .whitespaces)
        // Keep the entity's kind prefix if the user drops it.
        if kind == .group && !n.hasPrefix("group:") { n = "group:\(n)" }
        if kind == .tag && !n.hasPrefix("tag:") { n = "tag:\(n)" }
        if n != name {
            store.renameEntity(from: name, to: n)
        }
        dismiss()
    }
}
