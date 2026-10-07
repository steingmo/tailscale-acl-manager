import SwiftUI

/// Subnet routes and node settings: the policy's "autoApprovers" and
/// "nodeAttrs" sections, plus the routes your devices advertise.
struct RoutesScreen: View {
    @EnvironmentObject var store: PolicyStore
    @State private var editingApprovers: ApproverEdit?
    @State private var editingAttr: AttrEdit?
    @State private var pending: RouteChange?
    @State private var routeError: String?
    @State private var approving = false

    struct RouteChange {
        var node: HeadscaleNode
        var routes: [String]   // routes to add or remove (exit node = both 0.0.0.0/0 and ::/0)
        var approve: Bool
    }

    struct ApproverEdit: Identifiable {
        let id = UUID()
        var route: String?   // nil = exit node approvers
        var isNew = false
    }

    struct AttrEdit: Identifiable {
        let id = UUID()
        var index: Int?      // nil = new entry
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Routes")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundStyle(Theme.textPrimary)
                    Text("Auto-approved subnet routes and exit nodes, node attributes, relay servers, and the routes your devices advertise")
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.textSecondary)
                }
                if store.isValid {
                    approversPanel
                    if store.model.grants.contains(where: { !$0.via.isEmpty }) { viaPanel }
                    attrsPanel
                    if !store.model.derpRegions.isEmpty { DERPPanel(regions: store.model.derpRegions) }
                    devicesPanel
                } else {
                    Label("Fix the policy in the editor to manage routes.", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(Theme.textSecondary)
                }
            }
            .padding(16)
            .frame(maxWidth: 860, alignment: .topLeading)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .background(Theme.background)
        .sheet(item: $editingApprovers) { ApproverSheet(edit: $0) }
        .sheet(item: $editingAttr) { NodeAttrSheet(index: $0.index) }
        .confirmationDialog(pendingTitle, isPresented: Binding(get: { pending != nil },
                                                               set: { if !$0 { pending = nil } })) {
            if let pending {
                Button(pending.approve ? "Approve on server" : "Remove approval on server",
                       role: pending.approve ? nil : .destructive) { apply(pending) }
            }
        } message: {
            Text("This changes the device on \(store.serverDisplayName) right away.")
        }
    }

    // MARK: - Panels

    private var approversPanel: some View {
        panel("Auto-approvers", detail: "Routes and exit nodes advertised by these approvers are approved without a manual step.") {
            ForEach(store.model.routeApprovers, id: \.route) { entry in
                row {
                    Chip(text: entry.route, color: Theme.orange, icon: "point.3.connected.trianglepath.dotted")
                    Image(systemName: "arrow.left").font(.system(size: 9.5)).foregroundStyle(Theme.textSecondary)
                    ForEach(entry.approvers, id: \.self) { EntityChip(name: $0) }
                } actions: {
                    Button("Edit…") { editingApprovers = ApproverEdit(route: entry.route) }
                    Button { store.setRouteApprovers(route: entry.route, approvers: []) } label: {
                        Image(systemName: "trash")
                    }
                    .help("Remove this route")
                }
            }
            row {
                Chip(text: "exit node", color: Theme.pink, icon: "arrow.up.right.circle")
                Image(systemName: "arrow.left").font(.system(size: 9.5)).foregroundStyle(Theme.textSecondary)
                if store.model.exitNodeApprovers.isEmpty {
                    Text("no approvers").font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                }
                ForEach(store.model.exitNodeApprovers, id: \.self) { EntityChip(name: $0) }
            } actions: {
                Button("Edit…") { editingApprovers = ApproverEdit(route: nil) }
            }
            ToolbarButton(label: "Add route", icon: "plus") {
                editingApprovers = ApproverEdit(route: "", isNew: true)
            }
        }
    }

    /// Grants that send traffic through specific routers or exit nodes.
    private var viaPanel: some View {
        panel("Routed through (via)", detail: "Grants whose traffic must go through the subnet routers, exit nodes, or app connectors carrying these tags.") {
            ForEach(store.model.grants.filter { !$0.via.isEmpty }) { g in
                VStack(alignment: .leading, spacing: 5) {
                    row {
                        ForEach(g.src, id: \.self) { EntityChip(name: $0) }
                        Image(systemName: "arrow.right").font(.system(size: 9.5)).foregroundStyle(Theme.textSecondary)
                        ForEach(g.dst, id: \.self) { Chip(text: $0, color: Theme.purple) }
                        Text("via").font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                        ForEach(g.via, id: \.self) { EntityChip(name: $0) }
                    } actions: { EmptyView() }
                    if !store.headscaleNodes.isEmpty {
                        let routers = store.headscaleNodes.filter { !Set($0.allTags).isDisjoint(with: g.via) }
                        Text(verbatim: routers.isEmpty
                             ? "No device carries \(g.via.joined(separator: " or ")), so this traffic has no route."
                             : "Devices: " + routers.map(\.displayName).joined(separator: ", "))
                            .font(.system(size: 10.5))
                            .foregroundStyle(routers.isEmpty ? Theme.orange : Theme.textSecondary)
                    }
                }
            }
        }
    }

    private var attrsPanel: some View {
        panel("Node attributes", detail: "Attributes (and app capabilities) given to the devices each entry targets.") {
            if store.model.nodeAttrs.isEmpty {
                Text("No node attributes.").font(.system(size: 11.5)).foregroundStyle(Theme.textSecondary)
            }
            ForEach(store.model.nodeAttrs) { entry in
                row {
                    ForEach(entry.target, id: \.self) { EntityChip(name: $0) }
                    Image(systemName: "arrow.right").font(.system(size: 9.5)).foregroundStyle(Theme.textSecondary)
                    ForEach(entry.attr, id: \.self) { Chip(text: $0, color: Theme.purple) }
                    if entry.hasApp { Chip(text: "app", color: Theme.pink) }
                } actions: {
                    Button("Edit…") { editingAttr = AttrEdit(index: entry.index) }
                    Button { store.deleteRule(section: "nodeAttrs", index: entry.index) } label: {
                        Image(systemName: "trash")
                    }
                    .help("Remove this entry")
                }
            }
            ToolbarButton(label: "Add node attribute", icon: "plus") { editingAttr = AttrEdit(index: nil) }
        }
    }

    private var devicesPanel: some View {
        let routers = store.headscaleNodes.filter { !($0.availableRoutes ?? []).isEmpty }
        let ev = store.evaluator
        return panel("Devices advertising routes",
                     detail: store.headscaleNodes.isEmpty
                        ? "Connect a server on the Server screen to see which routes your devices advertise."
                        : "Green: approved on the server. Orange: not yet approved, but auto-approvers cover it. Gray: needs manual approval.") {
            if let routeError {
                Label(routeError, systemImage: "xmark.octagon.fill")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !store.headscaleNodes.isEmpty && routers.isEmpty {
                Text("No device advertises routes.").font(.system(size: 11.5)).foregroundStyle(Theme.textSecondary)
            }
            ForEach(routers) { node in
                row {
                    Text(verbatim: node.displayName)
                        .font(.system(size: 12, weight: .semibold, design: .monospaced))
                        .foregroundStyle(Theme.textPrimary)
                    ForEach(node.availableRoutes ?? [], id: \.self) { route in
                        let approved = (node.approvedRoutes ?? []).contains(route)
                        let auto = ev.autoApproves(route: route, node: node)
                        Chip(text: route, color: approved ? Theme.green : auto ? Theme.orange : Theme.textSecondary)
                            .help(approved ? "Approved — right-click to remove approval"
                                  : auto ? "Not approved yet — auto-approvers cover it"
                                  : "Needs manual approval (no auto-approver covers it)")
                            .contextMenu {
                                if approved, store.serverClient() != nil {
                                    Button("Remove approval…") {
                                        pending = RouteChange(node: node, routes: group(route, node), approve: false)
                                    }
                                }
                            }
                        if !approved, store.serverClient() != nil {
                            Button("Approve") {
                                pending = RouteChange(node: node, routes: group(route, node), approve: true)
                            }
                            .font(.system(size: 10.5))
                            .buttonStyle(.borderless)
                            .disabled(approving)
                        }
                    }
                } actions: { EmptyView() }
            }
        }
    }

    // MARK: - Route approval

    private static let exitRoutes: Set<String> = ["0.0.0.0/0", "::/0"]

    /// An exit-node route is approved together with its IPv4/IPv6 twin.
    private func group(_ route: String, _ node: HeadscaleNode) -> [String] {
        guard Self.exitRoutes.contains(route) else { return [route] }
        return (node.availableRoutes ?? []).filter { Self.exitRoutes.contains($0) }
    }

    private var pendingTitle: String {
        guard let pending else { return "" }
        let what = pending.routes.contains("0.0.0.0/0") ? "exit node" : pending.routes.joined(separator: ", ")
        return pending.approve ? "Approve \(what) for \(pending.node.displayName)?"
            : "Remove approval of \(what) for \(pending.node.displayName)?"
    }

    private func apply(_ change: RouteChange) {
        guard let client = store.serverClient() else { return }
        let current = change.node.approvedRoutes ?? []
        let next = change.approve ? (current + change.routes).uniqued() : current.filter { !change.routes.contains($0) }
        approving = true
        routeError = nil
        Task {
            do {
                try await client.setApprovedRoutes(nodeID: change.node.id, routes: next)
                try? await store.refreshNodes()
            } catch {
                routeError = "The server refused: \(error.localizedDescription)"
            }
            approving = false
        }
    }

    // MARK: - Layout helpers

    private func panel<Content: View>(_ title: String, detail: String,
                                      @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.system(size: 13, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            Text(detail)
                .font(.system(size: 10.5))
                .foregroundStyle(Theme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            content()
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 9).fill(Theme.panel))
        .overlay(RoundedRectangle(cornerRadius: 9).stroke(Theme.panelBorder, lineWidth: 1))
    }

    private func row<Content: View, Actions: View>(@ViewBuilder _ content: () -> Content,
                                                   @ViewBuilder actions: () -> Actions) -> some View {
        HStack(spacing: 6) {
            content()
            Spacer()
            actions()
                .font(.system(size: 11))
                .buttonStyle(.borderless)
        }
    }
}

// MARK: - Sheets

private struct ApproverSheet: View {
    var edit: RoutesScreen.ApproverEdit
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var route = ""
    @State private var approvers: [String] = []

    private var isExitNode: Bool { edit.route == nil }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(isExitNode ? "Exit node approvers" : edit.isNew ? "Add auto-approved route" : "Edit auto-approved route")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            if !isExitNode {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Route")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(Theme.textSecondary)
                    TextField("e.g. 192.168.1.0/24", text: $route)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 12, design: .monospaced))
                    Text("Covers any advertised route inside this prefix.")
                        .font(.system(size: 10.5))
                        .foregroundStyle(Theme.textSecondary.opacity(0.8))
                }
            }
            StringListEditor(title: "Approvers — devices with these tags or users", addPrompt: "e.g. tag:router or group:netadmins",
                             suggestions: store.model.tagOrder + store.model.groupOrder, items: $approvers)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") {
                    if isExitNode {
                        store.setExitNodeApprovers(approvers)
                    } else {
                        store.setRouteApprovers(route: route.trimmingCharacters(in: .whitespaces), approvers: approvers,
                                                replacing: edit.isNew ? nil : edit.route)
                    }
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!isExitNode && (route.trimmingCharacters(in: .whitespaces).isEmpty || approvers.isEmpty))
            }
        }
        .padding(20)
        .frame(width: 440)
        .background(Theme.background)
        .onAppear {
            route = edit.route ?? ""
            approvers = isExitNode ? store.model.exitNodeApprovers
                : store.model.routeApprovers.first { $0.route == edit.route }?.approvers ?? []
        }
    }
}

private struct NodeAttrSheet: View {
    var index: Int?
    @EnvironmentObject var store: PolicyStore
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var target: [String] = []
    @State private var attr: [String] = []
    @State private var hasApp = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(index == nil ? "Add node attribute" : "Edit node attribute")
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            TextField("Name (saved as a comment)", text: $name)
                .textFieldStyle(.roundedBorder)
            StringListEditor(title: "Targets", addPrompt: "e.g. tag:server, group:eng, or *",
                             suggestions: ["*", "autogroup:member"] + store.model.tagOrder + store.model.groupOrder,
                             items: $target)
            StringListEditor(title: "Attributes", addPrompt: "e.g. funnel or mullvad",
                             suggestions: ["funnel", "mullvad", "drive:share", "drive:access"], items: $attr)
            if hasApp {
                Text("This entry also has app capabilities (\"app\"), which are kept as they are.")
                    .font(.system(size: 10.5))
                    .foregroundStyle(Theme.textSecondary)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") {
                    store.saveRule(section: "nodeAttrs", index: index, name: name, fields: [
                        ("target", stringArrayJSON(target)),
                        ("attr", attr.isEmpty ? nil : stringArrayJSON(attr)),
                    ])
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(target.isEmpty || (attr.isEmpty && !hasApp))
            }
        }
        .padding(20)
        .frame(width: 440)
        .background(Theme.background)
        .onAppear {
            guard let index, let entry = store.model.nodeAttrs.first(where: { $0.index == index }) else { return }
            (name, target, attr, hasApp) = (entry.comments.first ?? "", entry.target, entry.attr, entry.hasApp)
        }
    }
}
