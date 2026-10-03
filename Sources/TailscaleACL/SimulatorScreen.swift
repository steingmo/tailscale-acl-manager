import SwiftUI

struct SimulatorScreen: View {
    @EnvironmentObject var store: PolicyStore
    @State private var source = ""
    @State private var dest = ""
    @State private var port = 443
    @State private var sshMode = false
    @State private var login = "root"
    @State private var hasServer = false
    @State private var loadingNodes = false
    @State private var nodeError: String?
    /// Tailscale's answer for the current query: (agrees, text).
    @State private var tailscaleCheck: (agrees: Bool?, text: String)?
    @State private var checkingTailscale = false

    /// Autogroups stand in for "a user with this role", "any tagged device", ….
    private var sourceSections: [(name: String, items: [String])] {
        let used = store.model.sourceSpecs.filter { $0.hasPrefix("autogroup:") && $0 != "autogroup:members" }
        return entitySections(special: (["*", "autogroup:member", "autogroup:tagged"] + used).uniqued())
    }

    private var destSections: [(name: String, items: [String])] {
        entitySections(special: ["*"])
    }

    private func entitySections(special: [String]) -> [(name: String, items: [String])] {
        let m = store.model
        var sections: [(String, [String])] = []
        if !store.headscaleNodes.isEmpty {
            sections.append(("Devices", store.headscaleNodes.map { "node:\($0.id)" }))
        }
        if !m.allUsers.isEmpty { sections.append(("Users", m.allUsers)) }
        if !m.groupOrder.isEmpty { sections.append(("Groups", m.groupOrder)) }
        if !m.tagOrder.isEmpty { sections.append(("Tags", m.tagOrder)) }
        if !m.hostOrder.isEmpty { sections.append(("Hosts", m.hostOrder)) }
        if !m.ipsetOrder.isEmpty { sections.append(("IP sets", m.ipsetOrder)) }
        sections.append(("Special", special))
        return sections
    }

    private var sources: [String] { sourceSections.flatMap(\.items).uniqued() }
    private var dests: [String] { destSections.flatMap(\.items).uniqued() }

    private func node(for selection: String) -> HeadscaleNode? {
        guard selection.hasPrefix("node:") else { return nil }
        let id = String(selection.dropFirst(5))
        return store.headscaleNodes.first { $0.id == id }
    }

    private func label(for selection: String) -> String {
        node(for: selection).map { "\($0.displayName) (\($0.identities.first ?? "no identity"))" } ?? selection
    }

    /// What the selection matches as in the policy: a node's identities, or itself.
    private func identities(for selection: String) -> [String] {
        node(for: selection)?.identities ?? [selection]
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Access Simulator")
                            .font(.system(size: 16, weight: .bold))
                            .foregroundStyle(Theme.textPrimary)
                        Text("Check whether a source can reach a destination on a port")
                            .font(.system(size: 11.5))
                            .foregroundStyle(Theme.textSecondary)
                    }
                    Spacer()
                    if hasServer {
                        VStack(alignment: .trailing, spacing: 4) {
                            HStack(spacing: 6) {
                                if loadingNodes { ProgressView().controlSize(.small) }
                                ToolbarButton(
                                    label: store.headscaleNodes.isEmpty ? "Load devices" : "Refresh devices",
                                    icon: "arrow.clockwise"
                                ) { loadNodes() }
                                .disabled(loadingNodes)
                            }
                            if let nodeError {
                                Text(nodeError)
                                    .font(.system(size: 10.5))
                                    .foregroundStyle(Theme.red)
                                    .lineLimit(2)
                            }
                        }
                    }
                }
                .padding(16)

                VStack(alignment: .leading, spacing: 14) {
                    Text("Connection")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundStyle(Theme.textPrimary)

                    formRow(title: "Source", subtitle: "Who is initiating the connection") {
                        sectionedPicker(selection: $source, sections: sourceSections)
                    }

                    formRow(title: "Destination", subtitle: "The device or resource being reached") {
                        sectionedPicker(selection: $dest, sections: destSections)
                    }

                    formRow(title: "Check", subtitle: "Network access on a port, or Tailscale SSH login") {
                        Picker("", selection: $sshMode) {
                            Text("Network").tag(false)
                            Text("SSH").tag(true)
                        }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                        .frame(width: 180)
                    }

                    if sshMode {
                        formRow(title: "Login", subtitle: "Account on the destination device") {
                            TextField("root", text: $login)
                                .textFieldStyle(.roundedBorder)
                                .font(.system(size: 13, design: .monospaced))
                                .frame(width: 150)
                        }
                    } else {
                        formRow(title: "Port", subtitle: "Destination port to test") {
                            HStack(spacing: 4) {
                                TextField("", value: $port, format: .number.grouping(.never))
                                    .textFieldStyle(.roundedBorder)
                                    .font(.system(size: 13, design: .monospaced))
                                    .frame(width: 90)
                                Stepper("", value: $port, in: 1...65535)
                                    .labelsHidden()
                            }
                        }
                    }
                }
                .padding(16)
                .frame(maxWidth: 760, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 9).fill(Theme.panel))
                .overlay(RoundedRectangle(cornerRadius: 9).stroke(Theme.panelBorder, lineWidth: 1))
                .padding(.horizontal, 16)

                if store.isValid, !source.isEmpty, !dest.isEmpty {
                    Group {
                        if sshMode { sshResultSection } else { resultSection }
                    }
                    .padding(16)
                } else if !store.isValid {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(Theme.orange)
                        Text("Fix the policy in the editor to run the simulator.")
                            .foregroundStyle(Theme.textSecondary)
                    }
                    .padding(20)
                }
                Spacer(minLength: 20)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Theme.background)
        .onChange(of: "\(source)|\(dest)|\(port)|\(sshMode)|\(store.text.hashValue)") { tailscaleCheck = nil }
        .onChange(of: store.currentWorkspaceID) {
            hasServer = store.serverClient() != nil
            nodeError = nil
            source = sources.first ?? ""
            dest = store.model.tagOrder.first ?? store.model.hostOrder.first ?? dests.first ?? ""
        }
        .onAppear {
            hasServer = store.serverClient() != nil
            if source.isEmpty { source = sources.first ?? "" }
            if dest.isEmpty {
                dest = store.model.tagOrder.first
                    ?? store.model.hostOrder.first
                    ?? dests.first ?? ""
            }
        }
    }

    @ViewBuilder
    private func endpointChip(_ selection: String) -> some View {
        if let n = node(for: selection) {
            Chip(text: n.displayName, color: Theme.textPrimary, icon: "desktopcomputer")
        } else if selection.contains("@") {
            Chip(text: selection, color: Theme.green, icon: "person")
        } else {
            EntityChip(name: selection)
        }
    }

    private func loadNodes() {
        guard let client = store.serverClient() else { return }
        loadingNodes = true
        nodeError = nil
        Task {
            do {
                store.headscaleNodes = try await client.listNodes()
            } catch {
                nodeError = error.localizedDescription
            }
            loadingNodes = false
        }
    }

    private func sectionedPicker(selection: Binding<String>,
                                 sections: [(name: String, items: [String])]) -> some View {
        Picker("", selection: selection) {
            ForEach(sections, id: \.name) { section in
                Section(section.name) {
                    ForEach(section.items, id: \.self) { Text(verbatim: label(for: $0)).tag($0) }
                }
            }
        }
        .labelsHidden()
        .frame(width: 230)
    }

    private func formRow<Content: View>(title: String, subtitle: String,
                                        @ViewBuilder control: () -> Content) -> some View {
        HStack(alignment: .center) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(Theme.textPrimary)
                Text(subtitle)
                    .font(.system(size: 10.5))
                    .foregroundStyle(Theme.textSecondary)
            }
            Spacer()
            control()
        }
    }

    private var sshResultSection: some View {
        let ev = store.evaluator
        let src = identities(for: source)
        let dst = identities(for: dest)
        let user = login.trimmingCharacters(in: .whitespaces).isEmpty ? "root" : login.trimmingCharacters(in: .whitespaces)
        let matches = ev.evaluateSSH(sourceIDs: src, destIDs: dst, login: user)
        let network = ev.sshNetworkAllowed(sourceIDs: src, destIDs: dst)
        let allowed = network && !matches.isEmpty
        let check = matches.contains { $0.action == "check" } && !matches.contains { $0.action == "accept" }
        let verdict: String = {
            if allowed { return check ? "Allowed with check — the user must re-authenticate periodically." : "Allowed." }
            if matches.isEmpty && !network { return "Denied. No SSH rule allows this login, and there is no network access to port 22." }
            if matches.isEmpty { return "Denied. No SSH rule allows logging in as \(user)." }
            return "Denied. An SSH rule matches, but the policy doesn't allow network access to port 22."
        }()
        let color = allowed ? (check ? Theme.orange : Theme.green) : Theme.red

        return VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 8) {
                endpointChip(source)
                Image(systemName: "arrow.right")
                    .foregroundStyle(Theme.textSecondary)
                endpointChip(dest)
                Chip(text: "ssh \(user)", color: Theme.pink, icon: "terminal")
            }
            ForEach([source, dest].compactMap(node(for:)), id: \.id) { n in
                Text(verbatim: "\(n.displayName) matches as: \(n.identities.isEmpty ? "nothing (no tags, user, or IPs)" : n.identities.joined(separator: ", "))")
                    .font(.system(size: 10.5, design: .monospaced))
                    .foregroundStyle(Theme.textSecondary)
                    .textSelection(.enabled)
            }

            HStack(spacing: 8) {
                Image(systemName: allowed ? "checkmark.shield" : "xmark.shield")
                    .font(.system(size: 13, weight: .semibold))
                Text(verbatim: verdict)
                    .font(.system(size: 13, weight: .semibold))
                    .fixedSize(horizontal: false, vertical: true)
            }
            .foregroundStyle(color)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
            .background(RoundedRectangle(cornerRadius: 8).fill(color.opacity(0.10)))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(color.opacity(0.35), lineWidth: 1))

            Label(network ? "Network access to port 22: allowed" : "Network access to port 22: denied",
                  systemImage: network ? "checkmark.circle" : "xmark.circle")
                .font(.system(size: 11.5))
                .foregroundStyle(network ? Theme.green : Theme.red)

            if !matches.isEmpty {
                Text("Matching SSH rules")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(Theme.textPrimary)
                ForEach(matches) { m in
                    HStack(spacing: 6) {
                        Text("SSH rule #\(m.ruleIndex + 1)")
                            .font(.system(size: 10.5, weight: .bold))
                            .foregroundStyle(Theme.pink)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 3)
                            .background(Theme.pink.opacity(0.15), in: RoundedRectangle(cornerRadius: 5))
                        Text(m.action)
                            .font(.system(size: 10.5, weight: .bold))
                            .foregroundStyle(m.action == "check" ? Theme.orange : Theme.green)
                        Text(verbatim: "\(m.srcSpec) → \(m.dstSpec)")
                            .font(.system(size: 11.5, weight: .semibold, design: .monospaced))
                            .foregroundStyle(Theme.textPrimary)
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Theme.panel))
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.panelBorder, lineWidth: 1))
                }
            }
        }
        .frame(maxWidth: 760, alignment: .leading)
    }

    /// The source device's posture attributes (nil for non-device sources).
    private var sourceAttributes: [String: String]? { node(for: source)?.postureAttributes }

    /// Ask Tailscale to evaluate this source → destination:port against the
    /// editor's policy, by validating it with a single synthetic test. The
    /// test carries the device's known posture attributes, and the app's
    /// expectation is computed the same way (only those attributes are set).
    private func checkWithTailscale() {
        guard let client = store.serverClient() else { return }
        let src = node(for: source)?.policyName ?? source
        let dstHost = node(for: dest).flatMap { n in n.ipAddresses?.first { !$0.contains(":") } } ?? dest
        let entry = "\(dstHost):\(port)"
        let attrs = sourceAttributes ?? [:]
        let expectAllowed = Evaluator(model: store.model, sourceAttributes: attrs, attributesComplete: true)
            .evaluate(sourceIDs: identities(for: source), destIDs: identities(for: dest), port: port).allowed
        let test = ACLTest(index: 0, src: src, accept: expectAllowed ? [entry] : [], deny: expectAllowed ? [] : [entry],
                           srcPostureAttrs: attrs.isEmpty ? nil : attrs)
        checkingTailscale = true
        tailscaleCheck = nil
        Task {
            defer { checkingTailscale = false }
            do {
                guard let report = try await client.validate(try policyWithTests(store.text, [test])) else { return }
                let verdict = expectAllowed ? "allowed" : "denied"
                if report.passed {
                    tailscaleCheck = (true, "Tailscale agrees: \(verdict).")
                } else if !report.failures.isEmpty {
                    tailscaleCheck = (false, "Tailscale disagrees — \(report.failures.flatMap(\.errors).joined(separator: "; "))")
                } else {
                    tailscaleCheck = (nil, "Tailscale couldn't check this (\(src) → \(entry)): \(report.message ?? "")")
                }
            } catch {
                tailscaleCheck = (nil, "Tailscale couldn't check this: \(error.localizedDescription)")
            }
        }
    }

    private var resultSection: some View {
        let result = Evaluator(model: store.model, sourceAttributes: sourceAttributes)
            .evaluate(sourceIDs: identities(for: source), destIDs: identities(for: dest), port: port)
        let color = !result.allowed ? Theme.red : result.conditional ? Theme.orange : Theme.green
        return VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 8) {
                endpointChip(source)
                Image(systemName: "arrow.right")
                    .foregroundStyle(Theme.textSecondary)
                endpointChip(dest)
                Chip(text: ":\(port)", color: Theme.textSecondary)
            }
            ForEach([source, dest].compactMap(node(for:)), id: \.id) { n in
                Text(verbatim: "\(n.displayName) matches as: \(n.identities.isEmpty ? "nothing (no tags, user, or IPs)" : n.identities.joined(separator: ", "))")
                    .font(.system(size: 10.5, design: .monospaced))
                    .foregroundStyle(Theme.textSecondary)
                    .textSelection(.enabled)
            }

            HStack(spacing: 8) {
                Image(systemName: result.allowed ? "checkmark.shield" : "xmark.shield")
                    .font(.system(size: 13, weight: .semibold))
                Text(verbatim: !result.allowed ? "Denied. No rule allows this connection."
                     : result.conditional
                        ? "Allowed only if the source device meets \(result.postures.joined(separator: " or "))\(node(for: source) == nil ? "." : " — the app can't tell from the device list.")"
                        : "Allowed by \(result.matches.count) rule\(result.matches.count == 1 ? "" : "s").")
                    .font(.system(size: 13, weight: .semibold))
                    .fixedSize(horizontal: false, vertical: true)
            }
            .foregroundStyle(color)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
            .background(RoundedRectangle(cornerRadius: 8).fill(color.opacity(0.10)))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(color.opacity(0.35), lineWidth: 1))
            if let attrs = sourceAttributes, !attrs.isEmpty {
                Text(verbatim: "Posture attributes from the device list: " + attrs.sorted { $0.key < $1.key }.map { "\($0.key) = \($0.value)" }.joined(separator: ", "))
                    .font(.system(size: 10.5, design: .monospaced))
                    .foregroundStyle(Theme.textSecondary)
                    .textSelection(.enabled)
            }

            if store.currentWorkspace.kind == .tailscale, store.serverClient() != nil {
                HStack(spacing: 8) {
                    Button("Check with Tailscale") { checkWithTailscale() }
                        .disabled(checkingTailscale)
                        .help("Ask Tailscale's own policy engine the same question about the editor's policy")
                    if checkingTailscale { ProgressView().controlSize(.small) }
                    if let check = tailscaleCheck {
                        Label(check.text, systemImage: check.agrees == true ? "checkmark.seal"
                              : check.agrees == false ? "exclamationmark.triangle.fill" : "questionmark.circle")
                            .font(.system(size: 11.5))
                            .foregroundStyle(check.agrees == true ? Theme.green : check.agrees == false ? Theme.red : Theme.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }

            if !result.matches.isEmpty {
                Text("Matching rules")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(Theme.textPrimary)

                ForEach(result.matches) { match in
                    matchCard(match)
                }
            }
        }
        .frame(maxWidth: 760, alignment: .leading)
    }

    private func matchCard(_ match: RuleMatch) -> some View {
        let isGrant = match.kind == .grant
        let badgeColor = isGrant ? Theme.green : Theme.blue
        let detail = isGrant
            ? "\(match.srcSpec) → \(match.dstSpec) (\(match.ipSpec ?? "*"))"
            : "\(match.srcSpec) → \(match.dstSpec)"
        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Text(isGrant ? "Grant #\(match.ruleIndex + 1)" : "Rule #\(match.ruleIndex + 1)")
                    .font(.system(size: 10.5, weight: .bold))
                    .foregroundStyle(badgeColor)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 3)
                    .background(badgeColor.opacity(0.15), in: RoundedRectangle(cornerRadius: 5))
                Text("matched")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.textSecondary)
                Text(detail)
                    .font(.system(size: 11.5, weight: .semibold, design: .monospaced))
                    .foregroundStyle(Theme.textPrimary)
                ForEach(match.posture, id: \.self) { Chip(text: "if \($0)", color: Theme.orange, icon: "checkmark.shield") }
            }
            if isGrant, let grant = store.model.grants.first(where: { $0.index == match.ruleIndex }) {
                HStack(spacing: 6) {
                    ForEach(grant.src, id: \.self) { EntityChip(name: $0) }
                    Image(systemName: "arrow.right")
                        .font(.system(size: 9.5))
                        .foregroundStyle(Theme.textSecondary)
                    ForEach(grant.dst, id: \.self) { Chip(text: $0, color: Theme.purple) }
                    ForEach(grant.ip, id: \.self) { Chip(text: $0, color: Theme.orange) }
                    if grant.hasApp {
                        Chip(text: "app", color: Theme.pink)
                    }
                    ForEach(grant.via, id: \.self) { Chip(text: "via \($0)", color: Theme.textSecondary) }
                }
            } else if let rule = store.model.rules.first(where: { $0.index == match.ruleIndex }) {
                HStack(spacing: 6) {
                    ForEach(rule.src, id: \.self) { EntityChip(name: $0) }
                    Image(systemName: "arrow.right")
                        .font(.system(size: 9.5))
                        .foregroundStyle(Theme.textSecondary)
                    ForEach(rule.dst, id: \.self) { Chip(text: $0, color: Theme.purple) }
                    if let proto = rule.proto {
                        Chip(text: proto.uppercased(), color: Theme.orange)
                    }
                }
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(Theme.panel))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.panelBorder, lineWidth: 1))
    }
}
