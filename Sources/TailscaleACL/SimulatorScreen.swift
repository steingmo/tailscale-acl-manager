import SwiftUI

struct SimulatorScreen: View {
    @EnvironmentObject var store: PolicyStore
    @State private var source = ""
    @State private var dest = ""
    @State private var port = 443

    private var sourceSections: [(name: String, items: [String])] {
        entitySections(special: ["*", "autogroup:members"])
    }

    private var destSections: [(name: String, items: [String])] {
        entitySections(special: ["*"])
    }

    private func entitySections(special: [String]) -> [(name: String, items: [String])] {
        let m = store.model
        var sections: [(String, [String])] = []
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

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Access Simulator")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundStyle(Theme.textPrimary)
                    Text("Check whether a source can reach a destination on a port")
                        .font(.system(size: 11.5))
                        .foregroundStyle(Theme.textSecondary)
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
                .padding(16)
                .frame(maxWidth: 760, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 9).fill(Theme.panel))
                .overlay(RoundedRectangle(cornerRadius: 9).stroke(Theme.panelBorder, lineWidth: 1))
                .padding(.horizontal, 16)

                if store.isValid, !source.isEmpty, !dest.isEmpty {
                    resultSection
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
        .onAppear {
            if source.isEmpty { source = sources.first ?? "" }
            if dest.isEmpty {
                dest = store.model.tagOrder.first
                    ?? store.model.hostOrder.first
                    ?? dests.first ?? ""
            }
        }
    }

    private func sectionedPicker(selection: Binding<String>,
                                 sections: [(name: String, items: [String])]) -> some View {
        Picker("", selection: selection) {
            ForEach(sections, id: \.name) { section in
                Section(section.name) {
                    ForEach(section.items, id: \.self) { Text($0).tag($0) }
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

    private var resultSection: some View {
        let result = store.evaluator.evaluate(sourceID: source, destID: dest, port: port)
        return VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 8) {
                if source.contains("@") {
                    Chip(text: source, color: Theme.green, icon: "person")
                } else {
                    EntityChip(name: source)
                }
                Image(systemName: "arrow.right")
                    .foregroundStyle(Theme.textSecondary)
                EntityChip(name: dest)
                Chip(text: ":\(port)", color: Theme.textSecondary)
            }

            HStack(spacing: 8) {
                Image(systemName: result.allowed ? "checkmark.shield" : "xmark.shield")
                    .font(.system(size: 13, weight: .semibold))
                Text(result.allowed
                     ? "Allowed by \(result.matches.count) rule\(result.matches.count == 1 ? "" : "s")."
                     : "Denied. No rule allows this connection.")
                    .font(.system(size: 13, weight: .semibold))
            }
            .foregroundStyle(result.allowed ? Theme.green : Theme.red)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill((result.allowed ? Theme.green : Theme.red).opacity(0.10))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke((result.allowed ? Theme.green : Theme.red).opacity(0.35), lineWidth: 1)
            )

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
