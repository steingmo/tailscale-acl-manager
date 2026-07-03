# Tailscale ACL — native macOS app

A fully native SwiftUI app for editing, visualizing, simulating, and testing
Tailscale ACL policies. 100% local/offline — the app never touches the network;
policies only touch disk when you explicitly import or export.

Unofficial community tool, not affiliated with or endorsed by Tailscale Inc.
Licensed under the [MIT License](LICENSE).

## Install

With [Homebrew](https://brew.sh):

```sh
brew install --cask steingmo/tap/tailscale-acl
```

Or grab the latest notarized build from the
[Releases page](https://github.com/steingmo/tailscale-acl-manager/releases),
unzip, and drag **Tailscale ACL.app** to Applications. The app is signed and
notarized with a Developer ID, so it runs without Gatekeeper warnings.

Requires macOS 14 (Sonoma) or newer, Apple silicon.

The app checks for updates once a day via [Sparkle](https://sparkle-project.org)
(or on demand from the app menu) and can install them in place. Homebrew
installs can also update with `brew upgrade --cask tailscale-acl`.

## Build from source

```sh
swift build           # or: swift run
```

Requires Xcode command line tools (Swift 5.9+, macOS 14+).

## Features

- **Policy Editor** — HuJSON (JSON + comments + trailing commas) editor with
  syntax highlighting, line numbers, and live validation. Import, Copy,
  Export, and Reset-to-sample.
- **Access Matrix** — grid of every source × destination pair showing exactly
  which ports are open between them.
- **Visual Builder** — draggable diagram of groups, tags, hosts, and IP sets.
  Drag from a source dot to a destination box to grant access (protocol picker
  plus quick-select ports: SSH, DNS, HTTP, HTTPS, RDP, MySQL, PostgreSQL,
  Redis — or custom ranges). Click a line to edit or remove that rule. Add,
  rename (updates every reference across the policy), or delete entities with
  cleanup across all rules and tests. Export the diagram as PNG.
- **Access Simulator** — pick source, destination, and port; see instantly
  whether the connection is allowed or denied, and which rule(s) matched.
- **Tests** — runs the policy's `tests` section locally with pass/fail per
  assertion. Add tests through a dialog (source + allow/deny assertions) or
  delete them — no manual HuJSON editing needed.

All structural edits (visual builder, tests) write back into the underlying
HuJSON while preserving your comments.

## Layout

- `Sources/TailscaleACL/HuJSON.swift` — comment-preserving HuJSON parser/serializer
- `Sources/TailscaleACL/PolicyModel.swift` — parsed policy model + dst-spec handling
- `Sources/TailscaleACL/Evaluator.swift` — ACL semantics (default-deny, groups,
  tags, autogroups, wildcard, port ranges, IPv4 CIDR) + test runner
- `Sources/TailscaleACL/PolicyStore.swift` — app state, tree mutations, import/export
- `Sources/TailscaleACL/*Screen.swift` — the five screens
- `Sources/TailscaleACL/CodeEditor.swift` — NSTextView-based editor with highlighting
