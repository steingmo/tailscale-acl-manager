# Tailscale ACL — native macOS app

A fully native SwiftUI app for editing, visualizing, simulating, and testing
Tailscale ACL policies. Local-first: policies only touch disk when you
explicitly import, export, or link a workspace to a policy file, and the network is used only for update checks
and — if you configure one per workspace — your own
[Headscale](https://headscale.net) server or a tailnet on the official
Tailscale API, where you can pull and push the policy (reviewed first), and
manage device tags and route approvals. Credentials stay in your Keychain.
Headscale pushes require `policy.mode: database`; for Tailscale, an OAuth
client with the `policy_file` and `devices` scopes is the recommended
credential.

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

## Command line

The Homebrew cask also installs `tailscale-acl`, which runs the app's checks
without opening it, e.g. in CI or a pre-commit hook:

```sh
tailscale-acl lint policy.hujson   # problems; exit 1 on errors
tailscale-acl test policy.hujson   # problems + the policy's tests; exit 1 on any failure
```

Use `-` to read the policy from standard input.

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
- **Device posture** — `postures`, `srcPosture`, and `defaultSrcPosture` are
  evaluated: the simulator says "allowed only if posture X", checks real
  devices against their OS and client version, and tests honor
  `srcPostureAttrs`.
- **Linked files** — keep a workspace in sync with a policy file in a Git
  repo (GitOps): valid edits are saved to it, and outside changes load in.
- **Temporary access** — give a rule an expiry date; Problems warns before it
  expires and offers to delete it after.
- **Device clean-up** — find devices not seen in 30 days or with expiring
  keys, and expire, rename, or delete them on the server.
- **Problems in context** — click a problem to jump to its line; the editor
  gutter marks lines with problems, and the command-line tool prints
  `file:line:` locations.
- **ACLs → grants** — convert legacy ACL rules to grants in one step, with
  a check that every user, group, tag, and device keeps exactly the same
  access.
- **Editor help** — completes group, tag, host, IP set, posture, and
  autogroup names inside strings, and shows what a name is on hover.
- **SSH tests** — the policy's `sshTests` run locally next to the network
  tests, and "Generate from current access" pins SSH logins too.
- **Simulator extras** — type any IP as the destination (it shows which
  hosts and IP sets contain it), and "Pin as test" saves the question and
  today's answer as a policy test.
- **Server hygiene** — with a server connected, Problems flags `via` grants
  whose routers lack an approved route for the destination, and group
  members who are no longer users on the server (one-click removal).
- **IP lookup** — type an IP into ⌘K search to see every host, IP set,
  rule, test, and device that covers it, each linked to its line.
- **Real roles** — for Tailscale, users' roles from the users API make
  `autogroup:admin` and the other role autogroups match real people.
- **Shareable reviews** — copy or export a push review (access changes,
  checks, and the text diff) as Markdown for a ticket or pull request.
- **Users** — invite people to Tailscale (with a role) or create Headscale
  users with a pre-auth key, and put them in the policy's groups in the same
  step; change roles, approve, suspend, restore, and offboard (suspend or
  delete, and remove from every group). Policy edits go through the reviewed
  push as usual.
- **Traffic** (Tailscale flow logs) — see real connections between devices,
  users, and subnets; find rules no traffic used and broad rules where only
  a few ports were used; and before a push, replay recent traffic against
  the new policy to see what it would block. Needs flow logging on and the
  `logs:network:read` scope.
- **Who changed it** — for Tailscale, the configuration audit log shows who
  changed the policy and when (needs the `logs:configuration:read` scope).

All structural edits (visual builder, tests) write back into the underlying
HuJSON while preserving your comments.

## Layout

- `Sources/TailscaleACL/HuJSON.swift` — comment-preserving HuJSON parser/serializer
- `Sources/TailscaleACL/PolicyModel.swift` — parsed policy model + dst-spec handling
- `Sources/TailscaleACL/Evaluator.swift` — ACL semantics (default-deny, groups,
  tags, autogroups, wildcard, port ranges, IPv4/IPv6 CIDR) + test runner
- `Sources/TailscaleACL/PolicyStore.swift` — app state, tree mutations, import/export
- `Sources/TailscaleACL/*Screen.swift` — the five screens
- `Sources/TailscaleACL/CodeEditor.swift` — NSTextView-based editor with highlighting
