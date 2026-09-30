# Tailscale ACL Manager — project context

Native macOS SwiftUI app for editing, visualizing, simulating, and testing
Tailscale ACL policies. Offline except Sparkle update checks and an opt-in
Headscale connection (`Headscale.swift`: REST client + Keychain-stored API
key; `HeadscaleScreen.swift`: pull, reviewed push, push history/rollback,
list nodes; `Impact.swift`: node-to-node access diff shown before a push;
`History.swift`: push history in ~/Library/Application Support/TailscaleACL,
written *before* each push so a rollback copy always exists; device checks
in `lintNodes` in `Lint.swift`). Pushing needs
the server in `policy.mode: database`. ATS allows plain HTTP only to local
networks (`NSAllowsLocalNetworking`).
Unofficial community tool, MIT licensed, distributed via GitHub Releases
and a Homebrew tap (`steingmo/homebrew-tap`, cask `tailscale-acl`).

## Architecture

Swift Package (no Xcode project). All source in `Sources/TailscaleACL/`:

- `HuJSON.swift` — HuJSON parser/serializer (JSON + comments + trailing
  commas). Comments preceding object members / array elements are captured
  on the node and re-emitted on serialization. **The JSON tree is the source
  of truth**: all structural edits mutate the tree and regenerate the text,
  which is how comments survive UI edits.
- `PolicyModel.swift` — read-only model derived from the tree (groups,
  tagOwners, hosts, acls, grants, tests) + `DestSpec` ("tag:server:22,80"
  → target/ports; ports are whatever follows the *last* colon, if
  port-shaped).
- `Evaluator.swift` — access semantics: default deny, accept-only ACLs,
  grants (`ip` grammar: `*`, `443`, `80-443`, `proto:port`, `proto:*`;
  app-only grants confer no network access; non-TCP/UDP proto specs never
  match port queries), groups/tags/hosts/autogroup/wildcard sources, IPv4
  CIDR containment, test runner.
- `PolicyStore.swift` — `@MainActor ObservableObject`; owns the text, the
  tree, and all mutations (rules, grants, tests, entities, rename cascade).
  Typing reparses on a 120 ms debounce; programmatic mutations reparse
  immediately.
- `CodeEditor.swift` — NSTextView-based editor. **Deliberately TextKit 1**
  and **deliberately no NSRulerView**: the ruler corrupts NSScrollView
  tiling inside SwiftUI on recent macOS and blanks the text. Line numbers
  are a sibling `GutterView` synced via bounds-change notifications.
- `*Screen.swift` — the screens (access map, editor, matrix, visual
  builder, simulator, ssh, tests, problems, headscale). `AccessMapScreen`
  is a NetBird-style focused view: one device/user/group/tag → the rules
  that apply to it → destinations. Maps use `DotGrid` and dashed
  `ConnectionCurve`s; `PillTabs` is the shared segmented tab bar. Visual builder draws ACL connections
  blue, grants green. Matrix cells are clickable (add/edit/remove access
  via the shared `ConnectionSheet` in `SharedSheets.swift`).
- `Lint.swift` — pure `lintPolicy(model)`: undefined references, ownerless
  tags, unused entities, empty groups, invalid addresses/port specs,
  same-kind shadowed rules. Cached on `PolicyStore` per parse.
- `App.swift` — app entry, sidebar navigation + workspace menu, Sparkle
  updater (`UpdaterViewModel`) + "Check for Updates…" menu item.
- `Workspaces.swift` — named workspaces (policy + Headscale URL) persisted
  to Application Support; each workspace's API key is a Keychain item keyed
  by workspace id. The editor text autosaves into the current workspace.
  First launch migrates the old single URL/key into "Default".
- Undo: every whole-text replacement goes through `PolicyStore.replaceText`,
  which registers on the window's undo manager (the same one NSTextView
  typing uses), so Cmd-Z covers visual edits; switching workspaces clears
  undo. Test harnesses touching `PolicyStore` must back up and restore the
  Application Support files and pre-seed `workspaces.json` so the Keychain
  migration doesn't run.
- SSH: `Evaluator.evaluateSSH` + `sshNetworkAllowed` (Tailscale needs both
  an SSH rule and network access on port 22); the simulator has an SSH mode
  and the push review diffs SSH logins.

Gotcha: interpolating `Int` directly into SwiftUI `Text` applies
locale-aware grouping separators ("3.389") — use `Text(verbatim:)` or
`String()` for ports and other identifiers.

## Building

- Dev: `swift build` / `swift run`.
- App bundle: `./build_app.sh` — builds release, assembles the bundle **in a
  temp staging dir** (the project may live in an iCloud-synced folder, which
  stamps FinderInfo xattrs that codesign rejects as "detritus" — never sign
  in place), embeds Sparkle.framework, signs everything (Developer ID if
  present, else ad-hoc), and moves the app into the project dir.

## Releasing

`./release.sh X.Y.Z` does everything: bumps Info.plist, builds + notarizes +
staples + packages `dist/TailscaleACL-X.Y.Z.zip`, signs the zip with the
Sparkle EdDSA key, commits + tags `vX.Y.Z` + pushes, creates the GitHub
release, regenerates `appcast.xml` (served raw from main — this is the
Sparkle feed), and updates the Homebrew cask in `~/Documents/homebrew-tap`.
`--dry-run` runs the build pipeline without touching git/GitHub/tap.

Machine requirements for releasing (not needed for code changes): a
Developer ID certificate in the keychain, a `notarytool` keychain profile
named `tailscale-acl-notary`, the Sparkle EdDSA private key in the login
keychain (**never regenerate it** — shipped apps only trust updates signed
by this key; the owner keeps a backup), an authenticated `gh` CLI, and a
clone of the tap repo at `~/Documents/homebrew-tap`.

## Testing

`Tests/TailscaleACLTests` is an XCTest suite (policy logic, lint, SSH, access
diff, line diff, report, and store/workspace/undo behavior). Run it with:

```sh
swift test --scratch-path "${TMPDIR}tailscale-acl-test-build"
```

The scratch path must be outside the project: iCloud-synced folders stamp
xattrs that make codesign reject the test bundle. `release.sh` runs the suite
first and stops on failure; GitHub Actions (`.github/workflows/test.yml`) runs
it on every push to main. Store tests set `TAILSCALE_ACL_DATA_DIR` to a temp
folder and pre-seed `workspaces.json`, so they never touch real app data or
the Keychain migration — keep it that way for new store tests.

Screens can be checked offscreen by hosting them in an `NSWindow` +
`NSHostingView` and rendering to a PNG via `bitmapImageRepForCachingDisplay`
(screenshot tools may lack screen-recording permission). Point
`TAILSCALE_ACL_DATA_DIR` at a temp folder when doing so.

## Conventions

- Policy semantics should match Tailscale's documented behavior; when in
  doubt, check https://tailscale.com/docs/reference (grants syntax:
  /docs/reference/syntax/grants).
- Keep the public repo free of personal identifiers (team IDs, Apple IDs,
  credential names beyond what this file already states).
- UI is compact and dark; editor palette mirrors the Tailscale admin
  console (blue keys, green strings, gray comments).
