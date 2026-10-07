# Tailscale ACL Manager — project context

Native macOS SwiftUI app for editing, visualizing, simulating, and testing
Tailscale ACL policies. Offline except Sparkle update checks and an opt-in,
per-workspace server connection: self-hosted Headscale or the official
Tailscale API. `Servers.swift` defines the `PolicyServer` protocol both
clients implement (`HeadscaleClient` in `Headscale.swift`, `TailscaleClient`
in `Servers.swift`) — screens only use `PolicyStore.serverClient()`, never a
concrete client. Tailscale specifics: HuJSON via `Accept: application/hujson`,
ETag/If-Match on push (412 → refused), `acl/validate` shown in the review,
OAuth client secrets (tskey-client-<id>-…) exchanged at `oauth/token`, device
ids are `nodeId`. Headscale pushes need `policy.mode: database`.
`HeadscaleScreen.swift` is the Server screen (pull, reviewed push, push
history/rollback, devices); `Impact.swift` diffs node-to-node access before a
push; `History.swift` writes push history *before* each push. Credentials
live in the Keychain per workspace (`HeadscaleKeychain`). ATS allows plain
HTTP only to local networks (`NSAllowsLocalNetworking`). Client tests stub
the network with `StubProtocol` (URLProtocol), so they run in CI.
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
  app-only grants confer no network access; non-TCP/UDP proto specs — and
  ACLs with such a `proto` — never match port queries), groups/tags/hosts/
  wildcard sources, autogroups (member, tagged, self, internet, danger-all;
  role autogroups match only when simulated as the source), IPv4/IPv6 CIDR
  containment (`parseCIDR`/`cidrContains` in Lint.swift), test runner.
  IPv6 ACL destinations with ports are bracketed: `[fd7a::1]:22`.
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
  `ConnectionCurve`s; `PillTabs` is the shared segmented tab bar. The map
  has a "Reached by" direction (`ruleSummaries(destIDs:)`) and honors
  `PolicyStore.mapFocusRequest` (set by ⌘K `QuickSearchSheet`).
  `RoutesScreen` edits `autoApprovers`/`nodeAttrs` and shows device routes
  (`Evaluator.autoApproves`). `DeviceTagsSheet` sets device tags via
  `POST /api/v1/node/{id}/tags` (Headscale requires ≥1 tag).
- Port comparisons (push review, device matrix) use `portIntervals`: every
  named port range cut into atomic intervals, one probe each, so changes
  inside ranges are exact. `generateTests` pins current access as tests;
  `explainFailure` says why a test assertion fails.
- `LintIssue.fixes` are one-click fixes applied by `PolicyStore.apply`.
  `LintIssue.path` ("grants[3].src", "groups[group:eng]") resolves to a line
  via `JSON.line(at:)` (the parser records each member's/element's line);
  Problems links to it (`PolicyStore.editorLineRequest`), the gutter marks
  it, and the CLI prints `file:line:`.
- SSH tests: `PolicyModel.sshTests`, `Evaluator.runSSHTests`/`sshOutcome`
  (SSH rules only, no network check — like Tailscale), `generateSSHTests`.
- Server checks in Lint.swift: `lintNodes` also checks `via` grants against
  routers' approved routes (`addressPrefixes`, `prefixContains`);
  `lintUsers` flags group members missing from `PolicyServer.userLogins()`
  (`PolicyStore.serverLogins`, loaded with devices).
- `PolicyServer.serverUsers()` returns logins plus role autogroups
  (Tailscale roles/shared). They're injected as `PolicyModel.userAutogroups`
  (not part of the policy) so every `Evaluator(model:)` sees them; the push
  review copies them onto both models it compares.
- Users (UsersPanel.swift on the Server screen): `PolicyServer` invite/user
  methods are protocol requirements with throwing defaults in an extension
  (so calls through the existential dispatch to each server). Tailscale
  invites need a personal access token; user changes need the `users` scope.
  `PolicyStore.addUser(_:toGroups:)` / `removeUserEverywhere` edit the policy.
- Traffic (Traffic.swift, TrafficScreen.swift): `PolicyServer.flowRecords`
  (Tailscale `logging/network`; nil for Headscale), loaded a day per request
  into `PolicyStore.traffic`. Each device logs its own view, so
  `TrafficAccumulator` treats the lower port as the service and counts bytes
  from the client side only. `Evaluator.proto` makes matching protocol-exact
  for real traffic; `ruleUsage` and `trafficBlocked` (push review) use it.
- `routeAccess` (Impact.swift) backs the Access Map's exit-node/subnet
  summary: internet access comes from `autogroup:internet` or `*` (never
  subnets), `via` limits exit nodes and routers to devices with those tags.
- GitOps (GitOps.swift, GitOpsSheet.swift): `Workspace.gitOps` + linked
  file in a GitHub clone. `GitRepo.pushBranch` commits in a temporary
  `git worktree` from origin's default branch (the user's checkout is never
  touched), `openPullRequest` then uses `gh` (or GitHub's compare page).
  In Git mode the push review opens a PR instead of pushing, and
  `checkServerDrift` compares the server with the file on origin's default
  branch (`driftGitBase`). Tests drive real git against a local bare repo.
- Security (Security.swift): `PolicyStore.serverClient()` returns a
  `GuardedServer` — every mutating call asks `Authorizer` (Touch ID or
  password, 2-minute grace; setting `requireAuthForChanges`) and is appended
  to `ActivityLog` (<data>/activity.jsonl, no secrets). Reads pass through.
  New `PolicyServer` methods must be forwarded in `GuardedServer` (changes
  via `change(…)`). Secrets go to the clipboard via `SecureClipboard`
  (concealed type, cleared after 60 s). `credentialInfo()` reports scopes and
  expiry. CI and the generated GitOps workflow pin actions to commit SHAs
  (Dependabot updates them).
- `ipLookup` (SharedSheets.swift) backs ⌘K IP search; `pushReviewMarkdown`
  (Report.swift) exports the push review.
- `convertACLsToGrants` (Templates.swift) rewrites ACLs as grants; the sheet
  proves equivalence with `entityAccessDifferences` (+ `accessChanges` on
  devices). Headscale accepts grants from 0.29.0.
- Editor: `PolicyTextView` completes `EditorVocabulary` names inside string
  literals (only a chosen completion is inserted) and shows definitions as
  tooltips. `PolicyServer.policyChanges` reads Tailscale's configuration
  audit log (nil for Headscale) for the drift banner and Server screen.
- `Snapshots.swift`: per-workspace version history (<data>/snapshots/),
  recorded on open and around every whole-policy replacement
  (`loadPolicy(_:reason:)`), pushes, and by hand.
- `Templates.swift`: `policyTemplates`, pure tree edits applied in one
  undoable `mutate`. Every template must lint error-free (tested).
- `PolicyStore.checkServerDrift` runs when a workspace opens; the root view
  shows a banner when the server changed since the last pull/push.
- Routes: `HeadscaleClient.setApprovedRoutes` replaces a device's whole
  approved list; exit-node routes are approved as a 0.0.0.0/0 + ::/0 pair.
- `AccessMapScreen(focus:_:direction:)` renders just the map; `renderPNG`
  turns it into an image (map export, per-group/tag images in reports). Visual builder draws ACL connections
  blue, grants green. Matrix cells are clickable (add/edit/remove access
  via the shared `ConnectionSheet` in `SharedSheets.swift`).
- `Lint.swift` — pure `lintPolicy(model)`: undefined references, ownerless
  tags, unused entities, empty groups, invalid addresses/port specs,
  same-kind shadowed rules, postures, `via`, expiring and wide-open rules.
  Cached on `PolicyStore` per parse.
- `RuleConditions.swift`: posture condition grammar/evaluation and the
  `// expires: YYYY-MM-DD` rule comment (parsed out of `comments` into
  `expires`). `Evaluator(sourceAttributes:attributesComplete:)`: nil
  attributes → posture-gated matches are kept but listed in
  `RuleMatch.posture` (`AccessResult.conditional`); tests run with only their
  `srcPostureAttrs`, like Tailscale. Device attributes come from the device
  list (`HeadscaleNode.postureAttributes`: node:os, node:tsVersion).
- `CLI.swift` holds `@main`: `TailscaleACL lint|test <file>` runs headless
  (the cask links it as `tailscale-acl`); anything else starts the app.
- Linked file (`Workspace.linkedFile`): `PolicyStore` reads it on open and
  polls it; valid parses are written back, but only after it was read this
  session, so a stale editor never overwrites it.
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
swift test --scratch-path "$HOME/Library/Caches/tailscale-acl-test-build"
```

The scratch path must be outside the project: iCloud-synced folders stamp
xattrs that make codesign reject the test bundle. Don't use `$TMPDIR` either:
macOS purges old files there, which corrupts the cached Sparkle artifact. `release.sh` runs the suite
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
