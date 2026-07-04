# Tailscale ACL Manager — project context

Native macOS SwiftUI app for editing, visualizing, simulating, and testing
Tailscale ACL policies. Fully offline except Sparkle update checks.
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
- `*Screen.swift` — the five screens (editor, matrix, visual builder,
  simulator, tests). Visual builder draws ACL connections blue, grants
  green.
- `App.swift` — app entry, sidebar navigation, Sparkle updater
  (`UpdaterViewModel`) + "Check for Updates…" menu item.

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

No XCTest target. Logic is verified with small headless harnesses compiled
directly against the source files (they're UI-free):

```sh
swiftc -o /tmp/check Sources/TailscaleACL/{HuJSON,PolicyModel,Evaluator,SamplePolicy}.swift main.swift && /tmp/check
```

For store/UI-adjacent checks, compile everything except `App.swift` (it has
`@main`) and wrap in `MainActor.assumeIsolated`. Screens can be verified
offscreen by hosting them in an `NSWindow` + `NSHostingView` and rendering
to a PNG via `bitmapImageRepForCachingDisplay` — useful because standard
screenshot tools may lack screen-recording permission.

## Conventions

- Policy semantics should match Tailscale's documented behavior; when in
  doubt, check https://tailscale.com/docs/reference (grants syntax:
  /docs/reference/syntax/grants).
- Keep the public repo free of personal identifiers (team IDs, Apple IDs,
  credential names beyond what this file already states).
- UI is compact and dark; editor palette mirrors the Tailscale admin
  console (blue keys, green strings, gray comments).
