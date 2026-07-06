#!/bin/zsh
# Builds TailscaleACL in release mode and assembles "Tailscale ACL.app".
#
# Usage:
#   ./build_app.sh              build + sign
#   ./build_app.sh --notarize   build + sign + notarize with Apple + staple
#
# One-time notarization setup (stores an app-specific password in the keychain):
#   xcrun notarytool store-credentials "$NOTARY_PROFILE" \
#     --apple-id <your-apple-id-email> --team-id <your-team-id>
set -euo pipefail
cd "$(dirname "$0")"

NOTARY_PROFILE="${NOTARY_PROFILE:-tailscale-acl-notary}"
NOTARIZE=0
[[ "${1:-}" == "--notarize" ]] && NOTARIZE=1

swift build -c release

APP="Tailscale ACL.app"

# Assemble and sign in a private temp dir: this project lives in a
# file-provider-synced folder (iCloud Documents) that stamps FinderInfo
# xattrs onto files, which codesign rejects as "detritus".
STAGE="$(mktemp -d)/$APP"
mkdir -p "$STAGE/Contents/MacOS" "$STAGE/Contents/Resources" "$STAGE/Contents/Frameworks"
cp .build/release/TailscaleACL "$STAGE/Contents/MacOS/TailscaleACL"
cp Info.plist "$STAGE/Contents/Info.plist"
cp AppIcon.icns "$STAGE/Contents/Resources/AppIcon.icns"

# Embed Sparkle.framework (binary artifact fetched by SPM).
SPARKLE_FW="$(find .build/artifacts/sparkle -type d -name 'Sparkle.framework' | head -1)"
[[ -d "$SPARKLE_FW" ]] || { echo "error: Sparkle.framework not found — run swift build first." >&2; exit 1; }
ditto "$SPARKLE_FW" "$STAGE/Contents/Frameworks/Sparkle.framework"

xattr -cr "$STAGE"

# Sign with Developer ID when available (hardened runtime + timestamp),
# otherwise fall back to ad-hoc for machines without the certificate.
IDENTITY="${CODESIGN_IDENTITY:-Developer ID Application}"
if security find-identity -v -p codesigning | grep -q "$IDENTITY"; then
  # Sparkle's nested helpers (XPC services, Autoupdate, Updater.app) must be
  # signed with hardened runtime for notarization; --deep covers them all.
  codesign --force --options runtime --timestamp -s "$IDENTITY" --deep \
    "$STAGE/Contents/Frameworks/Sparkle.framework"
  codesign --force --options runtime --timestamp -s "$IDENTITY" "$STAGE"
else
  echo "note: no '$IDENTITY' identity found; using ad-hoc signature"
  codesign --force -s - --deep "$STAGE/Contents/Frameworks/Sparkle.framework"
  codesign --force -s - "$STAGE"
fi
codesign --verify --strict "$STAGE"

if [[ $NOTARIZE == 1 ]]; then
  if ! xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1; then
    echo "error: no keychain profile '$NOTARY_PROFILE' found." >&2
    echo "Run this once (uses an app-specific password from account.apple.com):" >&2
    echo "  xcrun notarytool store-credentials $NOTARY_PROFILE --apple-id <your-apple-id> --team-id <your-team-id>" >&2
    exit 1
  fi
  ZIP="$(dirname "$STAGE")/TailscaleACL.zip"
  ditto -c -k --keepParent "$STAGE" "$ZIP"
  echo "Submitting to Apple notary service (typically 1–5 minutes)…"
  xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$STAGE"
  rm -f "$ZIP"

  # Package the distribution zip from the clean staging copy, before the app
  # lands in the iCloud-synced project folder (which re-adds Finder xattrs).
  VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' Info.plist)"
  mkdir -p dist
  DIST_ZIP="dist/TailscaleACL-$VERSION.zip"
  rm -f "$DIST_ZIP"
  ditto -c -k --keepParent "$STAGE" "$DIST_ZIP"
  echo "Release zip: $PWD/$DIST_ZIP"
fi

rm -rf "$APP"
mv "$STAGE" "$APP"
rmdir "$(dirname "$STAGE")" 2>/dev/null || true

if [[ $NOTARIZE == 1 ]]; then
  spctl --assess --type execute -v "$APP" || true
fi

echo "Built: $PWD/$APP"
