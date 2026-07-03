#!/bin/zsh
# Releases a new version end-to-end:
#   1. bumps the version in Info.plist
#   2. builds, signs, notarizes, staples, and packages the zip
#   3. commits, tags vX.Y.Z, pushes
#   4. creates the GitHub release with the zip attached
#   5. updates the Homebrew cask in the tap and pushes it
#
# Usage:
#   ./release.sh 1.1.0             full release
#   ./release.sh 1.1.0 --dry-run   build + notarize + package only; no git/GitHub/tap changes
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${1:-}"
DRY_RUN=0
[[ "${2:-}" == "--dry-run" ]] && DRY_RUN=1

TAP_DIR="$HOME/Documents/homebrew-tap"
REPO="steingmo/tailscale-acl-manager"

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: ./release.sh X.Y.Z [--dry-run]" >&2
  exit 1
fi

# --- Preflight ---------------------------------------------------------------
if [[ $DRY_RUN == 0 ]]; then
  if [[ -n "$(git status --porcelain)" ]]; then
    echo "error: working tree has uncommitted changes — commit or stash first." >&2
    exit 1
  fi
  if [[ "$(git branch --show-current)" != "main" ]]; then
    echo "error: releases are cut from main." >&2
    exit 1
  fi
  if git rev-parse "v$VERSION" >/dev/null 2>&1; then
    echo "error: tag v$VERSION already exists." >&2
    exit 1
  fi
  gh auth status >/dev/null 2>&1 || { echo "error: gh not authenticated." >&2; exit 1; }
  [[ -d "$TAP_DIR/.git" ]] || { echo "error: tap clone not found at $TAP_DIR." >&2; exit 1; }
fi

# --- Bump version + build ----------------------------------------------------
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" Info.plist
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $VERSION" Info.plist

./build_app.sh --notarize

ZIP="dist/TailscaleACL-$VERSION.zip"
[[ -f "$ZIP" ]] || { echo "error: expected $ZIP was not produced." >&2; exit 1; }
SHA256="$(shasum -a 256 "$ZIP" | awk '{print $1}')"
echo "sha256: $SHA256"

# Sparkle EdDSA signature for the appcast (key lives in the login keychain).
SIGN_UPDATE="$(find .build/artifacts/sparkle -type f -name sign_update -not -path '*old_dsa*' | head -1)"
[[ -x "$SIGN_UPDATE" ]] || { echo "error: Sparkle sign_update tool not found." >&2; exit 1; }
ED_SIG="$("$SIGN_UPDATE" "$ZIP")"
echo "sparkle: $ED_SIG"

if [[ $DRY_RUN == 1 ]]; then
  git checkout -- Info.plist
  echo ""
  echo "Dry run complete. Would have:"
  echo "  - committed Info.plist bump and tagged v$VERSION"
  echo "  - created GitHub release v$VERSION with $ZIP"
  echo "  - updated appcast.xml and pushed it"
  echo "  - updated cask to $VERSION / $SHA256 and pushed the tap"
  exit 0
fi

# --- Commit, tag, push, release ---------------------------------------------
git add Info.plist
git commit -m "Release v$VERSION"
git tag "v$VERSION"
git push origin main "v$VERSION"

gh release create "v$VERSION" \
  "$ZIP#Tailscale ACL $VERSION (macOS 14+, Apple silicon, notarized)" \
  --title "Tailscale ACL $VERSION" \
  --generate-notes

# --- Update the Sparkle appcast ----------------------------------------------
PUBDATE="$(LC_ALL=C date -u +"%a, %d %b %Y %H:%M:%S +0000")"
cat > appcast.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
  <channel>
    <title>Tailscale ACL</title>
    <item>
      <title>Version $VERSION</title>
      <pubDate>$PUBDATE</pubDate>
      <sparkle:version>$VERSION</sparkle:version>
      <sparkle:shortVersionString>$VERSION</sparkle:shortVersionString>
      <sparkle:minimumSystemVersion>14.0</sparkle:minimumSystemVersion>
      <sparkle:releaseNotesLink>https://github.com/$REPO/releases/tag/v$VERSION</sparkle:releaseNotesLink>
      <enclosure
        url="https://github.com/$REPO/releases/download/v$VERSION/TailscaleACL-$VERSION.zip"
        $ED_SIG
        type="application/octet-stream"/>
    </item>
  </channel>
</rss>
EOF
git add appcast.xml
git commit -m "Update appcast for v$VERSION"
git push origin main

# --- Update the Homebrew cask ------------------------------------------------
git -C "$TAP_DIR" pull --quiet
cat > "$TAP_DIR/Casks/tailscale-acl.rb" <<EOF
cask "tailscale-acl" do
  version "$VERSION"
  sha256 "$SHA256"

  url "https://github.com/$REPO/releases/download/v#{version}/TailscaleACL-#{version}.zip"
  name "Tailscale ACL"
  desc "Edit, visualize, simulate, and test Tailscale ACL policies offline"
  homepage "https://github.com/$REPO"

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on macos: :sonoma
  depends_on arch: :arm64

  app "Tailscale ACL.app"
end
EOF
git -C "$TAP_DIR" add Casks/tailscale-acl.rb
git -C "$TAP_DIR" commit -m "tailscale-acl $VERSION"
git -C "$TAP_DIR" push

echo ""
echo "Released v$VERSION:"
echo "  https://github.com/$REPO/releases/tag/v$VERSION"
echo "  brew upgrade --cask tailscale-acl"
