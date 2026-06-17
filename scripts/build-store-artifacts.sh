#!/usr/bin/env bash
# Strategy doc Top-20 #18 — ship to all 7 browser stores.
#
# This produces one ZIP per store under dist/store-artifacts/.
# All Chromium-based stores (Chrome Web Store, Edge Add-ons, Opera
# add-ons, Brave/Vivaldi which both consume from CWS) share the
# same MV3 build — but each store has its own listing surface, so
# we ship one identical ZIP per store-target to keep the upload
# trail clean.
#
# Output:
#   dist/store-artifacts/cleanway-<version>-chrome.zip       # Chrome Web Store + Brave + Vivaldi
#   dist/store-artifacts/cleanway-<version>-edge.zip         # Microsoft Edge Add-ons
#   dist/store-artifacts/cleanway-<version>-opera.zip        # Opera add-ons
#   dist/store-artifacts/cleanway-<version>-firefox.zip      # Firefox Add-ons (MV2 shim)
#   dist/store-artifacts/cleanway-<version>-safari/          # Safari needs Xcode conversion — staged dir
#   dist/store-artifacts/cleanway-<version>-sha256.txt       # checksums for upload-time verification
#
# Pre-req: scripts/build-extensions.sh has just run (we don't
# re-run it here — the zip step should be a thin downstream).
#
# Usage:
#   bash scripts/build-store-artifacts.sh
#   bash scripts/build-store-artifacts.sh --version 1.4.2

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST="$ROOT/dist/store-artifacts"

VERSION=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

# Pull version from the chrome manifest if not overridden — keeps
# the artifact name aligned with what the store will see.
if [[ -z "$VERSION" ]]; then
  VERSION=$(grep -E '^[[:space:]]*"version"' "$ROOT/extension/manifest.json" \
            | head -n1 \
            | sed -E 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
fi

if [[ -z "$VERSION" ]]; then
  echo "ERROR: could not determine version" >&2
  exit 1
fi

rm -rf "$DIST"
mkdir -p "$DIST"

# Pack each source dir into a ZIP suitable for upload. We
# deliberately exclude:
#   - .DS_Store / Thumbs.db OS noise
#   - .map source-map files (no need on the store, smaller upload)
#   - overrides/ (build-time only)
zip_dir() {
  local src="$1"
  local label="$2"
  local out="$DIST/cleanway-$VERSION-$label.zip"

  if [[ ! -d "$src" ]]; then
    echo "WARN: $src missing — skipping $label" >&2
    return 0
  fi

  echo "→ Packing $label …"
  (
    cd "$src"
    # `zip -r -X` strips macOS extended attributes that the Edge
    # validator otherwise rejects with "extra data not allowed".
    zip -r -X "$out" . \
      -x '*.DS_Store' '*.map' 'overrides/*' '*.git*' \
      >/dev/null
  )
  local size
  size=$(du -h "$out" | awk '{print $1}')
  echo "   $out  ($size)"
}

zip_dir "$ROOT/extension"          chrome
zip_dir "$ROOT/extension"          edge
zip_dir "$ROOT/extension"          opera
zip_dir "$ROOT/extension-firefox"  firefox

# Safari can't be uploaded as a ZIP — it needs Xcode's
# `Convert to Safari Web Extension` step. Stage the source so the
# user can drag it into Xcode.
SAFARI_STAGE="$DIST/cleanway-$VERSION-safari"
mkdir -p "$SAFARI_STAGE"
rsync -a --exclude '.DS_Store' --exclude 'overrides/' \
  "$ROOT/extension-safari/" "$SAFARI_STAGE/"
echo "→ Staged Safari source at $SAFARI_STAGE/  (open in Xcode → Convert)"

# Checksums for upload-time integrity (each store calculates its
# own at submission; we publish ours so a watcher can reproduce).
echo "→ Writing SHA-256 manifest …"
(
  cd "$DIST"
  shasum -a 256 cleanway-"$VERSION"-*.zip > "cleanway-$VERSION-sha256.txt"
)

echo ""
echo "✓ Store artifacts ready at $DIST/"
echo "  Use docs/STORES.md as the per-store submission runbook."
ls -lh "$DIST"
