#!/usr/bin/env bash
# Sync packages/extension-core/ → extension/, extension-firefox/, extension-safari/
#
# Single source of truth: packages/extension-core/
# Each extension dir keeps its own manifest.json (browser-specific)
# and anything inside `overrides/` which takes precedence over core.
#
# Usage: bash scripts/build-extensions.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CORE_DIR="$ROOT/packages/extension-core"

if [[ ! -d "$CORE_DIR" ]]; then
  echo "ERROR: $CORE_DIR not found" >&2
  exit 1
fi

# Target dirs per browser flavor
declare -a TARGETS=(
  "extension:chrome"
  "extension-firefox:firefox"
  "extension-safari:safari"
)

sync_one() {
  local target_dir="$1"
  local flavor="$2"
  local dest="$ROOT/$target_dir"

  if [[ ! -d "$dest" ]]; then
    echo "ERROR: target $dest does not exist" >&2
    return 1
  fi

  echo "→ Syncing $flavor ($target_dir)"

  # Copy src/, public/, styles/ from core — rsync --delete clears stale files
  # inside these subtrees, but leaves root-level (manifest.json, etc.) alone.
  for subdir in src public styles; do
    if [[ -d "$CORE_DIR/$subdir" ]]; then
      mkdir -p "$dest/$subdir"
      rsync -a --delete \
        --exclude '_locales/' \
        "$CORE_DIR/$subdir/" "$dest/$subdir/"
    fi
  done

  # Apply per-flavor overrides (if any) — extension-firefox/overrides/
  # takes precedence over anything copied from core.
  if [[ -d "$dest/overrides" ]]; then
    echo "  Applying overrides from $target_dir/overrides/"
    rsync -a "$dest/overrides/" "$dest/"
  fi

  # Firefox MV2 compatibility: Promise-returning chrome.* APIs require Firefox's
  # `browser.*` namespace. Inject a shim so our code (which uses .then()) works.
  if [[ "$flavor" == "firefox" ]]; then
    local bg="$dest/src/background/index.js"
    if [[ -f "$bg" ]] && ! grep -q 'build-extensions.sh firefox shim' "$bg"; then
      echo "  [firefox] Injecting browser.* promise shim into background/index.js"
      {
        printf '// build-extensions.sh firefox shim: re-alias chrome to browser so Promise APIs work under MV2\n'
        printf 'if (typeof browser !== "undefined" && (typeof chrome === "undefined" || !chrome.storage || typeof chrome.storage.local.get === "function")) { var chrome = browser; }\n'
        cat "$bg"
      } > "$bg.tmp"
      mv "$bg.tmp" "$bg"
    fi
  fi
}

for entry in "${TARGETS[@]}"; do
  IFS=":" read -r target flavor <<< "$entry"
  sync_one "$target" "$flavor"
done

# Rebuild i18n locales too — core + i18n are built together
echo ""
echo "→ Rebuilding locales (packages/i18n-strings → extensions + landing)"
python3 "$ROOT/scripts/build-i18n.py" 2>&1 | tail -5

echo ""
echo "✓ All 3 extensions rebuilt from packages/extension-core/"
echo "  Load unpacked in browser dev mode to test:"
echo "    Chrome:  chrome://extensions → Developer mode → Load unpacked → $ROOT/extension"
echo "    Firefox: about:debugging → Load Temporary Add-on → $ROOT/extension-firefox/manifest.json"
echo "    Safari:  Xcode → Convert Web Extension → $ROOT/extension-safari"
