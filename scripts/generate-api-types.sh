#!/usr/bin/env bash
# Regenerate packages/api-types/ from the current FastAPI backend.
#
# Two-step pipeline:
#   1. Python: dump the live OpenAPI spec (packages/api-types/schema/openapi.json)
#   2. Node:   run openapi-typescript → packages/api-types/src/openapi.d.ts
#
# Usage: bash scripts/generate-api-types.sh
#        npm run build:api-types  (from monorepo root)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PKG="$ROOT/packages/api-types"
SCHEMA_FILE="$PKG/schema/openapi.json"
TYPES_FILE="$PKG/src/openapi.d.ts"

echo "→ Step 1/2: Dump OpenAPI from FastAPI"
python3 "$SCRIPT_DIR/dump-openapi.py" "$SCHEMA_FILE"

echo ""
echo "→ Step 2/2: Generate TypeScript types"

# Locate openapi-typescript binary — npm workspaces hoist devDeps to the
# repo-root node_modules, so the package-level path may not exist. Try
# the hoisted path first, then fall back to the per-package path for
# non-workspace setups, then install if neither is found.
find_openapi_bin() {
  if [[ -x "$ROOT/node_modules/.bin/openapi-typescript" ]]; then
    echo "$ROOT/node_modules/.bin/openapi-typescript"
  elif [[ -x "$PKG/node_modules/.bin/openapi-typescript" ]]; then
    echo "$PKG/node_modules/.bin/openapi-typescript"
  fi
}

OPENAPI_BIN="$(find_openapi_bin)"
if [[ -z "$OPENAPI_BIN" ]]; then
  echo "  Installing workspace devDependencies (first run)..."
  (cd "$ROOT" && npm install --silent)
  OPENAPI_BIN="$(find_openapi_bin)"
  if [[ -z "$OPENAPI_BIN" ]]; then
    echo "ERROR: openapi-typescript binary not found after install" >&2
    exit 1
  fi
fi

"$OPENAPI_BIN" "$SCHEMA_FILE" \
  --output "$TYPES_FILE" \
  --properties-required-by-default \
  2>&1 | sed 's/^/  /' || {
    echo "ERROR: openapi-typescript failed" >&2
    exit 1
  }

echo ""
echo "✓ Generated:"
echo "  schema : $SCHEMA_FILE ($(wc -c < "$SCHEMA_FILE" | tr -d ' ') bytes)"
echo "  types  : $TYPES_FILE  ($(wc -l < "$TYPES_FILE" | tr -d ' ') lines)"
echo ""
echo "Consumers import like:"
echo "  import type { DomainResult, PricingFor } from \"@cleanway/api-types\";"
