#!/usr/bin/env python3
"""Dump FastAPI's current OpenAPI schema to JSON, boot-free.

Usage:
    python3 scripts/dump-openapi.py [output_path]

Default output: packages/api-types/schema/openapi.json

We don't want the type-generation build to depend on a running API. We import
the FastAPI `app` object and call `app.openapi()` directly — no HTTP, no ports.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main() -> int:
    # Avoid crashing on missing prod-only env vars during import
    os.environ.setdefault("DEBUG", "true")
    os.environ.setdefault(
        "SUPABASE_JWT_SECRET",
        "schema-dump-placeholder-not-a-real-secret-never-used-for-auth",
    )

    repo_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo_root))

    from api.main import app  # noqa: E402 — path manipulated above

    schema = app.openapi()

    output = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else repo_root / "packages" / "api-types" / "schema" / "openapi.json"
    )
    output.parent.mkdir(parents=True, exist_ok=True)

    tmp = output.with_suffix(output.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2, ensure_ascii=False)
        f.write("\n")
    tmp.replace(output)

    paths = len(schema.get("paths", {}))
    schemas = len(schema.get("components", {}).get("schemas", {}))
    print(f"✓ OpenAPI {schema.get('openapi')} dumped to {output.relative_to(repo_root)}")
    print(f"  {paths} paths · {schemas} component schemas · {output.stat().st_size:,} bytes")

    return 0


if __name__ == "__main__":
    sys.exit(main())
