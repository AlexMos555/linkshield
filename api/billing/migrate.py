"""Apply api/billing/migrations/*.sql to the billing database, in order, once each.

    DATABASE_URL_BILLING=postgresql://... python -m api.billing.migrate

Tracks applied files in `billing_schema_migrations`. Each file runs inside
one transaction. This is the ONLY code that touches the billing schema;
Supabase migrations under supabase/ are a different database.
"""
from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Sequence

logger = logging.getLogger("cleanway.billing.migrate")

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

_TRACKING_TABLE = (
    "CREATE TABLE IF NOT EXISTS billing_schema_migrations ("
    "  name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
)


def migration_files(directory: Path = MIGRATIONS_DIR) -> Sequence[Path]:
    """The .sql files in lexical order (001_, 002_, ...)."""
    return sorted(p for p in directory.glob("*.sql") if p.is_file())


async def apply_migrations(conn, directory: Path = MIGRATIONS_DIR) -> Sequence[str]:
    """Apply every file not yet recorded; returns the names applied this run."""
    await conn.execute(_TRACKING_TABLE)
    done = {r["name"] for r in await conn.fetch("SELECT name FROM billing_schema_migrations")}
    applied = []
    for path in migration_files(directory):
        if path.name in done:
            continue
        async with conn.transaction():
            await conn.execute(path.read_text(encoding="utf-8"))
            await conn.execute("INSERT INTO billing_schema_migrations (name) VALUES ($1)", path.name)
        applied.append(path.name)
        # `name` is reserved on LogRecord — never use it as an extra key.
        logger.info("billing.migration.applied", extra={"migration": path.name})
    return applied


async def migrate(dsn: str) -> Sequence[str]:
    import asyncpg

    conn = await asyncpg.connect(dsn)
    try:
        return await apply_migrations(conn)
    finally:
        await conn.close()


def main(argv: Sequence[str]) -> int:
    from api.billing.settings import get_billing_settings

    dsn = argv[1] if len(argv) > 1 else get_billing_settings().database_url_billing
    if not dsn:
        print("DATABASE_URL_BILLING is not set", file=sys.stderr)
        return 2
    applied = asyncio.run(migrate(dsn))
    print("applied: " + (", ".join(applied) if applied else "nothing (up to date)"))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv))
