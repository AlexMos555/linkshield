"""Migration 026: orgs.admin_user_id cascades with its user.

Migration 001 left `orgs.admin_user_id` with no ON DELETE, so deleting an
org admin failed with a foreign-key violation — and the GDPR purge, which
deletes a batch of users in one DELETE, failed for the whole batch every
run (api/services/account_purge.py now deletes those orgs first).

CI has no database, so the SQL is checked statically (comments stripped,
as in tests/test_migrations_security.py). With MIGRATIONS_TEST_DATABASE_URL
pointing at a scratch Postgres — never a real project: the test drops and
recreates the `public` and `auth` schemas — 001 and 026 are applied for
real and the cascade is exercised.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

MIGRATIONS = Path(__file__).resolve().parents[1] / "supabase" / "migrations"
MIGRATION = MIGRATIONS / "026_orgs_admin_cascade.sql"
PG_URL = os.environ.get("MIGRATIONS_TEST_DATABASE_URL", "")


def _sql(path: Path) -> str:
    text = re.sub(r"/\*.*?\*/", "", path.read_text(encoding="utf-8"), flags=re.S)
    text = re.sub(r"--[^\n]*", "", text)
    return re.sub(r"\s+", " ", text).strip()


def test_026_has_its_own_migration_number():
    # It was the newest when written; 027 came next.
    numbers = sorted(int(p.name[:3]) for p in MIGRATIONS.glob("[0-9][0-9][0-9]_*.sql"))
    assert MIGRATION.exists()
    assert numbers.count(26) == 1 and 25 in numbers and 27 in numbers


def test_001_really_left_admin_user_id_without_on_delete():
    """The premise: if 001 ever changes, this migration needs a second look."""
    sql = _sql(MIGRATIONS / "001_initial_schema.sql")
    assert re.search(r"admin_user_id UUID NOT NULL REFERENCES users\(id\),", sql)


def test_026_recreates_the_fk_with_on_delete_cascade_in_one_transaction():
    sql = _sql(MIGRATION)
    assert sql.startswith("BEGIN;") and sql.endswith("COMMIT;")
    assert re.search(
        r"ALTER TABLE public\.orgs ADD CONSTRAINT orgs_admin_user_id_fkey "
        r"FOREIGN KEY \(admin_user_id\) REFERENCES public\.users \(id\) ON DELETE CASCADE;",
        sql,
    )
    # The old constraint is found by column, not by an assumed name, so a
    # project whose constraint is named differently doesn't end up with
    # both (the old NO ACTION one would keep blocking the delete).
    assert "c.conrelid = 'public.orgs'::regclass" in sql
    assert "c.contype = 'f'" in sql
    assert "a.attname = 'admin_user_id'" in sql
    assert "DROP CONSTRAINT %I" in sql


def test_026_touches_nothing_else():
    sql = _sql(MIGRATION)
    assert not re.search(r"\b(GRANT|REVOKE|CREATE POLICY|DROP POLICY|CREATE TABLE|DROP TABLE)\b", sql, re.I)
    altered = set(re.findall(r"ALTER TABLE (?:ONLY )?([\w.]+)", sql, re.I))
    assert altered == {"public.orgs"}


# ─── The real thing, on a scratch Postgres ───────────────────────


async def _fresh_001(conn) -> None:
    """An empty database with 001 applied. 001's policies call Supabase's
    auth.uid(), stubbed here."""
    await conn.execute(
        "DROP SCHEMA IF EXISTS public CASCADE; DROP SCHEMA IF EXISTS auth CASCADE;"
        "CREATE SCHEMA public; CREATE SCHEMA auth;"
        "CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS 'SELECT NULL::uuid';"
    )
    await conn.execute((MIGRATIONS / "001_initial_schema.sql").read_text(encoding="utf-8"))


@pytest.mark.asyncio
@pytest.mark.skipif(not PG_URL, reason="MIGRATIONS_TEST_DATABASE_URL not set")
async def test_026_on_postgres_deleting_the_admin_deletes_the_org_and_its_members():
    import asyncpg

    conn = await asyncpg.connect(PG_URL)
    try:
        await _fresh_001(conn)
        admin = await conn.fetchval("INSERT INTO users (email) VALUES ('admin@example.com') RETURNING id")
        member = await conn.fetchval("INSERT INTO users (email) VALUES ('member@example.com') RETURNING id")
        org = await conn.fetchval("INSERT INTO orgs (name, admin_user_id) VALUES ('Acme', $1) RETURNING id", admin)
        await conn.execute("INSERT INTO org_members (org_id, user_id) VALUES ($1, $2)", org, member)

        # Before 026: the admin can't be deleted (this is what failed the purge).
        with pytest.raises(asyncpg.ForeignKeyViolationError):
            await conn.execute("DELETE FROM users WHERE id = $1", admin)

        for _ in range(2):  # re-running is safe
            await conn.execute(MIGRATION.read_text(encoding="utf-8"))
        fks = await conn.fetch(
            "SELECT conname, confdeltype::text AS confdeltype FROM pg_constraint "
            "WHERE conrelid = 'public.orgs'::regclass AND contype = 'f'"
        )
        assert [(r["conname"], r["confdeltype"]) for r in fks] == [("orgs_admin_user_id_fkey", "c")]

        await conn.execute("DELETE FROM users WHERE id = $1", admin)
        assert await conn.fetchval("SELECT count(*) FROM orgs") == 0
        assert await conn.fetchval("SELECT count(*) FROM org_members") == 0
        assert await conn.fetchval("SELECT count(*) FROM users WHERE id = $1", member) == 1
    finally:
        await conn.close()


@pytest.mark.asyncio
@pytest.mark.skipif(not PG_URL, reason="MIGRATIONS_TEST_DATABASE_URL not set")
async def test_026_on_postgres_replaces_a_differently_named_constraint():
    import asyncpg

    conn = await asyncpg.connect(PG_URL)
    try:
        await _fresh_001(conn)
        await conn.execute("ALTER TABLE orgs RENAME CONSTRAINT orgs_admin_user_id_fkey TO legacy_admin_fk")
        await conn.execute(MIGRATION.read_text(encoding="utf-8"))
        names = await conn.fetch(
            "SELECT conname FROM pg_constraint WHERE conrelid = 'public.orgs'::regclass AND contype = 'f'"
        )
        assert [r["conname"] for r in names] == ["orgs_admin_user_id_fkey"]
    finally:
        await conn.close()
