"""Migration 027: Supabase Auth's own sign-in log is purged too.

GoTrue writes one row per sign-in, token refresh, sign-out and admin action
to auth.audit_log_entries: the account id, its email (or phone) and the IP
address. Nothing deleted those rows — not the 30-day account erase, not the
retention job — and the auth schema is not exposed through PostgREST. 027
adds two service-role-only SECURITY DEFINER functions:

  * purge_auth_audit_log(p_retention_days, p_dry_run) — rows older than the
    window (the retention job passes 730 days, the period the policy gives
    the security log); dry run (the default) only counts;
  * delete_auth_audit_log_for_users(p_user_ids) — every row about these
    accounts, as the actor (payload.actor_id) or as the subject of an admin
    action (payload.traits.user_id: the Admin API's own user_deleted row
    carries the account's email there).

CI has no database, so the SQL is checked statically (comments stripped, as
in tests/test_migrations_security.py). With MIGRATIONS_TEST_DATABASE_URL
pointing at a scratch Postgres — never a real project: the test drops and
recreates the `auth` schema and creates roles — 027 is applied the way
Supabase runs it (a non-superuser owner, Supabase's default EXECUTE grants)
and the functions are called as service_role and as the client roles.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "supabase" / "migrations"
MIGRATION = MIGRATIONS / "027_auth_audit_log_retention.sql"
PG_URL = os.environ.get("MIGRATIONS_TEST_DATABASE_URL", "")

NIL = "00000000-0000-0000-0000-000000000000"
PURGE_SIG = "public.purge_auth_audit_log(INTEGER, BOOLEAN)"
DELETE_SIG = "public.delete_auth_audit_log_for_users(UUID[])"


def _sql(path: Path) -> str:
    text = re.sub(r"/\*.*?\*/", "", path.read_text(encoding="utf-8"), flags=re.S)
    text = re.sub(r"--[^\n]*", "", text)
    return re.sub(r"\s+", " ", text).strip()


def _function(sql: str, name: str) -> str:
    m = re.search(rf"CREATE OR REPLACE FUNCTION public\.{name}\((.*?)\$\$(.*?)\$\$;", sql)
    assert m, f"{name} is not created"
    return m.group(1) + " $$ " + m.group(2)


def test_027_follows_026_and_has_its_own_number():
    numbers = sorted(int(p.name[:3]) for p in MIGRATIONS.glob("[0-9][0-9][0-9]_*.sql"))
    assert MIGRATION.exists()
    assert 26 in numbers and numbers.count(27) == 1


def test_027_runs_in_one_transaction():
    sql = _sql(MIGRATION)
    assert sql.startswith("BEGIN;") and sql.endswith("COMMIT;")


@pytest.mark.parametrize("name", ["purge_auth_audit_log", "delete_auth_audit_log_for_users"])
def test_027_functions_are_security_definer_with_a_pinned_search_path(name):
    fn = _function(_sql(MIGRATION), name)
    head = fn.split("$$")[0]
    assert "SECURITY DEFINER" in head
    assert "SET search_path = public, pg_temp" in head
    # The table is named in full, never through the search path.
    assert "auth.audit_log_entries" in fn
    assert not re.search(r"(?<!auth\.)\baudit_log_entries\b", fn)


def test_027_only_service_role_may_execute():
    sql = _sql(MIGRATION)
    for sig in (PURGE_SIG, DELETE_SIG):
        assert f"REVOKE ALL ON FUNCTION {sig} FROM PUBLIC, anon, authenticated;" in sql
        assert f"GRANT EXECUTE ON FUNCTION {sig} TO service_role;" in sql
    grants = re.findall(r"GRANT [^;]*;", sql)
    assert all("TO service_role;" in g for g in grants), grants


def test_027_purge_counts_unless_told_to_delete():
    fn = _function(_sql(MIGRATION), "purge_auth_audit_log")
    assert re.search(r"p_retention_days INTEGER, p_dry_run BOOLEAN DEFAULT true", fn)
    assert "p_retention_days IS NULL OR p_retention_days < 1" in fn
    assert "IF p_dry_run IS DISTINCT FROM false THEN" in fn
    assert re.search(r"DELETE FROM auth\.audit_log_entries WHERE created_at < v_cutoff;", fn)


def test_027_user_delete_matches_actor_and_traits_and_refuses_the_nil_id():
    fn = _function(_sql(MIGRATION), "delete_auth_audit_log_for_users")
    assert "payload ->> 'actor_id' = ANY (v_ids)" in fn
    assert "payload -> 'traits' ->> 'user_id' = ANY (v_ids)" in fn
    # The nil UUID is the actor of every service-role action, nobody's account.
    assert f"'{NIL}'::uuid" in fn


def test_027_checks_it_can_reach_the_table_before_creating_anything():
    sql = _sql(MIGRATION)
    preflight = sql.index("to_regclass('auth.audit_log_entries')")
    assert "has_table_privilege('auth.audit_log_entries', 'DELETE')" in sql
    assert preflight < sql.index("CREATE OR REPLACE FUNCTION")


def test_027_touches_nothing_else():
    sql = _sql(MIGRATION)
    assert not re.search(r"\b(CREATE POLICY|DROP POLICY|CREATE TABLE|DROP TABLE|ALTER TABLE|CREATE INDEX)\b", sql, re.I)
    created = set(re.findall(r"CREATE OR REPLACE FUNCTION ([\w.]+)\(", sql))
    assert created == {"public.purge_auth_audit_log", "public.delete_auth_audit_log_for_users"}


def test_the_api_calls_the_functions_by_the_names_027_declares():
    """PostgREST matches an RPC by function and argument names: a rename on
    either side would turn every call into a 404."""
    from api.services import account_purge, retention

    sql = _sql(MIGRATION)
    assert retention.AUTH_AUDIT_PURGE_FN == "purge_auth_audit_log"
    assert account_purge.AUTH_AUDIT_DELETE_FN == "delete_auth_audit_log_for_users"
    assert set(retention.auth_audit_args("on")) == {"p_retention_days", "p_dry_run"}
    assert "p_user_ids UUID[]" in _function(sql, account_purge.AUTH_AUDIT_DELETE_FN)


# ─── The real thing, on a scratch Postgres ───────────────────────

_MIGRATOR = "cleanway_test_migrator"
_NO_AUTH = "cleanway_test_no_auth"


async def _fresh_auth(conn) -> None:
    """GoTrue's table (00_init_auth_schema + 20220614074223_add_ip_address)
    owned by another role, and a non-superuser migrator that, like Supabase's
    `postgres`, may read and delete its rows; Supabase's default EXECUTE
    grants on new functions in public."""
    await conn.execute(
        f"""
        DROP FUNCTION IF EXISTS public.purge_auth_audit_log(integer, boolean);
        DROP FUNCTION IF EXISTS public.delete_auth_audit_log_for_users(uuid[]);
        DROP SCHEMA IF EXISTS auth CASCADE;
        DO $$
        DECLARE r text;
        BEGIN
            FOREACH r IN ARRAY ARRAY['anon', 'authenticated', 'service_role', 'supabase_auth_admin',
                                     '{_MIGRATOR}', '{_NO_AUTH}'] LOOP
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
                    EXECUTE format('CREATE ROLE %I NOLOGIN', r);
                END IF;
            END LOOP;
        END $$;
        CREATE SCHEMA auth AUTHORIZATION supabase_auth_admin;
        CREATE TABLE auth.audit_log_entries (
            instance_id uuid NULL,
            id uuid NOT NULL,
            payload json NULL,
            created_at timestamptz NULL,
            ip_address varchar(64) NOT NULL DEFAULT '',
            CONSTRAINT audit_log_entries_pkey PRIMARY KEY (id)
        );
        ALTER TABLE auth.audit_log_entries OWNER TO supabase_auth_admin;
        GRANT USAGE ON SCHEMA auth TO {_MIGRATOR}, {_NO_AUTH};
        GRANT SELECT, DELETE ON auth.audit_log_entries TO {_MIGRATOR};
        GRANT SELECT ON auth.audit_log_entries TO {_NO_AUTH};
        GRANT CREATE, USAGE ON SCHEMA public TO {_MIGRATOR}, {_NO_AUTH};
        GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
        ALTER DEFAULT PRIVILEGES FOR ROLE {_MIGRATOR} IN SCHEMA public
            GRANT EXECUTE ON FUNCTIONS TO anon, authenticated, service_role;
        """
    )


async def _apply(conn, role: str = _MIGRATOR) -> None:
    await conn.execute(f"SET ROLE {role}")
    try:
        await conn.execute(MIGRATION.read_text(encoding="utf-8"))
    except Exception:
        await conn.execute("ROLLBACK")  # the script's BEGIN is left aborted
        raise
    finally:
        await conn.execute("RESET ROLE")


async def _entry(conn, payload, age_days: float, ip: str = "203.0.113.7") -> None:
    await conn.execute(
        "INSERT INTO auth.audit_log_entries (id, payload, created_at, ip_address) "
        "VALUES (gen_random_uuid(), $1::json, now() - make_interval(secs => $2::float8 * 86400), $3)",
        payload if payload is None or isinstance(payload, str) else json.dumps(payload),
        float(age_days),
        ip,
    )


async def _as(conn, role: str, query: str, *args):
    async with conn.transaction():
        await conn.execute(f"SET LOCAL ROLE {role}")
        return await conn.fetchval(query, *args)


needs_pg = pytest.mark.skipif(not PG_URL, reason="MIGRATIONS_TEST_DATABASE_URL not set")


@pytest.mark.asyncio
@needs_pg
async def test_027_on_postgres_purge_counts_then_deletes_only_rows_past_the_window():
    import asyncpg

    conn = await asyncpg.connect(PG_URL)
    try:
        await _fresh_auth(conn)
        for _ in range(2):  # re-running is safe
            await _apply(conn)
        for age in (1, 729.9, 730.1, 1000):
            await _entry(conn, {"actor_id": "11111111-1111-1111-1111-111111111111", "action": "login"}, age)

        call = "SELECT public.purge_auth_audit_log($1, $2)"
        assert await _as(conn, "service_role", call, 730, True) == 2
        assert await _as(conn, "service_role", "SELECT public.purge_auth_audit_log(730)") == 2  # default: count
        assert await conn.fetchval("SELECT count(*) FROM auth.audit_log_entries") == 4
        assert await _as(conn, "service_role", call, 730, False) == 2
        assert await conn.fetchval("SELECT count(*) FROM auth.audit_log_entries") == 2
        assert await conn.fetchval("SELECT min(created_at) > now() - interval '730 days' FROM auth.audit_log_entries")
        assert await _as(conn, "service_role", call, 730, False) == 0

        for bad in (0, -1, None):
            with pytest.raises(asyncpg.InvalidParameterValueError):
                await _as(conn, "service_role", call, bad, False)
        assert await conn.fetchval("SELECT count(*) FROM auth.audit_log_entries") == 2
    finally:
        await conn.close()


@pytest.mark.asyncio
@needs_pg
async def test_027_on_postgres_a_dry_run_works_read_only_and_a_delete_cannot():
    """The retention job's dry run calls the function with GET, which
    PostgREST runs in a READ ONLY transaction: a dry run can't delete even
    if it asked to."""
    import asyncpg

    conn = await asyncpg.connect(PG_URL)
    try:
        await _fresh_auth(conn)
        await _apply(conn)
        await _entry(conn, {"actor_id": "11111111-1111-1111-1111-111111111111"}, 800)
        async with conn.transaction(readonly=True):
            await conn.execute("SET LOCAL ROLE service_role")
            assert await conn.fetchval("SELECT public.purge_auth_audit_log(730, true)") == 1
        with pytest.raises(asyncpg.ReadOnlySQLTransactionError):
            async with conn.transaction(readonly=True):
                await conn.execute("SET LOCAL ROLE service_role")
                await conn.fetchval("SELECT public.purge_auth_audit_log(730, false)")
        assert await conn.fetchval("SELECT count(*) FROM auth.audit_log_entries") == 1
    finally:
        await conn.close()


@pytest.mark.asyncio
@needs_pg
async def test_027_on_postgres_deletes_every_row_about_the_accounts_and_nothing_else():
    import asyncpg

    a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    c = "cccccccc-cccc-cccc-cccc-cccccccccccc"
    conn = await asyncpg.connect(PG_URL)
    try:
        await _fresh_auth(conn)
        await _apply(conn)
        # What GoTrue writes (internal/models/audit_log_entry.go, api/admin.go).
        user = {"actor_via_sso": False, "log_type": "account"}
        await _entry(conn, {**user, "actor_id": a, "actor_username": "a@example.com", "action": "login",
                            "traits": {"provider": "email"}}, 3)
        await _entry(conn, {**user, "actor_id": a, "actor_username": "a@example.com", "action": "token_refreshed",
                            "log_type": "token"}, 2)
        await _entry(conn, {"actor_id": NIL, "actor_username": "service_role", "action": "user_deleted",
                            "log_type": "team", "traits": {"user_id": a, "user_email": "a@example.com",
                                                           "user_phone": ""}}, 0, ip="")
        await _entry(conn, {**user, "actor_id": c, "actor_username": "c@example.com", "action": "logout"}, 1)
        await _entry(conn, {**user, "actor_id": b, "actor_username": "b@example.com", "action": "login"}, 1)
        await _entry(conn, {"actor_id": NIL, "actor_username": "service_role", "action": "user_modified",
                            "traits": {"user_id": b, "user_email": "b@example.com"}}, 1, ip="")
        # Shapes a delete must step over without failing.
        for odd in (None, "[1, 2]", '"text"', '{"traits": "none"}', '{"actor_id": 42}'):
            await _entry(conn, odd, 1)

        call = "SELECT public.delete_auth_audit_log_for_users($1::uuid[])"
        assert await _as(conn, "service_role", call, [a, c]) == 4
        left = await conn.fetch(
            "SELECT payload->>'actor_id' AS actor, payload->'traits'->>'user_id' AS subject "
            "FROM auth.audit_log_entries WHERE payload::text LIKE '%actor_id%'"
        )
        assert sorted((r["actor"], r["subject"]) for r in left) == sorted([(b, None), (NIL, b), ("42", None)])
        assert await conn.fetchval("SELECT count(*) FROM auth.audit_log_entries") == 7
        assert await _as(conn, "service_role", call, [a]) == 0  # idempotent
        assert await _as(conn, "service_role", call, []) == 0

        for bad in ([NIL], [b, NIL], None):
            with pytest.raises(asyncpg.InvalidParameterValueError):
                await _as(conn, "service_role", call, bad)
        assert await conn.fetchval("SELECT count(*) FROM auth.audit_log_entries") == 7
    finally:
        await conn.close()


@pytest.mark.asyncio
@needs_pg
async def test_027_on_postgres_clients_cannot_call_either_function():
    import asyncpg

    conn = await asyncpg.connect(PG_URL)
    try:
        await _fresh_auth(conn)
        await _apply(conn)
        for sig in (PURGE_SIG, DELETE_SIG):
            for role in ("anon", "authenticated", _NO_AUTH):
                assert await conn.fetchval("SELECT has_function_privilege($1, $2, 'EXECUTE')", role, sig) is False
            assert await conn.fetchval("SELECT has_function_privilege('service_role', $1, 'EXECUTE')", sig) is True
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await _as(conn, "anon", "SELECT public.purge_auth_audit_log(1, false)")
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await _as(conn, "authenticated", "SELECT public.delete_auth_audit_log_for_users(ARRAY[gen_random_uuid()])")
    finally:
        await conn.close()


@pytest.mark.asyncio
@needs_pg
async def test_027_on_postgres_fails_for_a_role_that_cannot_delete_the_rows():
    """A function owned by such a role would fail on every call; the
    migration refuses instead, before creating anything."""
    import asyncpg

    conn = await asyncpg.connect(PG_URL)
    try:
        await _fresh_auth(conn)
        with pytest.raises(asyncpg.RaiseError, match="DELETE"):
            await _apply(conn, role=_NO_AUTH)
        assert await conn.fetchval("SELECT to_regprocedure('public.purge_auth_audit_log(integer, boolean)')") is None
    finally:
        await conn.close()
