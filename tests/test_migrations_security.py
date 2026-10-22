"""Static checks on supabase/migrations/ — CI has no database, so the SQL is
parsed instead (comments stripped).

What is pinned:
  * every table a migration creates has row-level security switched on;
  * migration 025 takes every table privilege away from anon and
    authenticated (and from tables created later), and no later migration
    hands one back — clients reach data only through the API's service role;
  * after 025, the client-facing policies on users / families / orgs /
    org_members / user_settings / weekly_aggregates are read-only, orgs no
    longer recurse through org_members, sms_reports is not world-readable,
    family_alerts checks sender and recipient, and the trigger / RPC
    functions are not executable by anon or authenticated.

025 was also applied to a scratch Postgres 15 with Supabase's roles and
default privileges stubbed (2026-10-14): 0 table/column privileges left for
anon/authenticated, UPDATE users/families → permission denied, orgs readable
by a member without 42P17, service_role unaffected.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

MIGRATIONS = Path(__file__).resolve().parents[1] / "supabase" / "migrations"
LOCKDOWN = "025_lock_down_client_access.sql"


def _strip_comments(sql: str) -> str:
    sql = re.sub(r"/\*.*?\*/", "", sql, flags=re.S)
    return re.sub(r"--[^\n]*", "", sql)


def _ws(sql: str) -> str:
    return re.sub(r"\s+", " ", sql)


def _migrations() -> list[Path]:
    return sorted(MIGRATIONS.glob("*.sql"))


def _sql(path: Path) -> str:
    return _ws(_strip_comments(path.read_text(encoding="utf-8")))


@pytest.fixture(scope="module")
def lockdown() -> str:
    path = MIGRATIONS / LOCKDOWN
    assert path.exists(), f"{LOCKDOWN} is missing"
    return _sql(path)


def _after_lockdown() -> list[Path]:
    return [p for p in _migrations() if p.name > LOCKDOWN]


# ─── RLS on every table ───────────────────────────────────────────


def test_every_created_table_has_row_level_security_enabled():
    created: dict[str, str] = {}
    enabled: set[str] = set()
    for path in _migrations():
        sql = _sql(path)
        for name in re.findall(
            r"CREATE TABLE (?:IF NOT EXISTS )?(?:public\.)?\"?(\w+)\"?", sql, flags=re.I
        ):
            created.setdefault(name.lower(), path.name)
        for name in re.findall(
            r"ALTER TABLE (?:IF EXISTS )?(?:ONLY )?(?:public\.)?\"?(\w+)\"? ENABLE ROW LEVEL SECURITY",
            sql,
            flags=re.I,
        ):
            enabled.add(name.lower())
    assert created, "no CREATE TABLE found — is the parser broken?"
    missing = {t: f for t, f in created.items() if t not in enabled}
    assert not missing, f"tables without ENABLE ROW LEVEL SECURITY: {missing}"


def test_the_rls_parser_catches_a_table_without_rls(tmp_path):
    # Guard the guard: the regexes must actually see a CREATE TABLE.
    sql = _ws(_strip_comments("CREATE TABLE IF NOT EXISTS public.leaky (id int); -- no RLS"))
    assert re.findall(r"CREATE TABLE (?:IF NOT EXISTS )?(?:public\.)?\"?(\w+)\"?", sql, flags=re.I) == ["leaky"]


# ─── 025: privileges ──────────────────────────────────────────────


def test_lockdown_revokes_every_table_privilege_from_clients(lockdown):
    assert "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon, authenticated;" in lockdown
    assert "REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon, authenticated;" in lockdown
    assert (
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated;"
        in lockdown
    )
    assert (
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM anon, authenticated;"
        in lockdown
    )


_TABLE_GRANT_TO_CLIENTS = re.compile(
    r"GRANT [^;]*? ON (?!FUNCTION\b)(?!ALL FUNCTIONS\b)(?!SCHEMA\b)[^;]*? TO [^;]*\b(anon|authenticated|PUBLIC)\b",
    re.I,
)


def test_lockdown_grants_clients_no_table_privilege(lockdown):
    assert not _TABLE_GRANT_TO_CLIENTS.search(lockdown)


def test_no_later_migration_reopens_table_privileges_to_clients():
    # Clients (mobile, landing, extensions) call no PostgREST table: if one
    # ever must, grant the exact columns here deliberately and update this test.
    offenders = [p.name for p in _after_lockdown() if _TABLE_GRANT_TO_CLIENTS.search(_sql(p))]
    assert not offenders, f"migrations granting table privileges to anon/authenticated: {offenders}"


def test_the_grant_detector_sees_a_reopening_grant():
    assert _TABLE_GRANT_TO_CLIENTS.search("GRANT UPDATE (email) ON public.users TO authenticated;")
    assert _TABLE_GRANT_TO_CLIENTS.search("GRANT SELECT ON ALL TABLES IN SCHEMA public TO anon;")
    assert not _TABLE_GRANT_TO_CLIENTS.search(
        "GRANT EXECUTE ON FUNCTION public.is_org_member(UUID) TO authenticated, service_role;"
    )


# ─── 025: policies ────────────────────────────────────────────────

READ_ONLY_TABLES = ("users", "families", "user_settings", "weekly_aggregates")


def test_lockdown_drops_every_write_policy_on_owner_tables(lockdown):
    # By catalogue, not by name: 006 and 016 left duplicates under two names.
    loop = re.search(
        r"FROM pg_policies WHERE schemaname = 'public' AND tablename IN \(([^)]*)\) AND cmd <> 'SELECT'",
        lockdown,
    )
    assert loop, "the non-SELECT policy drop loop is missing"
    tables = {t.strip(" '") for t in loop.group(1).split(",")}
    assert tables == set(READ_ONLY_TABLES)
    assert "EXECUTE format('DROP POLICY %I ON public.%I', p.policyname, p.tablename);" in lockdown


def _created_policies(sql: str) -> list[tuple[str, str, str]]:
    """(name, table, command) for every CREATE POLICY; command defaults to ALL."""
    out = []
    for name, table, rest in re.findall(
        r'CREATE POLICY "([^"]+)" ON (?:public\.)?(\w+)(.*?);', sql, flags=re.I
    ):
        m = re.search(r"\bFOR (ALL|SELECT|INSERT|UPDATE|DELETE)\b", rest, flags=re.I)
        out.append((name, table.lower(), (m.group(1) if m else "ALL").upper()))
    return out


def test_policies_created_from_025_on_are_read_only_on_owner_tables():
    for path in [MIGRATIONS / LOCKDOWN, *_after_lockdown()]:
        for name, table, cmd in _created_policies(_sql(path)):
            if table in (*READ_ONLY_TABLES, "orgs", "org_members"):
                assert cmd == "SELECT", f"{path.name}: {name!r} on {table} is {cmd}"


def test_orgs_policies_are_replaced_without_recursion(lockdown):
    assert re.search(
        r"FROM pg_policies WHERE schemaname = 'public' AND tablename IN \('orgs', 'org_members'\) LOOP",
        lockdown,
    )
    fn = re.search(r"CREATE OR REPLACE FUNCTION public\.is_org_member\(org UUID\)(.*?)\$\$;", lockdown)
    assert fn and "SECURITY DEFINER" in fn.group(1) and "SET search_path = public, pg_temp" in fn.group(1)
    assert "REVOKE ALL ON FUNCTION public.is_org_member(UUID) FROM PUBLIC, anon;" in lockdown
    org_policies = [p for p in _created_policies(lockdown) if p[1] in ("orgs", "org_members")]
    assert org_policies
    # The orgs policy asks the SECURITY DEFINER helper; the org_members one
    # never looks at orgs — no policy can re-enter the other table.
    orgs_sql = re.search(r'CREATE POLICY "[^"]+" ON public\.orgs (.*?);', lockdown).group(1)
    assert "is_org_member(id)" in orgs_sql and "org_members" not in orgs_sql
    members_sql = re.search(r'CREATE POLICY "[^"]+" ON public\.org_members (.*?);', lockdown).group(1)
    assert "orgs" not in members_sql.replace("org_members", "")


def test_sms_reports_is_no_longer_world_readable(lockdown):
    assert 'DROP POLICY IF EXISTS "sms_reports_public_read" ON public.sms_reports;' in lockdown
    assert 'DROP POLICY IF EXISTS "sms_reports_authenticated_insert" ON public.sms_reports;' in lockdown
    insert = re.search(r'CREATE POLICY "sms_reports_own_insert" ON public\.sms_reports (.*?);', lockdown)
    assert insert and "reporter_user_id = (SELECT auth.uid())" in insert.group(1)
    for path in [MIGRATIONS / LOCKDOWN, *_after_lockdown()]:
        assert not re.search(
            r'CREATE POLICY "[^"]+" ON public\.sms_reports FOR SELECT USING \(true\)', _sql(path), flags=re.I
        ), path.name


def test_family_alerts_check_sender_and_recipient(lockdown):
    for old in ("Family members insert alerts", "Recipients read own alerts"):
        assert f'DROP POLICY IF EXISTS "{old}" ON public.family_alerts;' in lockdown
    insert = re.search(
        r'CREATE POLICY "Senders insert alerts to family members" ON public\.family_alerts FOR INSERT WITH CHECK \((.*?)\);',
        lockdown,
    )
    assert insert
    assert "sender_user_id = (SELECT auth.uid())" in insert.group(1)
    assert "shares_family_with(family_id, recipient_user_id)" in insert.group(1)
    select = re.search(
        r'CREATE POLICY "Recipients and senders read own alerts" ON public\.family_alerts FOR SELECT USING \((.*?)\);',
        lockdown,
    )
    assert select
    assert "recipient_user_id = (SELECT auth.uid())" in select.group(1)
    assert "sender_user_id = (SELECT auth.uid())" in select.group(1)
    fn = re.search(r"CREATE OR REPLACE FUNCTION public\.shares_family_with\(fam UUID, other UUID\)(.*?)\$\$;", lockdown)
    assert fn and "SECURITY DEFINER" in fn.group(1) and "me.user_id = (SELECT auth.uid())" in fn.group(1)
    assert "REVOKE ALL ON FUNCTION public.shares_family_with(UUID, UUID) FROM PUBLIC, anon;" in lockdown


def test_trigger_and_rpc_functions_are_not_client_callable(lockdown):
    assert "REVOKE ALL ON FUNCTION public.handle_new_auth_user() FROM PUBLIC, anon, authenticated;" in lockdown
    assert (
        "REVOKE ALL ON FUNCTION public.report_phone(TEXT, TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;"
        in lockdown
    )
    assert "GRANT EXECUTE ON FUNCTION public.report_phone(TEXT, TEXT, TEXT, TEXT) TO service_role;" in lockdown


# SECURITY DEFINER functions that signed-in clients must be able to run:
# RLS policies call them on the caller's behalf.
_CLIENT_CALLABLE_DEFINERS = {"is_org_member", "shares_family_with"}


def _security_definer_functions() -> dict[str, str]:
    found: dict[str, str] = {}
    for path in _migrations():
        sql = _sql(path)
        for m in re.finditer(r"CREATE (?:OR REPLACE )?FUNCTION public\.(\w+)\s*\((.*?)\$\$", sql, flags=re.I | re.S):
            if re.search(r"\bSECURITY DEFINER\b", m.group(2), flags=re.I):
                found.setdefault(m.group(1).lower(), path.name)
    return found


def _revoked_from(name: str) -> set[str]:
    roles: set[str] = set()
    for path in _migrations():
        for m in re.finditer(rf"REVOKE ALL ON FUNCTION public\.{name}\b[^;]*? FROM ([^;]*);", _sql(path), flags=re.I):
            roles |= {r.strip().lower() for r in m.group(1).split(",")}
    return roles


def test_every_security_definer_function_is_revoked_from_clients():
    """Supabase grants EXECUTE on every new function to anon and
    authenticated explicitly, so `REVOKE ... FROM PUBLIC` alone leaves a
    SECURITY DEFINER function callable by anyone through /rest/v1/rpc. 017's
    purge_old_audit_log did exactly that (any visitor could have emptied
    audit_log); it has never been applied to production (data-retention.md)."""
    definers = _security_definer_functions()
    assert {"register_device", "handle_new_auth_user", "purge_old_audit_log"} <= set(definers)
    open_to_clients = {}
    for name, where in definers.items():
        revoked = _revoked_from(name)
        needed = {"anon"} if name in _CLIENT_CALLABLE_DEFINERS else {"anon", "authenticated"}
        if not needed <= revoked:
            open_to_clients[name] = (where, sorted(needed - revoked))
    assert not open_to_clients, f"SECURITY DEFINER functions still executable by clients: {open_to_clients}"


def test_lockdown_runs_in_one_transaction(lockdown):
    assert lockdown.strip().startswith("BEGIN;") and lockdown.strip().endswith("COMMIT;")
