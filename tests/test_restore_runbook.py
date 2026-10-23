"""docs/runbooks/restore.md must bring the lock-down back with the data.

The nightly dump has no GRANT/REVOKE (pg_dump --no-privileges), and a new
Supabase project's default privileges hand anon and authenticated every right
on every restored table and function. Until 2026-10-22 the runbook restored
`public` first (its foreign keys to auth.users failed on an empty auth.users),
never re-created the sign-up trigger on auth.users, and never re-applied the
REVOKEs of 017 and 022-025. Pinned here:

  * every migration that changes privileges or puts a trigger on `auth.*`
    is re-applied by the runbook's loop, in order, with the lock-down (025)
    after everything older and only migrations that grant clients nothing
    after it (027: functions for service_role) — a new migration of that
    kind fails this file until it is added;
  * auth data is restored before `public`, with triggers (and so foreign
    keys) off and in one transaction: the nightly dump is schema + data, and
    pg_dump orders TABLE DATA by foreign key only in a data-only dump, so
    auth.identities, sessions and refresh_tokens come before auth.users.
    Replayed as is, their COPY fails, pg_restore carries on, and they stay
    empty (reproduced with postgres:17 on 2026-10-22);
  * step 3 shows the dump's newest Auth migration, not the script's footer;
  * the verification queries check table grants, the closed functions, the
    trigger, and the auth rows sign-in needs (users, identities, sessions).
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = ROOT / "docs" / "runbooks" / "restore.md"
MIGRATIONS = ROOT / "supabase" / "migrations"

_PRIVILEGE_OR_AUTH_TRIGGER = re.compile(
    r"\bREVOKE\b|\bGRANT\b|ALTER DEFAULT PRIVILEGES"
    r"|CREATE TRIGGER\s+\w+\s+(?:AFTER|BEFORE|INSTEAD OF)\s[^;]*?\bON\s+auth\.",
    re.I,
)


def _sql(path: Path) -> str:
    sql = re.sub(r"/\*.*?\*/", "", path.read_text(encoding="utf-8"), flags=re.S)
    return re.sub(r"--[^\n]*", "", sql)


def _runbook() -> str:
    return RUNBOOK.read_text(encoding="utf-8")


def _reapplied() -> list[str]:
    loop = re.search(r"for f in (.*?); do", _runbook(), flags=re.S)
    assert loop, "restore.md lost its re-apply loop"
    return loop.group(1).replace("\\", " ").split()


def test_every_privilege_or_auth_trigger_migration_is_reapplied():
    needed = sorted(p.stem for p in MIGRATIONS.glob("*.sql") if _PRIVILEGE_OR_AUTH_TRIGGER.search(_sql(p)))
    assert {"010_auto_create_user_records", "025_lock_down_client_access"} <= set(needed)
    missing = sorted(set(needed) - set(_reapplied()))
    assert not missing, f"restore.md step 6 does not re-apply: {missing}"


_GRANT_TO_CLIENTS = re.compile(r"\bGRANT\b[^;]*\bTO\b[^;]*\b(anon|authenticated|PUBLIC)\b", re.I)


def test_the_reapplied_migrations_exist_and_nothing_after_the_lockdown_reopens_it():
    names = _reapplied()
    for name in names:
        assert (MIGRATIONS / f"{name}.sql").exists(), name
    assert names == sorted(names)
    after = names[names.index("025_lock_down_client_access") + 1:]
    reopening = [n for n in after if _GRANT_TO_CLIENTS.search(_sql(MIGRATIONS / f"{n}.sql"))]
    assert not reopening, f"re-applied after the lock-down but grant clients something: {reopening}"


def test_the_reopening_detector_sees_a_client_grant():
    assert _GRANT_TO_CLIENTS.search("GRANT EXECUTE ON FUNCTION public.f() TO service_role, authenticated;")
    assert not _GRANT_TO_CLIENTS.search("GRANT EXECUTE ON FUNCTION public.f() TO service_role;")
    assert not _GRANT_TO_CLIENTS.search("REVOKE ALL ON FUNCTION public.f() FROM PUBLIC, anon, authenticated;")


def test_the_detector_sees_an_auth_trigger_and_a_grant():
    assert _PRIVILEGE_OR_AUTH_TRIGGER.search("CREATE TRIGGER t AFTER INSERT ON auth.users FOR EACH ROW EXECUTE f();")
    assert _PRIVILEGE_OR_AUTH_TRIGGER.search("GRANT EXECUTE ON FUNCTION public.f() TO service_role;")
    assert not _PRIVILEGE_OR_AUTH_TRIGGER.search("CREATE TRIGGER t AFTER INSERT ON public.x FOR EACH ROW EXECUTE f();")


def test_auth_data_is_restored_before_public():
    text = _runbook()
    auth = text.index("pg_restore --data-only --no-owner --no-privileges -L auth.list")
    public = text.index("pg_restore --no-owner --schema=public")
    loop = text.index("for f in ")
    assert auth < public < loop


def test_the_auth_schema_migrations_table_is_left_alone():
    assert "grep -v ' schema_migrations '" in _runbook()


def test_the_checks_cover_grants_functions_and_the_trigger():
    text = _runbook()
    assert "has_table_privilege(r.role, c.oid" in text
    for fn in ("register_device", "revoke_device", "report_phone", "handle_new_auth_user", "purge_old_audit_log",
               "purge_auth_audit_log", "delete_auth_audit_log_for_users"):
        assert f"'{fn}'" in text, fn
    assert "on_auth_user_created" in text
    assert "confrelid = 'auth.users'::regclass" in text


def _step(n: int) -> str:
    text = _runbook()
    start = text.index(f"\n{n}. **")
    end = text.index(f"\n{n + 1}. **", start)
    return text[start:end]


def test_auth_data_loads_with_triggers_off_in_one_transaction():
    step = _step(4)
    assert "pg_restore --data-only --no-owner --no-privileges -L auth.list -f - db.dump" in step
    assert "SET session_replication_role = replica" in step
    assert "--single-transaction" in step
    assert "ON_ERROR_STOP=1" in step


def test_the_version_check_prints_the_newest_auth_migration():
    step = _step(3)
    assert "grep -E '^[0-9]{14}' | sort | tail -1" in step
    assert "| tail -3" not in step
    assert "select max(version) from auth.schema_migrations" in step


def test_the_counts_include_the_auth_rows_sign_in_needs():
    step = _step(7)
    for table in ("auth.users", "auth.identities", "auth.sessions", "public.users", "public.entitlements"):
        assert f"from {table})" in step, table
