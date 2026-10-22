"""docs/runbooks/restore.md must bring the lock-down back with the data.

The nightly dump has no GRANT/REVOKE (pg_dump --no-privileges), and a new
Supabase project's default privileges hand anon and authenticated every right
on every restored table and function. Until 2026-10-22 the runbook restored
`public` first (its foreign keys to auth.users failed on an empty auth.users),
never re-created the sign-up trigger on auth.users, and never re-applied the
REVOKEs of 017 and 022-025. Pinned here:

  * every migration that changes privileges or puts a trigger on `auth.*`
    is re-applied by the runbook's loop, in order, with the lock-down (025)
    last — a new migration of that kind fails this file until it is added;
  * auth data is restored before `public`;
  * the verification queries check table grants, the closed functions and
    the trigger.
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


def test_the_reapplied_migrations_exist_and_the_lockdown_runs_last():
    names = _reapplied()
    for name in names:
        assert (MIGRATIONS / f"{name}.sql").exists(), name
    assert names == sorted(names)
    assert names[-1] == "025_lock_down_client_access"


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
    for fn in ("register_device", "revoke_device", "report_phone", "handle_new_auth_user", "purge_old_audit_log"):
        assert f"'{fn}'" in text, fn
    assert "on_auth_user_created" in text
    assert "confrelid = 'auth.users'::regclass" in text
