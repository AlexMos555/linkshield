"""`python -m api.services.export --user <uuid|email>` — the operator's way to
answer an access request that arrives by email (docs/runbooks/data-requests.md).

Supabase is tests/supabase_rest_stub.FakeSupabase: the account lookup and
every table read are recorded, so the tests pin that the export is the same
one the person downloads, scoped to the one account found.
"""
from __future__ import annotations

import json

import httpx
import pytest

from api.services import export
from tests.supabase_rest_stub import FakeSupabase

ACCOUNT = "55555555-5555-4555-8555-555555555555"


@pytest.fixture
def sb(monkeypatch) -> FakeSupabase:
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "fake-key", raising=False)
    stub = FakeSupabase()
    monkeypatch.setattr(httpx, "AsyncClient", stub.client())
    return stub


def _lookups(sb: FakeSupabase) -> list[dict]:
    return [c for c in sb.to("GET", "/rest/v1/users") if c["params"].get("select") == "id,email"]


def test_export_by_email_finds_the_account_and_prints_its_export(sb, capsys):
    sb.on("GET", "/rest/v1/users", body=[{"id": ACCOUNT, "email": "person@example.com"}])

    assert export.main(["--user", "  Person@Example.com "]) == 0

    (lookup,) = _lookups(sb)
    assert lookup["params"]["email"] == "eq.person@example.com"
    body = json.loads(capsys.readouterr().out)
    assert body["user_id"] == ACCOUNT and body["email"] == "person@example.com"
    assert set(body["tables"]) == {key for key, *_ in export.EXPORT_TABLES}
    reads = [c for c in sb.calls if c["params"].get("limit") == str(export.EXPORT_ROW_CAP)]
    assert len(reads) == len(export.EXPORT_TABLES)
    for c in reads:
        assert [v for v in c["params"].values() if v.startswith("eq.")] == [f"eq.{ACCOUNT}"]


def test_export_by_account_id_writes_a_file(sb, tmp_path, capsys):
    sb.on("GET", "/rest/v1/users", body=[{"id": ACCOUNT, "email": "person@example.com"}])
    sb.on("GET", "/rest/v1/audit_log", status=500)
    out = tmp_path / "export.json"

    assert export.main(["--user", ACCOUNT.upper(), "--out", str(out)]) == 0

    (lookup,) = _lookups(sb)
    assert lookup["params"]["id"] == f"eq.{ACCOUNT}"
    body = json.loads(out.read_text(encoding="utf-8"))
    assert body["tables"]["audit_log"] == {"error": "upstream returned 500"}
    err = capsys.readouterr().err
    assert "audit_log" in err and str(out) in err


def test_no_such_account_exits_1_and_reads_nothing_else(sb, capsys):
    sb.on("GET", "/rest/v1/users", body=[])
    assert export.main(["--user", "nobody@example.com"]) == 1
    assert "no account" in capsys.readouterr().err
    assert len(sb.calls) == 1


@pytest.mark.parametrize("identifier", ["not-an-id", "12345", ""])
def test_neither_an_id_nor_an_email_exits_2_without_a_query(sb, identifier, capsys):
    assert export.main(["--user", identifier]) == 2
    assert sb.calls == []
    assert "uuid" in capsys.readouterr().err


@pytest.mark.parametrize("failure", [{"status": 503}, {"exc": httpx.ConnectError("down")}])
def test_lookup_failure_exits_2(sb, failure, capsys):
    sb.on("GET", "/rest/v1/users", **failure)
    assert export.main(["--user", ACCOUNT]) == 2
    assert "lookup" in capsys.readouterr().err


def test_two_rows_for_one_lookup_is_no_answer(sb):
    sb.on("GET", "/rest/v1/users", body=[{"id": ACCOUNT}, {"id": "other"}])
    assert export.main(["--user", ACCOUNT]) == 1


def test_without_a_database_exits_2(monkeypatch, capsys):
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "", raising=False)
    assert export.main(["--user", ACCOUNT]) == 2
    assert "not configured" in capsys.readouterr().err
