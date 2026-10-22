"""Billing plumbing: the runtime context (memory vs Postgres), the migration runner, the lazily
built FastAPI context, the HTTP edges of /billing/v1 driven in-loop, MIXPLAT's real HTTP
transport (timeouts, 5xx, non-JSON) and malformed device passes.
"""
from __future__ import annotations

import asyncio
import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

from api.billing import bootstrap, deps, migrate
from api.billing.entitlement import Keyring, PassClaims, PassInvalid, Signer, generate_keypair
from api.billing.models import EntitlementSource, LapsePolicy, ProtectionMode
from api.billing.mount import mount_billing
from api.billing.partner import partner_signature
from api.billing.providers.base import EventKind, ProviderError, ProviderUnavailable
from api.billing.providers.mixplat import MixplatProvider, md5_signature, parse_payment_status
from api.billing.store.memory import MemoryStore
from api.config import ConfigError
from tests.billing.conftest import make_settings

CONSENT = "ru/v1"


# ── bootstrap: memory:// vs Postgres ──


@pytest.mark.asyncio
async def test_memory_dsn_opens_an_in_memory_store():
    assert isinstance(await bootstrap.open_store("memory://"), MemoryStore)


@pytest.mark.asyncio
async def test_any_other_dsn_opens_postgres(monkeypatch):
    from api.billing.store import postgres

    seen = []

    async def connect(cls, dsn, **kwargs):
        seen.append(dsn)
        return "pg-store"

    monkeypatch.setattr(postgres.PostgresStore, "connect", classmethod(connect))
    assert await bootstrap.open_store("postgresql://billing@db/billing") == "pg-store"
    assert seen == ["postgresql://billing@db/billing"]


@pytest.mark.asyncio
async def test_runtime_context_has_the_catalogue_and_the_providers_settings_allow():
    ctx = await bootstrap.build_runtime_context(make_settings())
    assert isinstance(ctx.store, MemoryStore)
    assert set(ctx.providers) == {"promo", "t2_direct", "fake"}
    async with ctx.store.transaction() as tx:
        stored = {p.code.value for p in await tx.list_plans()}
    assert stored == {"solo", "family3", "family5"}


@pytest.mark.asyncio
async def test_runtime_context_refuses_bad_settings_before_opening_anything(monkeypatch):
    async def must_not_open(dsn):
        raise AssertionError("opened a store with invalid settings")

    monkeypatch.setattr(bootstrap, "open_store", must_not_open)
    with pytest.raises(ConfigError):
        await bootstrap.build_runtime_context(make_settings(billing_hmac_key=""))


# ── migrate: in order, once each, one transaction per file ──


class FakeConn:
    """Just enough of asyncpg.Connection: execute / fetch / transaction / close."""

    def __init__(self, applied=(), fail_on=None):
        self.applied = list(applied)
        self.fail_on = fail_on
        self.log = []
        self.closed = False
        self._tx = None

    async def execute(self, sql, *args):
        if self.fail_on and self.fail_on in sql:
            raise RuntimeError("syntax error")
        self.log.append(("execute", sql.strip().split("\n")[0][:60], args))
        if sql.startswith("INSERT INTO billing_schema_migrations"):
            self._tx.append(args[0])

    async def fetch(self, sql):
        return [{"name": n} for n in self.applied]

    def transaction(self):
        conn = self

        class _Tx:
            async def __aenter__(self):
                conn._tx = []
                conn.log.append(("begin",))

            async def __aexit__(self, exc_type, exc, tb):
                if exc_type is None:
                    conn.applied.extend(conn._tx)
                    conn.log.append(("commit",))
                else:
                    conn.log.append(("rollback",))
                conn._tx = None
                return False

        return _Tx()

    async def close(self):
        self.closed = True


def _migrations(tmp_path: Path) -> Path:
    (tmp_path / "002_second.sql").write_text("CREATE TABLE b ();", encoding="utf-8")
    (tmp_path / "001_first.sql").write_text("CREATE TABLE a ();", encoding="utf-8")
    (tmp_path / "010_third.sql").write_text("CREATE TABLE c ();", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("not a migration", encoding="utf-8")
    (tmp_path / "999_dir.sql").mkdir()
    return tmp_path


def test_the_shipped_migrations_are_found_in_order():
    names = [p.name for p in migrate.migration_files()]
    assert names == sorted(names) and names[0].startswith("001_")


@pytest.mark.asyncio
async def test_migrations_apply_in_lexical_order_each_in_its_own_transaction(tmp_path):
    conn = FakeConn()
    applied = await migrate.apply_migrations(conn, _migrations(tmp_path))
    assert applied == ["001_first.sql", "002_second.sql", "010_third.sql"]
    assert conn.applied == applied
    assert conn.log[0][1].startswith("CREATE TABLE IF NOT EXISTS billing_schema_migrations")
    assert [e[0] for e in conn.log[1:]] == ["begin", "execute", "execute", "commit"] * 3
    # Running again applies nothing.
    assert await migrate.apply_migrations(conn, tmp_path) == []


@pytest.mark.asyncio
async def test_already_applied_files_are_skipped(tmp_path):
    conn = FakeConn(applied=["001_first.sql"])
    assert await migrate.apply_migrations(conn, _migrations(tmp_path)) == ["002_second.sql", "010_third.sql"]


@pytest.mark.asyncio
async def test_a_failing_file_rolls_back_and_stops_the_run(tmp_path):
    conn = FakeConn(fail_on="CREATE TABLE b")
    with pytest.raises(RuntimeError):
        await migrate.apply_migrations(conn, _migrations(tmp_path))
    assert conn.applied == ["001_first.sql"]          # 002 rolled back, 010 never attempted
    assert conn.log[-1] == ("rollback",)
    assert not any("CREATE TABLE c" in str(e) for e in conn.log)


@pytest.mark.asyncio
async def test_migrate_closes_the_connection_even_on_failure(monkeypatch):
    import asyncpg

    conn = FakeConn(fail_on="CREATE")
    seen = []

    async def connect(dsn):
        seen.append(dsn)
        return conn

    monkeypatch.setattr(asyncpg, "connect", connect)
    with pytest.raises(RuntimeError):
        await migrate.migrate("postgresql://x/billing")
    assert seen == ["postgresql://x/billing"] and conn.closed is True


def test_cli_needs_a_database_url(monkeypatch, capsys):
    import api.billing.settings as billing_settings

    monkeypatch.setattr(billing_settings, "get_billing_settings", lambda: make_settings(database_url_billing=""))
    assert migrate.main(["migrate"]) == 2
    assert "DATABASE_URL_BILLING is not set" in capsys.readouterr().err


def test_cli_reports_what_it_applied(monkeypatch, capsys):
    import api.billing.settings as billing_settings

    runs = iter([["001_billing_schema.sql"], []])
    dsns = []

    async def fake_migrate(dsn):
        dsns.append(dsn)
        return next(runs)

    monkeypatch.setattr(migrate, "migrate", fake_migrate)
    monkeypatch.setattr(billing_settings, "get_billing_settings",
                        lambda: make_settings(database_url_billing="postgresql://env/billing"))
    assert migrate.main(["migrate", "postgresql://argv/billing"]) == 0
    assert "applied: 001_billing_schema.sql" in capsys.readouterr().out
    assert migrate.main(["migrate"]) == 0
    assert "nothing (up to date)" in capsys.readouterr().out
    assert dsns == ["postgresql://argv/billing", "postgresql://env/billing"]


# ── deps: the context is built once, lazily, and closed ──


@pytest.mark.asyncio
async def test_context_is_built_once_under_concurrency_and_closed(monkeypatch):
    built = []
    closed = []

    class Store:
        async def close(self):
            closed.append(1)

    class Ctx:
        store = Store()

    async def build():
        built.append(1)
        await asyncio.sleep(0.01)
        return Ctx()

    monkeypatch.setattr(bootstrap, "build_runtime_context", build)
    deps.install_context(None)
    try:
        first, second = await asyncio.gather(deps.get_context(), deps.get_context())
        assert first is second and built == [1]
        assert await deps.get_context() is first
        await deps.close_context()
        assert closed == [1]
        await deps.close_context()       # nothing left to close
        assert closed == [1]
    finally:
        deps.install_context(None)


# ── HTTP edges, driven on the test's own event loop ──


@pytest_asyncio.fixture
async def http(ctx, monkeypatch):
    from tests.conftest import FakeRedis

    redis = FakeRedis()

    async def _get():
        return redis

    # A working limiter (the fail-open path without Redis is covered in test_router.py).
    monkeypatch.setattr("api.services.rate_limiter.get_redis", _get)
    app = FastAPI()
    assert mount_billing(app, ctx.settings) is True
    deps.install_context(ctx)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            yield client
    finally:
        deps.install_context(None)


async def _auth(http) -> dict:
    r = await http.post("/billing/v1/devices", json={"platform": "android"})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['data']['device_secret']}"}


@pytest.mark.asyncio
async def test_checkout_without_or_with_a_garbage_number_is_a_400(http):
    auth = await _auth(http)
    body = {"plan_code": "solo", "provider": "fake", "consent_doc_version": CONSENT}
    r = await http.post("/billing/v1/checkout", headers=auth, json=body)
    assert r.status_code == 400 and r.json()["error"]["code"] == "phone_required"
    r = await http.post("/billing/v1/checkout", headers=auth, json={**body, "msisdn": "not a phone"})
    assert r.status_code == 400 and r.json()["error"]["code"] == "phone_invalid"


@pytest.mark.asyncio
async def test_an_oversized_webhook_is_refused_before_parsing(http, ctx):
    r = await http.post("/billing/v1/webhooks/fake", content=b"{" + b" " * (64 * 1024) + b"}")
    assert r.status_code == 413 and r.json()["error"]["code"] == "too_large"
    assert ctx.store.tables.events == {}


@pytest.mark.asyncio
async def test_partner_licence_needs_a_valid_signature(http, ctx, security_events):
    body = json.dumps({"partner": "t2", "license_ref": "L-77", "seats": 1, "months": 1}).encode()
    r = await http.post("/billing/v1/partner/licenses", headers={"X-Partner-Signature": "f" * 64}, content=body)
    assert r.status_code == 401
    assert security_events == [("webhook_signature_invalid", "partner")]
    assert ctx.store.tables.subscriptions == {}
    # A valid signature over a different body is still a forgery.
    other = partner_signature("partner-secret", body.replace(b"L-77", b"L-78"))
    assert (await http.post("/billing/v1/partner/licenses", headers={"X-Partner-Signature": other},
                            content=body)).status_code == 401
    good = {"X-Partner-Signature": partner_signature("partner-secret", body)}
    r = await http.post("/billing/v1/partner/licenses", headers=good, content=body)
    assert r.status_code == 201 and r.json()["data"]["plan"] == "solo"


# ── MIXPLAT over its real HTTP transport (httpx, mocked at the transport layer) ──


@pytest.fixture
def mixplat_http(monkeypatch):
    """Route MixplatProvider._default_post's httpx client to a scripted handler."""
    state = {"handler": None, "requests": []}
    real = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        state["requests"].append(request)
        return state["handler"](request)

    def client(*args, **kwargs):
        return real(*args, transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client)
    return state, MixplatProvider(project_id=100057, api_key="k", base_url="https://api.example/")


@pytest.mark.asyncio
async def test_mixplat_posts_json_and_reads_the_reply(mixplat_http):
    state, mp = mixplat_http
    state["handler"] = lambda request: httpx.Response(200, json={"result": "ok", "payment_id": "REC-9"})
    assert await mp.charge_renewal(provider_subscription_id="R1", amount_kopecks=9900, idempotency_key="k1") == "REC-9"
    (request,) = state["requests"]
    assert str(request.url) == "https://api.example/create_recurrent_payment"
    sent = json.loads(request.content)
    assert sent["recurrent_id"] == "R1" and sent["amount"] == 9900 and sent["merchant_payment_id"] == "k1"
    assert sent["signature"] == md5_signature("R1", api_key="k")


@pytest.mark.asyncio
@pytest.mark.parametrize("respond", [
    lambda request: httpx.Response(502, text="Bad Gateway"),
    lambda request: (_ for _ in ()).throw(httpx.ReadTimeout("timed out", request=request)),
    lambda request: (_ for _ in ()).throw(httpx.ConnectError("refused", request=request)),
    lambda request: httpx.Response(200, text="<html>maintenance</html>"),
], ids=["5xx", "timeout", "connect", "not-json"])
async def test_mixplat_transport_failures_are_unknown_outcomes_not_refusals(mixplat_http, respond):
    """A charge whose answer we never read may have gone through: it must be retried / reconciled, not failed."""
    state, mp = mixplat_http
    state["handler"] = respond
    with pytest.raises(ProviderUnavailable):
        await mp.charge_renewal(provider_subscription_id="R1", amount_kopecks=9900, idempotency_key="k1")


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 401, 403, 404, 405, 409, 422])
async def test_mixplat_4xx_is_a_definite_refusal(mixplat_http, status):
    """A 4xx is MIXPLAT saying no to this request (bad signature, unknown project, malformed
    body): nothing was started, so the attempt fails now instead of waiting on a reconciler."""
    state, mp = mixplat_http
    state["handler"] = lambda request: httpx.Response(status, json={"result": "error"})
    with pytest.raises(ProviderError, match=f"HTTP {status}") as err:
        await mp.charge_renewal(provider_subscription_id="R1", amount_kopecks=9900, idempotency_key="k1")
    assert not isinstance(err.value, ProviderUnavailable)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
async def test_mixplat_timeouts_throttling_and_5xx_stay_unknown(mixplat_http, status):
    """408 / 429 are 'not now', and a 5xx may have happened after the charge: retry or reconcile."""
    state, mp = mixplat_http
    state["handler"] = lambda request: httpx.Response(status, text="busy")
    with pytest.raises(ProviderUnavailable):
        await mp.charge_renewal(provider_subscription_id="R1", amount_kopecks=9900, idempotency_key="k1")


@pytest.mark.asyncio
async def test_a_mixplat_4xx_on_checkout_closes_the_intent_at_once(mixplat_http, ctx):
    """End to end through the service: a refused checkout is closed, not kept for reconciliation."""
    from api.billing.service import checkout as checkout_service
    from api.billing.service.errors import NotConfigured
    from tests.billing.conftest import SUCCESS_NUMBER
    from tests.billing.test_flows import CONSENT, _device

    state, mp = mixplat_http
    state["handler"] = lambda request: httpx.Response(403, json={"result": "error"})
    ctx.providers["mixplat"] = mp
    device, _ = await _device(ctx)
    with pytest.raises(NotConfigured):
        await checkout_service.start_checkout(ctx, device, plan_code="solo", provider_code="mixplat",
                                              msisdn=SUCCESS_NUMBER, consent_doc_version=CONSENT)
    assert ctx.store.tables.subscriptions == {}
    actions = [a.action for a in ctx.store.tables.audit]
    assert "checkout.provider_refused" in actions and "checkout.provider_unreachable" not in actions


@pytest.mark.asyncio
async def test_mixplat_ok_reply_without_a_payment_id_is_a_refusal():
    async def no_id(url, body):
        return {"result": "ok"}

    with pytest.raises(ProviderError, match="create_recurrent_payment returned no payment_id") as err:
        await MixplatProvider(project_id=1, api_key="k", http_post=no_id).charge_renewal(
            provider_subscription_id="R1", amount_kopecks=9900, idempotency_key="k1")
    assert not isinstance(err.value, ProviderUnavailable)


@pytest.mark.asyncio
async def test_a_provider_error_from_the_transport_is_not_reclassified():
    async def refused(url, body):
        raise ProviderError("refused upstream")

    with pytest.raises(ProviderError) as err:
        await MixplatProvider(project_id=1, api_key="k", http_post=refused).fetch_status(provider_ref="P1")
    assert type(err.value) is ProviderError


def _signed(**fields):
    return {"request": "payment_status", "payment_id": "P1", "status": "success",
            "signature": md5_signature("P1", api_key="k"), **fields}


def test_mixplat_dates_moscow_time_iso_and_garbage():
    moscow = datetime(2026, 10, 1, 12, 0, tzinfo=timezone(timedelta(hours=3))).timestamp()
    assert parse_payment_status(_signed(date_processed="2026-10-01 12:00:00"), api_key="k").occurred_at == moscow
    assert parse_payment_status(_signed(date_processed="2026-10-01T12:00:00"), api_key="k").occurred_at == moscow
    before = datetime.now(timezone.utc).timestamp()
    for garbage in ("01.10.2026", "", None, ["2026"]):
        event = parse_payment_status(_signed(date_processed=garbage, date_created=None), api_key="k")
        assert event.occurred_at >= before and event.kind is EventKind.PAYMENT_SUCCEEDED


def test_mixplat_notification_without_a_payment_id_is_rejected():
    from api.billing.providers.base import InvalidSignature

    with pytest.raises(InvalidSignature):
        parse_payment_status({"request": "payment_status", "status": "success", "signature": md5_signature("", api_key="k")},
                             api_key="k")


# ── Device passes the verifier must reject ──


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@pytest.fixture
def signer():
    seed, _ = generate_keypair()
    return Signer(base64.b64decode(seed), kid="k1")


def _claims(**overrides):
    base = dict(dev="dev-1", mode=ProtectionMode.FULL, src=EntitlementSource.SUBSCRIPTION, lapse_policy=LapsePolicy.BASIC,
                iat=1_800_000_000, exp=1_800_000_000 + 86_400)
    base.update(overrides)
    return PassClaims(**base)


def test_a_pass_from_a_future_format_version_is_rejected(signer):
    ring = Keyring({"k1": signer.public_key_b64})
    with pytest.raises(PassInvalid) as err:
        ring.verify(signer.sign(_claims(v=2)), now=1_800_000_001)
    assert err.value.reason == "unsupported_version"


@pytest.mark.parametrize("token", [
    "a." + _b64(b"{}") + ".sig",                      # header: base64 with impossible padding
    "é." + _b64(b"{}") + ".sig",                  # header: not ASCII
    _b64(b"[1]") + "." + _b64(b"{}") + ".sig",        # header: JSON but not an object
], ids=["bad-padding", "non-ascii", "not-object"])
def test_structurally_broken_passes_are_malformed(signer, token):
    ring = Keyring({"k1": signer.public_key_b64})
    with pytest.raises(PassInvalid) as err:
        ring.verify(token, now=1_800_000_001)
    assert err.value.reason == "malformed"
