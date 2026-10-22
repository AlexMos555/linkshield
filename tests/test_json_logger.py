"""The production JSON log line (api/services/logger.py) keeps what runbooks
tell the founder to read, and only that.

Until 2026-10-22 the formatter printed 15 hard-coded `extra` keys. A
`retention.pass_complete` line came out as timestamp, level, logger and
message — no mode, no counts — although docs/runbooks/data-retention.md says
to read exactly those; 131 other keys (event_id, request_id, product_id …)
vanished the same way.

What is pinned here:
  * every `extra=` key used under api/ is classified: printed
    (ALLOWED_EXTRAS) or never printed (DENIED_EXTRAS) — a new key fails this
    file until someone decides, because docs/PRIVACY.md relies on unknown
    keys being dropped;
  * the fields runbooks name survive; ip_hash and message content never do;
  * values are scrubbed of credentials and email addresses and capped.
"""
from __future__ import annotations

import ast
import json
import logging
from pathlib import Path

import pytest

from api.services import logger as json_logger
from api.services.logger import ALLOWED_EXTRAS, DENIED_EXTRAS, MAX_VALUE_CHARS, JsonFormatter

API = Path(__file__).resolve().parents[1] / "api"

# Call sites whose `extra` is not a literal dict: the keys each can carry.
# A new dynamic site fails test_dynamic_extra_sites_are_known until listed.
DYNAMIC_EXTRA_KEYS = {
    "api/billing/scheduler.py": {
        "pending_timeouts", "renewals", "expiries", "reconciled", "unmatched_applied",
    },
    "api/billing/service/checkout.py": {
        "why", "expected_kopecks", "reported_kopecks", "currency", "event",
    },
    "api/services/rate_limiter.py": {"ip_hash", "install"},
}

_LOG_RECORD_ATTRS = set(vars(logging.LogRecord("n", logging.INFO, "f", 1, "m", None, None))) | {
    "message", "asctime",
}


def _extra_sites():
    """(path, literal keys, has a non-literal part) for every `extra=` call."""
    for path in sorted(API.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        rel = path.relative_to(API.parent).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg != "extra":
                    continue
                if isinstance(kw.value, ast.Dict):
                    literal = {k.value for k in kw.value.keys if isinstance(k, ast.Constant)}
                    dynamic = any(not isinstance(k, ast.Constant) for k in kw.value.keys)
                    yield rel, literal, dynamic
                else:
                    yield rel, set(), True


def _line(**extra) -> dict:
    record = logging.getLogger("cleanway.test").makeRecord(
        "cleanway.test", logging.INFO, __file__, 1, "event.name", None, None, extra=extra,
    )
    return json.loads(JsonFormatter().format(record))


# ── Classification ──

def test_every_extra_key_under_api_is_classified():
    used = set()
    for _path, literal, _dynamic in _extra_sites():
        used |= literal
    for keys in DYNAMIC_EXTRA_KEYS.values():
        used |= keys
    unclassified = sorted(used - ALLOWED_EXTRAS - DENIED_EXTRAS)
    assert not unclassified, (
        f"log `extra` keys neither printed nor denied: {unclassified} — add each to "
        "ALLOWED_EXTRAS (operational: ids, counts, states) or DENIED_EXTRAS "
        "(anything a person wrote, sent or holds) in api/services/logger.py"
    )


def test_dynamic_extra_sites_are_known():
    dynamic = {path for path, _literal, is_dynamic in _extra_sites() if is_dynamic}
    assert dynamic == set(DYNAMIC_EXTRA_KEYS), dynamic


def test_the_scan_sees_hundreds_of_call_sites():
    # A broken scan (wrong root, parse change) must not pass vacuously.
    assert sum(1 for _ in _extra_sites()) > 200


def test_allowed_and_denied_do_not_overlap():
    assert not ALLOWED_EXTRAS & DENIED_EXTRAS


def test_no_extra_key_can_overwrite_a_base_field_or_record_attribute():
    """`level` used to be both: analysis_complete and email_analyzed wrote the
    risk level over the log level (docs/runbooks/capacity.md)."""
    clashing = (ALLOWED_EXTRAS | DENIED_EXTRAS) & (set(json_logger.BASE_FIELDS) | _LOG_RECORD_ATTRS)
    assert not clashing
    for path, literal, _dynamic in _extra_sites():
        assert not literal & set(json_logger.BASE_FIELDS), path


# ── What survives ──

def test_the_retention_pass_line_carries_its_counts():
    line = _line(
        mode="dry_run",
        tables={"audit_log_2y": {"would_delete": 12}, "family_invites_expired": {"error": "status_500"}},
        accounts_deleted=None,
        accounts_would_delete=3,
        failed=["family_invites_expired"],
    )
    assert line["mode"] == "dry_run"
    assert line["tables"]["audit_log_2y"] == {"would_delete": 12}
    assert line["accounts_would_delete"] == 3
    assert line["failed"] == ["family_invites_expired"]
    assert "accounts_deleted" not in line  # None is left out, as before


def test_ids_runbooks_ask_for_survive():
    line = _line(request_id="ab12cd34", event_id="evt_1", product_id="cleanway_personal_monthly",
                 store="APP_STORE", type="INITIAL_PURCHASE", account_id="acc-1")
    assert {k: line[k] for k in ("request_id", "event_id", "product_id", "store", "type", "account_id")} == {
        "request_id": "ab12cd34", "event_id": "evt_1", "product_id": "cleanway_personal_monthly",
        "store": "APP_STORE", "type": "INITIAL_PURCHASE", "account_id": "acc-1",
    }


def test_the_old_fields_still_survive():
    line = _line(domain="example.ru", score=12, status=200, method="GET", path="/health",
                 elapsed_ms=1.5, user_id="u1", tier="free", proxy_peers={"100.64.0.0/10|xff=1": 3})
    assert line["domain"] == "example.ru" and line["proxy_peers"] == {"100.64.0.0/10|xff=1": 3}


def test_the_ip_hash_and_message_content_never_appear():
    line = _line(ip_hash="0123456789abcdef", install="1a2b3c4d", to="grandma@example.com",
                 subject="Ваш заказ", body="text", code="INVITE-1234", host="evil.example",
                 headers=["X-Test"], value="<mailto:x@example.com>")
    printed = json.dumps(line)
    for key in ("ip_hash", "install", "to", "subject", "body", "code", "host", "headers", "value"):
        assert key not in line
    for leaked in ("0123456789abcdef", "grandma@", "INVITE-1234", "evil.example"):
        assert leaked not in printed


def test_unknown_keys_are_dropped():
    assert "brand_new_key" not in _line(brand_new_key="x")


def test_the_log_level_is_never_overwritten():
    record = logging.getLogger("cleanway.test").makeRecord(
        "cleanway.test", logging.ERROR, __file__, 1, "boom", None, None, extra={"verdict": "dangerous"},
    )
    line = json.loads(JsonFormatter().format(record))
    assert line["level"] == "ERROR"
    assert line["verdict"] == "dangerous"


# ── Values ──

@pytest.mark.parametrize("secret,marker", [
    ("eyJ" + "hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl", "[redacted-jwt]"),
    ("Bearer abcdefghijklmnop", "Bearer [redacted]"),
    ("sb_" + "secret_abcdefghijklmnopqrstuvwxyz", "[redacted-supabase-key]"),
    ("AIza" + "SyA1234567890abcdefghijklmnopqrstuv", "[redacted-google-key]"),
    ("sk_" + "live_abcdefghijklmnopqrstuvwx", "[redacted-stripe-key]"),
    ("someone@example.com", "[redacted-email]"),
])
def test_credentials_and_addresses_are_scrubbed_from_values(secret, marker):
    line = _line(error=f"upstream said: {secret} rejected", tables={"t": {"error": secret}})
    assert secret not in json.dumps(line)
    assert marker in line["error"] and marker in line["tables"]["t"]["error"]


def test_credential_keys_inside_a_value_are_redacted():
    line = _line(outcomes={"password": "hunter2", "api_key": "k-1", "ok": 1})
    assert line["outcomes"] == {"password": "[redacted]", "api_key": "[redacted]", "ok": 1}


def test_ids_and_sites_are_not_scrubbed_from_values():
    # Railway's logs keep user ids, Stripe ids and sites on purpose (ops).
    uid = "123e4567-e89b-12d3-a456-426614174000"
    line = _line(user_id=uid, customer_id="cus_ABCDEFGHIJKLMNOP", domain="sberbank-bonus.ru")
    assert (line["user_id"], line["customer_id"], line["domain"]) == (uid, "cus_ABCDEFGHIJKLMNOP", "sberbank-bonus.ru")


def test_the_message_and_the_traceback_are_scrubbed_too():
    log = logging.getLogger("cleanway.test")
    try:
        raise RuntimeError("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl for a@b.ru")
    except RuntimeError:
        import sys

        record = log.makeRecord("cleanway.test", logging.ERROR, __file__, 1,
                                "failed for %s", ("someone@example.com",), sys.exc_info())
    line = json.loads(JsonFormatter().format(record))
    assert "someone@example.com" not in line["message"]
    assert "eyJhbGciOiJIUzI1NiJ9" not in line["exception"] and "a@b.ru" not in line["exception"]
    assert "RuntimeError" in line["exception"]


def test_long_values_are_capped():
    line = _line(error="x" * (MAX_VALUE_CHARS * 3), ids=[f"id-{i:05d}" for i in range(5000)])
    assert len(line["error"]) <= MAX_VALUE_CHARS + 32
    assert line["error"].endswith(json_logger.TRUNCATED)
    assert isinstance(line["ids"], str) and len(line["ids"]) <= MAX_VALUE_CHARS + 32


def test_small_structured_values_stay_structured():
    assert _line(failed=["a", "b"])["failed"] == ["a", "b"]
    assert _line(count=3, enabled=False)["enabled"] is False


def test_odd_values_are_printed_not_raised():
    class _Thing:
        def __str__(self):
            return "thing for x@y.ru"

    line = _line(reason=_Thing(), sources={"b", "a"}, outcomes={("a", 1): 2})
    assert line["reason"] == "thing for [redacted-email]"
    assert sorted(line["sources"]) == ["a", "b"]
    assert line["outcomes"] == "{('a', 1): 2}"  # not JSON-able as is: printed, the line survives
