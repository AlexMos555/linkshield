"""
Structured logging configuration.

Privacy-preserving: NEVER logs full URLs, user IPs, or JWT tokens.
Logs: domain names, scores, user_ids, timestamps, response times.

A log call's ``extra={...}`` reaches the JSON line only for keys in
ALLOWED_EXTRAS; any other key is dropped (docs/PRIVACY.md relies on that for
``ip_hash``). DENIED_EXTRAS names the keys that must never be printed —
anything a person wrote, sent or holds. tests/test_json_logger.py fails when
code under api/ uses a key that is in neither, so a new field is a decision,
not an accident. Until 2026-10-22 only 15 keys were printed and runbooks
pointed at fields (the retention counts, event ids) that never appeared.

Every printed string — the message, the traceback, and strings at any depth
of an extra value — is scrubbed of credentials and email addresses with the
Sentry scrubber's patterns (`sentry_scrubber.scrub_log_value`), and each
extra value is capped at MAX_VALUE_CHARS once serialised.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from api.services.sentry_scrubber import scrub_log_text, scrub_log_value

BASE_FIELDS = ("timestamp", "level", "logger", "message")
MAX_VALUE_CHARS = 4096
TRUNCATED = "…[truncated]"

# Operational fields: ids (ours, Stripe's, the stores'), counts, states,
# names of things in our own code. Grouped by where they come from.
ALLOWED_EXTRAS = frozenset({
    # request log + checks (the 15 printed before 2026-10-22, minus `level`)
    "domain", "score", "status", "method", "path", "elapsed_ms", "error",
    "user_id", "tier", "checks", "debug", "origins", "doh", "proxy_peers",
    "request_id", "status_code", "verdict", "confidence", "confidence_pct",
    "basis", "incomplete", "findings", "links", "blocks", "samples", "size",
    "url_count", "unique_domains", "cap", "result", "threat_types", "sources",
    "source", "breaker", "failures", "attempt", "attempts", "backend",
    "fail_closed", "used", "limit", "window", "count", "category", "length",
    "bytes", "mime", "kind", "type", "outcome", "alg",
    # startup
    "environment", "strict_config", "has_supabase", "has_stripe",
    "has_revenuecat", "has_sentry", "supabase_server_key_kind", "role",
    "enabled", "migration", "release",
    # accounts, families, orgs (our own ids)
    "account_id", "uid", "caller", "owner", "redeemer", "invite_id",
    "family_id", "org", "org_id", "admin_user_id", "platform", "targets",
    "target_kind", "target_id", "action", "restore_until", "days",
    # retention and account purge
    "mode", "tables", "table", "accounts_deleted", "accounts_would_delete",
    "failed", "interval_s", "cutoff", "candidates", "deleted", "restored",
    "skipped", "ids", "user_ids",
    # email (never the address, subject or body)
    "template", "send_id", "provider", "locale", "fallback", "html_len",
    "text_len",
    # payments: Stripe, RevenueCat, the store webhooks
    "event_id", "plan", "pricing_tier", "trial", "trial_end_epoch",
    "subscription_id", "subscription_ids", "previous", "new", "customer_id",
    "charge_id", "dispute_id", "amount_cents", "amount_paid_cents",
    "amount_refunded_cents", "currency", "reason", "product_id",
    "new_product_id", "store", "external_id", "existing_source",
    "new_source", "rows", "applied", "ended",
    # operator billing (api/billing)
    "subscription", "payment", "event", "found", "age_hours", "outcomes",
    "trial_days", "grace_days", "lapse_policy", "fake_provider", "mixplat",
    "mixplat_test", "why", "expected_kopecks", "reported_kopecks",
    "pending_timeouts", "renewals", "expiries", "reconciled",
    "unmatched_applied",
})

# Never printed, whatever the value: message content and addresses (to,
# from, subject, body, headers, a raw header value), codes people redeem,
# hosts a probe or a redirect visited, the IP hash and install hash of the
# rate limiter, and `prefix` (the breach check's SHA-1 prefix shares the name).
DENIED_EXTRAS = frozenset({
    "to", "from", "subject", "body", "headers", "value", "code", "host",
    "ip_hash", "install", "prefix",
})


def _bounded(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value if len(value) <= MAX_VALUE_CHARS else value[:MAX_VALUE_CHARS] + TRUNCATED
    text = json.dumps(value, default=str, ensure_ascii=False)
    return value if len(text) <= MAX_VALUE_CHARS else text[:MAX_VALUE_CHARS] + TRUNCATED


class JsonFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": scrub_log_text(record.getMessage()),
        }

        # Extra fields, in the order the call site wrote them. A base field
        # can never be overwritten (the risk level used to replace the log
        # level); no allowed key is one, which the tests pin.
        for key, value in record.__dict__.items():
            if key in ALLOWED_EXTRAS and value is not None and key not in log_entry:
                log_entry[key] = _bounded(scrub_log_value(value))

        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = scrub_log_text(self.formatException(record.exc_info))

        return json.dumps(log_entry, default=str)


def setup_logging(debug: bool = False) -> None:
    """
    Configure structured JSON logging for the entire application.
    Call once at startup.
    """
    level = logging.DEBUG if debug else logging.INFO

    # Root logger
    root = logging.getLogger()
    root.setLevel(level)

    # Remove existing handlers
    root.handlers.clear()

    # JSON handler for stdout
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)

    # Quiet noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    # httpx2 (pulled in by anthropic 1.x, and preferred by Starlette's test
    # client when present) logs every request URL at INFO under its own name.
    # A DoH GET carries the query name in ?dns=, so it must never reach a log.
    logging.getLogger("httpx2").setLevel(logging.WARNING)
