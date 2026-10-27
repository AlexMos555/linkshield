"""Which requests the backend's Sentry client traces.

sentry-sdk's Starlette integration wraps the whole app — outside the DoH fast
path, the DNS routing and load shedding — and until 2026-10-24 sampled 10 % of
every request as a performance transaction, /dns-query included. One phone
with the DNS profile sends ~3 000 queries a day (~91 000 a month,
docs/runbooks/capacity.md): ~9 000 transactions a month from each phone,
~90 million at 10 000 phones — many times what the $26 Sentry plan includes
(docs/ACCOUNTS_BILLING_PLAN.md), while the whole server costs ~$45–60 a month
at that scale — plus the CPU to build them. A DNS trace shows nothing the
aggregate counters do not (api/services/doh_metrics, /health/doh). The
health probes are the same: Railway, the uptime monitors and the DNS canary
call them on a timer.

`traces_sampler`, wired in sentry_scrubber.sentry_init_options:
  * never traces /dns-query (GET and POST, under api.cleanway.ai,
    dns.cleanway.ai and the DNS service's own domain alike), /health,
    /health/doh or /health/deep — not even when the request carries a sampled
    `sentry-trace` header, which sentry-sdk otherwise obeys and any client
    can send;
  * everything else: the incoming trace's decision when there is one (what
    sentry-sdk does without a sampler — the landing's server-side fetches
    keep whole traces), else `traces_sample_rate` as passed to
    sentry_sdk.init, TRACES_SAMPLE_RATE. Nothing in api/config.py overrides
    the rate and sentry-sdk 2.x reads no environment variable for it, so
    that option stays the one knob.

The request is still wrapped (an unsampled transaction object, no envelope):
the sampler cuts what is recorded and sent, not the wrapper — ~0.2 ms CPU
per cached DNS answer, measured locally (docs/runbooks/capacity.md).
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

TRACES_SAMPLE_RATE = 0.1

# Every path dns.cleanway.ai answers (request_guards.DNS_HOST_PATHS) plus the
# deep probe.
UNTRACED_PATHS = frozenset({"/dns-query", "/health", "/health/doh", "/health/deep"})


def _request_path(sampling_context: dict[str, Any]) -> str:
    """The request path: the ASGI scope's, else the transaction name's (a
    route, a path, or a whole URL — the fast path's transactions are named
    `http://<host>/dns-query`)."""
    scope = sampling_context.get("asgi_scope")
    if isinstance(scope, dict) and isinstance(scope.get("path"), str):
        path = scope["path"]
    else:
        name = (sampling_context.get("transaction_context") or {}).get("name") or ""
        try:
            path = urlsplit(name).path if "://" in name else name
        except ValueError:
            path = name
    return path.rstrip("/") or "/"


def traces_sampler(sampling_context: dict[str, Any]) -> float | bool:
    if _request_path(sampling_context) in UNTRACED_PATHS:
        return 0.0
    parent = sampling_context.get("parent_sampled")
    if parent is not None:
        return parent
    import sentry_sdk

    rate = sentry_sdk.get_client().options.get("traces_sample_rate")
    return TRACES_SAMPLE_RATE if rate is None else rate
