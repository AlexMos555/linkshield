"""Google's part of a verdict, and how long it may be kept.

Web Risk's rules for warnings (docs.cloud.google.com/web-risk/docs/
user-warnings, read 2026-11-04): a warning can be shown only while "a URL
matches a threat entry and the cached response is still valid at the time a
warning is shown. Under no other circumstances may a warning be shown." The
Web Risk client caches a match until its expireTime, at most an hour
(web_risk.positive_ttl); a verdict built on that match must not outlive it
in any cache: the public check's, the signed-in check's, or a client's.

A verdict rests on Google when one of its reasons is `safe_browsing` — the
code a Google hit has had since Safe Browsing v4 (scoring.py). How long it
may still be kept is the life left in Google's cached answer
(safe_browsing.threat_seconds_left); the public response passes it on as
`advisory_ttl` so the extension, the app and the website cap their caches.
"""
from __future__ import annotations

from typing import Optional

from api.models.schemas import DomainResult

GOOGLE_REASON = "safe_browsing"


def has_google_reason(result: DomainResult) -> bool:
    return any(r.signal == GOOGLE_REASON for r in (result.reasons or ()))


async def seconds_left(result: DomainResult) -> Optional[int]:
    """None for a verdict with no Google reason (no window applies);
    otherwise how many more seconds it may be kept or shown from a cache —
    0 when Google's answer is gone or cannot be read."""
    if not has_google_reason(result):
        return None
    from api.services.safe_browsing import threat_seconds_left

    return await threat_seconds_left(result.domain)


def capped(ttl: int, left: Optional[int]) -> int:
    """A cache lifetime, never longer than Google's answer has left."""
    return ttl if left is None else max(0, min(ttl, left))
