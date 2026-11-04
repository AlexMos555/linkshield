"""
Circuit Breaker for external API calls.

Prevents cascading failures when external services (Safe Browsing, PhishTank,
RDAP) are down. Three states:

  CLOSED  → Normal operation. Requests go through.
  OPEN    → After N consecutive failures. Skip calls for cooldown period.
  HALF_OPEN → After cooldown. One probe request allowed; the calls that
              come while it is out are skipped as if OPEN.
              Success → CLOSED. Failure → OPEN again — for twice as long,
              up to max_cooldown_seconds, on a breaker that has one.
              Cancelled (the analysis deadline) → OPEN again for the same
              cooldown: no news that the source is back.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Optional, TypeVar

logger = logging.getLogger("cleanway.circuit_breaker")

T = TypeVar("T")


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    """
    Per-service circuit breaker.

    Usage:
        sb_breaker = CircuitBreaker(name="safe_browsing")

        result = await sb_breaker.call(check_safe_browsing, domain)
        # Returns (result, True) on success
        # Returns (fallback, False) if circuit is open
    """
    name: str
    failure_threshold: int = 3       # Consecutive failures to open circuit
    cooldown_seconds: float = 60.0   # How long to stay open before half-open probe
    fallback: Any = None             # Value to return when circuit is open
    # A probe that fails doubles the next cooldown, up to this; a success
    # resets it. None: the cooldown never grows. For a source that stays dead
    # for days: with a fixed 60 s every check at low traffic was the probe
    # (PhishStats, 2026-11-04).
    max_cooldown_seconds: Optional[float] = None

    # Internal state
    _state: CircuitState = field(default=CircuitState.CLOSED, init=False)
    _failure_count: int = field(default=0, init=False)
    _last_failure_time: float = field(default=0.0, init=False)
    _last_success_time: float = field(default=0.0, init=False)
    _cooldown: float = field(default=0.0, init=False)  # the current one; set in __post_init__
    _probing: bool = field(default=False, init=False)  # a half-open probe is out

    def __post_init__(self) -> None:
        self._cooldown = self.cooldown_seconds

    @property
    def state(self) -> CircuitState:
        """Get current state, transitioning OPEN → HALF_OPEN if cooldown elapsed."""
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self._last_failure_time >= self._cooldown:
                self._state = CircuitState.HALF_OPEN
                logger.info(
                    "circuit_half_open",
                    extra={"breaker": self.name},
                )
        return self._state

    async def call(self, func: Callable[..., Coroutine], *args, **kwargs) -> tuple[Any, bool]:
        """
        Execute function through circuit breaker.

        Returns:
            (result, succeeded) — result is the function return or fallback,
            succeeded indicates if the actual call was made and succeeded.
        """
        current_state = self.state

        # OPEN, or HALF_OPEN with the probe already out → fallback at once:
        # a dead source is asked once per cooldown, not by every check that
        # arrives while the probe waits out its time limit.
        if current_state == CircuitState.OPEN or (current_state == CircuitState.HALF_OPEN and self._probing):
            logger.debug("circuit_open_skip", extra={"breaker": self.name})
            return self.fallback, False

        # CLOSED or HALF_OPEN → attempt the call
        probe = current_state == CircuitState.HALF_OPEN
        if probe:
            self._probing = True
        try:
            result = await func(*args, **kwargs)
            self._on_success()
            return result, True
        except asyncio.CancelledError:
            if probe:
                self._on_probe_cancelled()
            raise
        except Exception as e:
            self._on_failure(e)
            return self.fallback, False
        finally:
            # Also when the probe is cancelled: the probe after the next
            # cooldown must be able to run.
            if probe:
                self._probing = False

    def _on_success(self) -> None:
        """Record a successful call."""
        if self._state == CircuitState.HALF_OPEN:
            logger.info("circuit_closed", extra={"breaker": self.name})
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._cooldown = self.cooldown_seconds
        self._last_success_time = time.monotonic()

    def _on_probe_cancelled(self) -> None:
        """The half-open probe was cancelled before it answered — the analysis
        deadline cut it, a late start leaving it less than its own limit. No
        news that the source is back, so OPEN again for the same cooldown.
        Not longer and not a failure: it did not fail either. Left half-open,
        the next call was the probe again, and a dead source whose probes
        started late held check after check to the deadline (review of #407,
        2026-11-04)."""
        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.OPEN
            self._last_failure_time = time.monotonic()
            logger.info("circuit_probe_cancelled", extra={"breaker": self.name})

    def _on_failure(self, error: Exception) -> None:
        """Record a failed call."""
        self._failure_count += 1
        self._last_failure_time = time.monotonic()

        if self._state == CircuitState.HALF_OPEN:
            # The probe failed: the source is still down. Wait longer before
            # the next one, on a breaker that allows it.
            cap = self.max_cooldown_seconds
            if cap is not None:
                self._cooldown = min(max(cap, self.cooldown_seconds), self._cooldown * 2)
        elif self._state == CircuitState.CLOSED:
            self._cooldown = self.cooldown_seconds

        if self._failure_count >= self.failure_threshold:
            self._state = CircuitState.OPEN
            logger.warning(
                "circuit_opened",
                extra={
                    "breaker": self.name,
                    "failures": self._failure_count,
                    "error": str(error),
                },
            )
        elif self._state == CircuitState.HALF_OPEN:
            # Probe failed → back to OPEN
            self._state = CircuitState.OPEN
            logger.info(
                "circuit_reopened",
                extra={"breaker": self.name, "error": str(error)},
            )

    def get_status(self) -> dict:
        """Return status dict for health endpoint."""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self._failure_count,
        }


# ─────────────────────────────────────────────────────────────────────
# Pre-configured breakers for each external service
# ─────────────────────────────────────────────────────────────────────

safe_browsing_breaker = CircuitBreaker(
    name="safe_browsing",
    failure_threshold=3,
    cooldown_seconds=60,
    fallback=False,  # If circuit open, assume not in blacklist
)

# The two keyless community feeds back off to one probe an hour while they
# stay down: on 2026-11-04 PhishStats had answered 0 of 235 calls (its API
# hangs; phishstats.info answers 502) and keyless PhishTank's answer was not
# JSON 235 times of 235. A probe of a hanging source holds that one answer to
# the source's limit and is named in its checks_incomplete; replayed at one
# fresh check every 5 minutes, a 30 min cap still made 46 of 232 answers such
# probes, 1 h made 29. Each feed is asked again within the hour of its recovery. The other
# breakers keep their fixed cooldown.
_DEAD_FEED_MAX_COOLDOWN_S = 60 * 60

phishtank_breaker = CircuitBreaker(
    name="phishtank",
    failure_threshold=3,
    cooldown_seconds=60,
    fallback=False,
    max_cooldown_seconds=_DEAD_FEED_MAX_COOLDOWN_S,
)

whois_breaker = CircuitBreaker(
    name="whois",
    failure_threshold=5,  # RDAP is flaky, higher threshold
    cooldown_seconds=120,
    fallback={},
)

ssl_breaker = CircuitBreaker(
    name="ssl",
    failure_threshold=5,
    cooldown_seconds=60,
    fallback={"has_ssl": False},
)

headers_breaker = CircuitBreaker(
    name="headers",
    failure_threshold=5,
    cooldown_seconds=60,
    fallback={"missing": []},
)


urlhaus_breaker = CircuitBreaker(
    name="urlhaus",
    failure_threshold=3,
    cooldown_seconds=60,
    fallback=False,
)

dns_breaker = CircuitBreaker(
    name="dns",
    failure_threshold=5,
    cooldown_seconds=60,
    fallback={},
)

redirect_breaker = CircuitBreaker(
    name="redirect",
    failure_threshold=5,
    cooldown_seconds=60,
    fallback={"count": 0, "cross_domain": False},
)


phishstats_breaker = CircuitBreaker(name="phishstats", failure_threshold=3, cooldown_seconds=60, fallback=False,
                                    max_cooldown_seconds=_DEAD_FEED_MAX_COOLDOWN_S)
threatfox_breaker = CircuitBreaker(name="threatfox", failure_threshold=3, cooldown_seconds=60, fallback=False)
spamhaus_breaker = CircuitBreaker(name="spamhaus_dbl", failure_threshold=5, cooldown_seconds=120, fallback=False)
surbl_breaker = CircuitBreaker(name="surbl", failure_threshold=5, cooldown_seconds=120, fallback=False)
alienvault_breaker = CircuitBreaker(name="alienvault_otx", failure_threshold=3, cooldown_seconds=60, fallback={})
ipqs_breaker = CircuitBreaker(name="ipqualityscore", failure_threshold=3, cooldown_seconds=120, fallback={})

# Strategy doc Top-20 #5 — extend abuse.ch coverage. URLhaus + ThreatFox
# already in place; MalwareBazaar (malware-distribution domains) and
# Feodo Tracker (C2 server tracker) close the bundle. Both free / no
# key required and refresh at the same 5-min cadence as URLhaus.
malware_bazaar_breaker = CircuitBreaker(name="malware_bazaar", failure_threshold=3, cooldown_seconds=60, fallback=False)
feodo_breaker = CircuitBreaker(name="feodo_tracker", failure_threshold=3, cooldown_seconds=60, fallback=False)

# Strategy doc Top-20 #14 — the top-1M popularity signal (Majestic
# Million + Chrome UX Report since 2026-10-23; the name is the list it
# replaced, and /health reports it under that name). Local-only
# Redis HGET, but wrapped in a breaker for resilience: if Redis is
# down the lookup returns the breaker fallback (un-ranked dict)
# and scoring simply omits the popularity bonus.
tranco_breaker = CircuitBreaker(
    name="tranco",
    failure_threshold=5,
    cooldown_seconds=30,
    fallback={"ranked": False, "rank": None, "weight": 0, "label": ""},
)

# Strategy doc Top-20 #2 — favicon brand-clone detection. Outbound
# HTTPS fetch with a 2-second budget; breaker keeps a flapping
# domain from holding up the analyzer loop.
favicon_breaker = CircuitBreaker(
    name="favicon",
    failure_threshold=3,
    cooldown_seconds=60,
    fallback={"cloned": False, "brand": None, "matched_hash": None, "weight": 0, "detail": ""},
)

# Strategy doc Top-20 #17 — typosquat watchtower lookup. Hits
# Supabase REST on the typosquat_alerts table. Wrapped in a
# breaker so a Supabase outage degrades to "no watchtower
# contribution" rather than 502'ing the whole /check.
watchtower_breaker = CircuitBreaker(
    name="watchtower",
    failure_threshold=5,
    cooldown_seconds=30,
    fallback={"matched": False, "brand": None, "variant_kind": None, "edit_distance": None, "weight": 0},
)


def get_all_breaker_statuses() -> list[dict]:
    """Return status of all circuit breakers (for health endpoint)."""
    return [
        safe_browsing_breaker.get_status(),
        phishtank_breaker.get_status(),
        urlhaus_breaker.get_status(),
        phishstats_breaker.get_status(),
        threatfox_breaker.get_status(),
        spamhaus_breaker.get_status(),
        surbl_breaker.get_status(),
        alienvault_breaker.get_status(),
        ipqs_breaker.get_status(),
        malware_bazaar_breaker.get_status(),
        feodo_breaker.get_status(),
        tranco_breaker.get_status(),
        favicon_breaker.get_status(),
        watchtower_breaker.get_status(),
        whois_breaker.get_status(),
        ssl_breaker.get_status(),
        headers_breaker.get_status(),
        dns_breaker.get_status(),
        redirect_breaker.get_status(),
    ]
