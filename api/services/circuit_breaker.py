"""
Circuit Breaker for external API calls.

Prevents cascading failures when external services (Safe Browsing, PhishTank,
RDAP) are down. Three states:

  CLOSED  → Normal operation. Requests go through.
  OPEN    → After N consecutive failures. Skip calls for cooldown period.
  HALF_OPEN → After cooldown. One probe request allowed.
              Success → CLOSED. Failure → OPEN again.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, TypeVar

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

    # Internal state
    _state: CircuitState = field(default=CircuitState.CLOSED, init=False)
    _failure_count: int = field(default=0, init=False)
    _last_failure_time: float = field(default=0.0, init=False)
    _last_success_time: float = field(default=0.0, init=False)

    @property
    def state(self) -> CircuitState:
        """Get current state, transitioning OPEN → HALF_OPEN if cooldown elapsed."""
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self._last_failure_time >= self.cooldown_seconds:
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

        # OPEN → return fallback immediately
        if current_state == CircuitState.OPEN:
            logger.debug("circuit_open_skip", extra={"breaker": self.name})
            return self.fallback, False

        # CLOSED or HALF_OPEN → attempt the call
        try:
            result = await func(*args, **kwargs)
            self._on_success()
            return result, True
        except Exception as e:
            self._on_failure(e)
            return self.fallback, False

    def _on_success(self) -> None:
        """Record a successful call."""
        if self._state == CircuitState.HALF_OPEN:
            logger.info("circuit_closed", extra={"breaker": self.name})
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_success_time = time.monotonic()

    def _on_failure(self, error: Exception) -> None:
        """Record a failed call."""
        self._failure_count += 1
        self._last_failure_time = time.monotonic()

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

phishtank_breaker = CircuitBreaker(
    name="phishtank",
    failure_threshold=3,
    cooldown_seconds=60,
    fallback=False,
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


phishstats_breaker = CircuitBreaker(name="phishstats", failure_threshold=3, cooldown_seconds=60, fallback=False)
threatfox_breaker = CircuitBreaker(name="threatfox", failure_threshold=3, cooldown_seconds=60, fallback=False)
spamhaus_breaker = CircuitBreaker(name="spamhaus_dbl", failure_threshold=5, cooldown_seconds=120, fallback=False)
surbl_breaker = CircuitBreaker(name="surbl", failure_threshold=5, cooldown_seconds=120, fallback=False)
alienvault_breaker = CircuitBreaker(name="alienvault_otx", failure_threshold=3, cooldown_seconds=60, fallback={})
ipqs_breaker = CircuitBreaker(name="ipqualityscore", failure_threshold=3, cooldown_seconds=120, fallback={})


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
        whois_breaker.get_status(),
        ssl_breaker.get_status(),
        headers_breaker.get_status(),
        dns_breaker.get_status(),
        redirect_breaker.get_status(),
    ]
