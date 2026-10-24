"""Start the backend's Sentry client: which deploy, which environment, which
process an event came from.

Until 2026-10-22 events carried no release and an environment guessed from
the debug flag ("production" for staging too), so an error could not be tied
to the deploy that introduced it. Now:

  * release — SENTRY_RELEASE when set, else Railway's RAILWAY_GIT_COMMIT_SHA
    (Railway sets it on every deploy from GitHub). sentry-sdk does not read
    Railway's variable, and the image has no .git (.dockerignore), so without
    this the SDK finds nothing;
  * environment — settings.environment (development / staging / production);
  * tag `role` — `api` or `billing` (ROLE, api/billing/settings.py), so the
    Russian billing deployment's errors are told apart from the main API's;
  * tag `service_role` — `api` or `dns` when SERVICE_ROLE says so (the DNS
    service of docs/runbooks/dns-service-split.md); none for the default.

Privacy options and the scrubber stay in api/services/sentry_scrubber.py.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Mapping, Optional

logger = logging.getLogger("cleanway.sentry")

_ROLES = ("api", "billing")
# "all" (the default) adds no tag, so events look as they always did.
_SERVICE_ROLES = ("api", "dns")


def sentry_release(environ: Optional[Mapping[str, str]] = None) -> Optional[str]:
    env = os.environ if environ is None else environ
    explicit = (env.get("SENTRY_RELEASE") or "").strip()
    if explicit:
        return explicit
    sha = (env.get("RAILWAY_GIT_COMMIT_SHA") or "").strip()
    return f"cleanway-api@{sha[:12]}" if sha else None


def sentry_tags(environ: Optional[Mapping[str, str]] = None) -> dict[str, str]:
    env = os.environ if environ is None else environ
    role = (env.get("ROLE") or env.get("BILLING_ROLE") or "").strip().lower()
    tags = {"role": role if role in _ROLES else "api"}
    # Which Railway service, once DNS has its own (SERVICE_ROLE, api/config.py).
    service_role = (env.get("SERVICE_ROLE") or "").strip().lower()
    if service_role in _SERVICE_ROLES:
        tags["service_role"] = service_role
    return tags


def init_sentry(settings: Any) -> bool:
    """Initialise sentry-sdk when SENTRY_DSN is set. Returns whether it did."""
    dsn = getattr(settings, "sentry_dsn", "")
    if not dsn:
        return False
    try:
        import sentry_sdk
    except ImportError:
        logger.debug("sentry-sdk not installed, skipping")
        return False

    from api.services.sentry_scrubber import sentry_init_options

    release = sentry_release()
    # Errors, breadcrumbs AND sampled performance transactions all go
    # through the scrubber; no trace headers leave on outgoing requests.
    sentry_sdk.init(**sentry_init_options(
        dsn, settings.debug, environment=settings.environment, release=release,
    ))
    scope = sentry_sdk.get_global_scope()
    for key, value in sentry_tags().items():
        scope.set_tag(key, value)
    logger.info("Sentry initialized with PII scrubber", extra={"environment": settings.environment,
                                                              "release": release})
    return True
