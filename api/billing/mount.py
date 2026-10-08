"""Mount /billing/v1 on the FastAPI app — only for ROLE=billing with the flag on.

With the defaults (BILLING_ENABLED=false, ROLE=api) this is a no-op: no
route exists, no context is built, no scheduler runs, and the Railway
deployment never loads asyncpg or touches the Russian database.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import FastAPI

from api.billing.settings import BillingSettings, get_billing_settings

logger = logging.getLogger("cleanway.billing.mount")


def mount_billing(app: FastAPI, settings: Optional[BillingSettings] = None) -> bool:
    """Include the billing router when this process is the billing role. Returns whether it did."""
    settings = settings or get_billing_settings()
    if not settings.routes_enabled():
        logger.info("billing.routes_disabled", extra={"enabled": settings.billing_enabled, "role": settings.role})
        return False
    from api.billing.deps import register_error_handlers
    from api.billing.router import router

    app.include_router(router)
    register_error_handlers(app)
    logger.info("billing.routes_mounted", extra={"prefix": router.prefix})
    return True


def is_billing_mounted(app: FastAPI) -> bool:
    """True when any route under /billing/ exists (an included router may be nested)."""
    return _has_billing_route(app.routes)


def _has_billing_route(routes) -> bool:
    for route in routes:
        if (getattr(route, "path", None) or "").startswith("/billing/"):
            return True
        nested = getattr(route, "original_router", None) or (route if not hasattr(route, "path") else None)
        if nested is not None and _has_billing_route(getattr(nested, "routes", ())):
            return True
    return False
