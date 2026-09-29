"""Build the runtime BillingContext from settings (billing role only)."""
from __future__ import annotations

from typing import Optional

from api.billing.context import BillingContext, build_context, ensure_plans
from api.billing.providers.registry import build_providers
from api.billing.settings import BillingSettings, get_billing_settings, validate_billing_settings
from api.billing.store.base import BillingStore

MEMORY_DSN = "memory://"


async def open_store(dsn: str) -> BillingStore:
    """`memory://` for a local demo with the Fake provider; anything else is Postgres."""
    if dsn == MEMORY_DSN:
        from api.billing.store.memory import MemoryStore

        return MemoryStore()
    from api.billing.store.postgres import PostgresStore

    return await PostgresStore.connect(dsn)


async def build_runtime_context(settings: Optional[BillingSettings] = None) -> BillingContext:
    settings = settings or get_billing_settings()
    validate_billing_settings(settings)
    store = await open_store(settings.database_url_billing)
    ctx = build_context(settings, store, build_providers(settings))
    await ensure_plans(ctx)
    return ctx
