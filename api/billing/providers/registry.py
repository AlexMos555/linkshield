"""Which adapters a deployment exposes, from settings.

    promo      always (support grants; no money)
    t2_direct  always registered, always NotConfiguredError (contract stub)
    fake       only with BILLING_FAKE_PROVIDER_ENABLED=true (never production)
    mixplat    only with project id + API key
"""
from __future__ import annotations

from typing import Dict

from api.billing.providers.base import BillingProvider
from api.billing.providers.fake import FakeProvider
from api.billing.providers.mixplat import MixplatProvider
from api.billing.providers.promo import PromoProvider
from api.billing.providers.t2 import T2DirectProvider
from api.billing.settings import BillingSettings


def build_providers(settings: BillingSettings) -> Dict[str, BillingProvider]:
    providers: Dict[str, BillingProvider] = {
        PromoProvider.code: PromoProvider(),
        T2DirectProvider.code: T2DirectProvider(),
    }
    if settings.billing_fake_provider_enabled:
        providers[FakeProvider.code] = FakeProvider()
    if settings.billing_mixplat_project_id and settings.billing_mixplat_api_key:
        providers[MixplatProvider.code] = MixplatProvider(
            project_id=settings.billing_mixplat_project_id,
            api_key=settings.billing_mixplat_api_key,
            test=settings.billing_mixplat_test,
            base_url=settings.billing_mixplat_base_url,
        )
    return providers


def checkout_providers(providers: Dict[str, BillingProvider]) -> tuple:
    """Codes a device may pick at checkout (promo is support-only, t2_direct is a stub)."""
    return tuple(code for code in providers if code in ("fake", "mixplat", "rustore"))
