"""A complete billing context on the in-memory store with a controllable clock."""
from __future__ import annotations

import base64
import os
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from api.billing.context import build_context, ensure_plans
from api.billing.providers.fake import FakeProvider
from api.billing.providers.promo import PromoProvider
from api.billing.providers.t2 import T2DirectProvider
from api.billing.settings import BillingSettings
from api.billing.store.memory import MemoryStore

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
SUCCESS_NUMBER = "+79150000000"
NO_MONEY_NUMBER = "+79030000000"


class Clock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs) -> datetime:
        self.now = self.now + timedelta(**kwargs)
        return self.now


def _b64(n: int) -> str:
    return base64.b64encode(os.urandom(n)).decode()


def make_settings(**overrides) -> BillingSettings:
    base = dict(
        billing_enabled=True, role="billing", database_url_billing="memory://",
        billing_entitlement_private_key=_b64(32), billing_msisdn_key=_b64(32), billing_hmac_key=_b64(32),
        billing_fake_provider_enabled=True, billing_partner_hmac_key="partner-secret",
    )
    base.update(overrides)
    return BillingSettings(_env_file=None, **base)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def settings() -> BillingSettings:
    return make_settings()


@pytest.fixture
def fake() -> FakeProvider:
    return FakeProvider()


@pytest_asyncio.fixture
async def ctx(settings, clock, fake):
    providers = {"fake": fake, "promo": PromoProvider(), "t2_direct": T2DirectProvider()}
    context = build_context(settings, MemoryStore(), providers, clock=clock)
    await ensure_plans(context)
    return context
