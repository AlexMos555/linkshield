"""Everything a billing operation needs, assembled once from settings.

The service functions (api/billing/service/) take a `BillingContext` and
nothing else, so tests build one with a MemoryStore, a FakeProvider and a
fixed clock, while the router builds the real one at startup.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Mapping, Tuple

from api.billing.crypto import KeyedHasher, MsisdnCipher
from api.billing.entitlement import Signer
from api.billing.models import LapsePolicy, Plan, PlanCode
from api.billing.providers.base import BillingProvider
from api.billing.settings import BillingSettings, decode_key
from api.billing.state_machine import Policy
from api.billing.store.base import BillingStore
from api.config import ConfigError

_SEATS = {PlanCode.SOLO: 1, PlanCode.FAMILY3: 3, PlanCode.FAMILY5: 5}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def plan_catalog(settings: BillingSettings) -> Tuple[Plan, ...]:
    """The RU catalogue new sales use: solo / family3 / family5 at BILLING_PLAN_VERSION."""
    return tuple(
        Plan(code=code, version=settings.billing_plan_version, seats=seats,
             price_kopecks=settings.price_kopecks(code.value))
        for code, seats in _SEATS.items()
    )


@dataclass(frozen=True)
class BillingContext:
    settings: BillingSettings
    store: BillingStore
    providers: Mapping[str, BillingProvider]
    signer: Signer
    cipher: MsisdnCipher
    hasher: KeyedHasher
    clock: Callable[[], datetime] = utc_now

    def now(self) -> datetime:
        return self.clock()

    def policy(self) -> Policy:
        return Policy(
            grace_days=self.settings.billing_grace_days,
            lapse_policy=LapsePolicy(self.settings.billing_lapse_policy),
            retry_days=self.settings.retry_days(),
            pending_timeout_minutes=self.settings.billing_pending_timeout_minutes,
        )

    def plans(self) -> Tuple[Plan, ...]:
        return plan_catalog(self.settings)

    def plan(self, code: PlanCode) -> Plan:
        return next(p for p in self.plans() if p.code is code)


def build_context(settings: BillingSettings, store: BillingStore, providers: Mapping[str, BillingProvider],
                  clock: Callable[[], datetime] = utc_now) -> BillingContext:
    """Decode the keys once; fails loudly (ConfigError) on a bad key."""
    seed = decode_key(settings.billing_entitlement_private_key, name="BILLING_ENTITLEMENT_PRIVATE_KEY",
                      min_bytes=32, exact=32)
    aes_key = decode_key(settings.billing_msisdn_key, name="BILLING_MSISDN_KEY", min_bytes=32, exact=32)
    hmac_key = decode_key(settings.billing_hmac_key, name="BILLING_HMAC_KEY", min_bytes=32)
    return BillingContext(
        settings=settings, store=store, providers=providers,
        signer=Signer(seed, settings.billing_entitlement_key_id),
        cipher=MsisdnCipher(aes_key), hasher=KeyedHasher(hmac_key), clock=clock,
    )


async def ensure_plans(ctx: BillingContext) -> None:
    """Write the catalogue rows so subscriptions can reference them.

    A stored version is immutable: renewals charge its price, so a price
    change under the same version would silently reprice every running
    subscription. That is refused; bump BILLING_PLAN_VERSION instead.
    """
    async with ctx.store.transaction() as tx:
        for plan in ctx.plans():
            stored = await tx.get_plan(plan.code.value, plan.version)
            if stored is not None and (stored.price_kopecks, stored.seats) != (plan.price_kopecks, plan.seats):
                raise ConfigError(
                    f"Plan {plan.code.value} v{plan.version} is stored at {stored.price_kopecks} kopecks; "
                    f"a new price needs a new BILLING_PLAN_VERSION (running subscriptions keep their price)."
                )
            await tx.upsert_plan(plan)
