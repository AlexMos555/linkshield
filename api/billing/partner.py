"""Partner licences — the T2 "option" model (plan A.6 `/partner/licenses`).

T2 (or another partner) bills the subscriber itself and tells us to issue
a licence for N seats; we answer with an activation code the partner puts
in its SMS (`cleanway://activate?code=…`). The first phone that redeems
the code becomes the licence's owner and can add relatives.

Skeleton: the request is HMAC-signed with BILLING_PARTNER_HMAC_KEY; the
real T2 contract (mTLS, their field names, renewals, revocation) replaces
`verify_partner_signature` and `parse_partner_request` later.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import timedelta
from typing import Any, Dict, Mapping, Optional

from api.billing.context import BillingContext
from api.billing.models import (
    ClaimPurpose,
    PlanCode,
    ProviderCode,
    Subscription,
    SubscriptionStatus,
)
from api.billing.service.errors import Conflict, Invalid, NotConfigured, Unauthorized
from api.billing.service.seats import CLAIM_INSTALL_URL, _new_code
from api.billing.state_machine import add_months

SIGNATURE_HEADER = "x-partner-signature"
ACTIVATE_SCHEME = "cleanway://activate?code="
LICENSE_CODE_TTL_DAYS = 30
_MAX_MONTHS = 12


def verify_partner_signature(key: str, headers: Mapping[str, str], body: bytes) -> None:
    if not key:
        raise NotConfigured("partner licences are not configured")
    presented = next((v for k, v in headers.items() if k.lower() == SIGNATURE_HEADER), "")
    expected = hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not presented or not hmac.compare_digest(presented, expected):
        raise Unauthorized("bad partner signature")


def parse_partner_request(body: bytes) -> Dict[str, Any]:
    try:
        payload = json.loads(body)
    except ValueError as e:
        raise Invalid("body is not JSON") from e
    if not isinstance(payload, dict):
        raise Invalid("body must be an object")
    partner = str(payload.get("partner") or "")
    license_ref = str(payload.get("license_ref") or "")
    if not partner.isalnum() or not (1 <= len(license_ref) <= 128):
        raise Invalid("partner and license_ref required")
    try:
        seats = int(payload.get("seats", 1))
        months = int(payload.get("months", 1))
    except (TypeError, ValueError) as e:
        raise Invalid("seats and months must be integers") from e
    if not 1 <= months <= _MAX_MONTHS:
        raise Invalid(f"months must be 1..{_MAX_MONTHS}")
    return {"partner": partner, "license_ref": license_ref, "seats": seats, "months": months}


def plan_for_seats(ctx: BillingContext, seats: int) -> PlanCode:
    for plan in sorted(ctx.plans(), key=lambda p: p.seats):
        if seats <= plan.seats:
            return plan.code
    raise Invalid("no plan with that many seats", code="too_many_seats")


async def create_partner_license(ctx: BillingContext, *, partner: str, license_ref: str, seats: int,
                                 months: int) -> Dict[str, Any]:
    plan_code = plan_for_seats(ctx, seats)
    plan = ctx.plan(plan_code)
    now = ctx.now()
    provider_ref = f"{partner}:{license_ref}"
    async with ctx.store.transaction() as tx:
        if await tx.get_subscription_by_provider_ref(ProviderCode.T2_OPTION.value, provider_ref) is not None:
            raise Conflict("licence already issued", code="license_exists")
        account_id = await tx.create_account(display_label=partner)
        end = add_months(now, months)
        sub = await tx.create_subscription(Subscription(
            id=str(uuid.uuid4()), payer_account_id=account_id, plan_code=plan.code, plan_version=plan.version,
            provider=ProviderCode.T2_OPTION, status=SubscriptionStatus.ACTIVE, created_at=now, updated_at=now,
            provider_subscription_id=provider_ref, current_period_start=now, current_period_end=end,
            next_charge_at=None, operator=partner,
        ))
        expires_at = now + timedelta(days=LICENSE_CODE_TTL_DAYS)
        code = await _new_code(ctx, tx, sub.id, expires_at, purpose=ClaimPurpose.PARTNER_LICENSE)
        await tx.add_audit(actor=f"partner:{partner}", action="partner_license.created", target=f"subscription:{sub.id}",
                           meta={"license_ref": license_ref, "seats": plan.seats, "months": months})
    return {
        "subscription_id": sub.id, "plan": plan.code.value, "seats": plan.seats, "valid_until": int(end.timestamp()),
        "activation_code": code, "activation_link": ACTIVATE_SCHEME + code, "install_url": CLAIM_INSTALL_URL,
        "code_expires_at": int(expires_at.timestamp()),
    }


def partner_signature(key: str, body: bytes) -> str:
    """For the partner's integration tests and ours."""
    return hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()


def maybe_partner(value: Optional[str]) -> Optional[str]:
    return value if value and value.isalnum() else None
