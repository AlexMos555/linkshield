"""FakeProvider — every screen of the flow without an aggregator (tests, local demo).

The outcome is scripted by the phone number so the app can show each error
screen of §2.5 (screen 8):

    +7903 000-00-00  → failure: no_money        (MIXPLAT's own test number)
    +7903 000-00-01  → failure: payments_banned
    +7903 000-00-02  → failure: passport
    +7903 000-00-03  → failure: corporate
    +7903 000-00-04  → failure: user_declined
    +7903 000-00-05  → stays pending (never answers; exercises timeouts and reconciliation)
    anything else    → success

Webhooks are JSON bodies signed with HMAC-SHA-256 in `X-Fake-Signature`
(`sign()` builds them for tests). Never enabled in production
(`BILLING_FAKE_PROVIDER_ENABLED`).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence

from api.billing.models import FailureReason
from api.billing.providers.base import (
    BillingEvent,
    CheckoutStart,
    EventKind,
    InvalidSignature,
)

SIGNATURE_HEADER = "x-fake-signature"

_SCRIPT: Mapping[str, Optional[FailureReason]] = {
    "+79030000000": FailureReason.NO_MONEY,
    "+79030000001": FailureReason.PAYMENTS_BANNED,
    "+79030000002": FailureReason.PASSPORT,
    "+79030000003": FailureReason.CORPORATE,
    "+79030000004": FailureReason.USER_DECLINED,
}
PENDING_FOREVER = "+79030000005"


def scripted_outcome(msisdn: Optional[str]) -> Optional[FailureReason]:
    """The failure a number is scripted to produce, or None for success."""
    return _SCRIPT.get(msisdn or "")


class FakeProvider:
    code = "fake"
    initiates_renewals = True

    def __init__(self, secret: str = "fake-webhook-secret") -> None:
        self._secret = secret.encode("utf-8")
        # What each checkout / renewal was asked to do, by provider ref.
        self.checkouts: Dict[str, Dict[str, Any]] = {}
        self.renewals: List[Dict[str, Any]] = []
        self.cancelled: List[str] = []
        self.refunds: List[Dict[str, Any]] = []
        # What get-status reports for a renewal, by idempotency key (absent = the charge went through).
        self.renewal_script: Dict[str, Optional[FailureReason]] = {}

    # ── BillingProvider ──

    async def start_checkout(self, *, plan_product_id: str, amount_kopecks: int, msisdn: Optional[str],
                             idempotency_key: str, return_url: str) -> CheckoutStart:
        ref = f"fake_{hashlib.sha256(idempotency_key.encode()).hexdigest()[:16]}"
        self.checkouts.setdefault(ref, {
            "plan_product_id": plan_product_id, "amount_kopecks": amount_kopecks, "msisdn": msisdn,
            "idempotency_key": idempotency_key, "outcome": scripted_outcome(msisdn),
            "pending_forever": msisdn == PENDING_FOREVER,
        })
        return CheckoutStart(kind="await_sms", provider_ref=ref)

    async def charge_renewal(self, *, provider_subscription_id: str, amount_kopecks: int, idempotency_key: str) -> str:
        payment_id = f"fakepay_{hashlib.sha256(idempotency_key.encode()).hexdigest()[:16]}"
        self.renewals.append({
            "provider_subscription_id": provider_subscription_id, "amount_kopecks": amount_kopecks,
            "idempotency_key": idempotency_key, "payment_id": payment_id,
        })
        return payment_id

    async def cancel(self, *, provider_subscription_id: str) -> None:
        self.cancelled.append(provider_subscription_id)

    async def refund(self, *, provider_payment_id: str, amount_kopecks: int, idempotency_key: str) -> None:
        self.refunds.append({"provider_payment_id": provider_payment_id, "amount_kopecks": amount_kopecks,
                             "idempotency_key": idempotency_key})

    def parse_webhook(self, headers: Mapping[str, str], body: bytes) -> Sequence[BillingEvent]:
        presented = _header(headers, SIGNATURE_HEADER)
        if not presented or not hmac.compare_digest(presented, self.signature(body)):
            raise InvalidSignature("bad X-Fake-Signature")
        try:
            payload = json.loads(body)
        except ValueError as e:
            raise InvalidSignature("body is not JSON") from e
        if not isinstance(payload, dict):
            raise InvalidSignature("body is not an object")
        return (self._event_from(payload),)

    def ack_body(self) -> Mapping[str, Any]:
        return {"success": True}

    async def fetch_status(self, *, provider_ref: Optional[str] = None,
                           merchant_payment_id: Optional[str] = None) -> Optional[BillingEvent]:
        renewal = next((r for r in self.renewals
                        if (provider_ref and r["payment_id"] == provider_ref)
                        or (merchant_payment_id and r["idempotency_key"] == merchant_payment_id)), None)
        if renewal is not None:
            outcome = self.renewal_script.get(renewal["idempotency_key"])
            payload = self.event_payload(renewal["provider_subscription_id"], outcome=outcome,
                                         payment_id=renewal["payment_id"], amount_kopecks=renewal["amount_kopecks"],
                                         merchant_payment_id=renewal["idempotency_key"],
                                         event_id=f"status_{renewal['payment_id']}")
            return self._event_from(payload)
        ref = provider_ref if provider_ref in self.checkouts else next(
            (r for r, c in self.checkouts.items() if merchant_payment_id and c["idempotency_key"] == merchant_payment_id), None)
        checkout = self.checkouts.get(ref) if ref else None
        if checkout is None or checkout["pending_forever"]:
            return None
        return self._event_from(self.event_payload(ref, outcome=checkout["outcome"],
                                                   merchant_payment_id=checkout["idempotency_key"]))

    # ── Test helpers ──

    def signature(self, body: bytes) -> str:
        return hmac.new(self._secret, body, hashlib.sha256).hexdigest()

    def sign(self, payload: Mapping[str, Any]) -> tuple:
        """(headers, body) for a webhook the parser will accept."""
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        return {SIGNATURE_HEADER: self.signature(body)}, body

    def event_payload(self, provider_ref: str, *, outcome: Optional[FailureReason] = None,
                      event_id: Optional[str] = None, kind: Optional[str] = None,
                      payment_id: Optional[str] = None, amount_kopecks: Optional[int] = None,
                      merchant_payment_id: Optional[str] = None) -> Dict[str, Any]:
        """The JSON the Fake 'aggregator' would POST for a checkout or renewal."""
        checkout = self.checkouts.get(provider_ref, {})
        resolved_kind = kind or ("payment_failed" if outcome else "payment_succeeded")
        return {
            "event_id": event_id or f"evt_{provider_ref}_{resolved_kind}",
            "kind": resolved_kind,
            "subscription_ref": provider_ref,
            "payment_id": payment_id or f"fakepay_{provider_ref}",
            "amount_kopecks": amount_kopecks if amount_kopecks is not None else checkout.get("amount_kopecks"),
            "failure": outcome.value if outcome else None,
            "occurred_at": time.time(),
            "merchant_payment_id": merchant_payment_id,
        }

    def _event_from(self, payload: Mapping[str, Any]) -> BillingEvent:
        try:
            kind = EventKind(payload["kind"])
            failure = FailureReason(payload["failure"]) if payload.get("failure") else None
            return BillingEvent(
                provider=self.code, provider_event_id=str(payload["event_id"]), kind=kind,
                occurred_at=float(payload.get("occurred_at") or time.time()),
                provider_subscription_id=payload.get("subscription_ref"),
                provider_payment_id=payload.get("payment_id"),
                merchant_payment_id=payload.get("merchant_payment_id"),
                amount_kopecks=int(payload["amount_kopecks"]) if payload.get("amount_kopecks") is not None else None,
                failure=failure,
            )
        except (KeyError, ValueError, TypeError) as e:
            raise InvalidSignature(f"malformed fake event: {e}") from e


def _header(headers: Mapping[str, str], name: str) -> Optional[str]:
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None
