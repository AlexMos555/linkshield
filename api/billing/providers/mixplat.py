"""MixplatProvider — the mobile-commerce aggregator (docs.mixplat.ru, read 2026-09-29).

What the public documentation states, and this adapter follows:
  * every method is POST-JSON to https://api.mixplat.com/<method>, `api_version: 3`;
  * signatures are md5 of concatenated strings + API_KEY (docs' own examples
    are pinned as test vectors in tests/billing/test_providers.py):
      create_payment_form     md5(request_id + project_id + merchant_payment_id + API_KEY)
      create_recurrent_payment md5(recurrent_id + API_KEY)
      get_payment_status      md5(payment_id + merchant_payment_id + API_KEY)
      refund_payment          md5(payment_id + API_KEY)
      payment_status webhook  md5(payment_id + API_KEY)
  * amounts are kopecks; `user_phone` is digits only with country code
    (79031234567); `test: 1` selects the sandbox, where 79150000000 succeeds
    and 79030000000 fails with `failure_no_money`;
  * a first payment with `recurrent_payment: 1` yields `recurrent_id` in the
    `payment_status` notification; later charges use `create_recurrent_payment`;
  * statuses: pending | success | failure; `status_extended` names the reason
    (`failure_no_money`, `failure_timeout`, `failure_canceled_by_user`, …);
  * the merchant answers a notification with {"result": "ok"}.

UNCERTAIN (mark for the MIXPLAT manager before go-live):
  * `request_id` in the create_payment_form signature is not among the
    documented request fields; we send it as a merchant-side unique id and
    include it in the signature exactly as the formula reads;
  * the operator-specific failure codes for "payments banned", "passport
    required" and "corporate number" are not documented — they map to OTHER;
  * there is no documented call to STOP a recurrent — we simply never charge
    again after a cancel (`initiates_renewals=True`), and `cancel()` is a no-op;
  * webhook source IPs and retry cadence are not published
    (BILLING_MIXPLAT_WEBHOOK_IPS is an optional allowlist, empty = off);
  * the notification's md5 covers payment_id only, so every success is
    re-checked with get_payment_status before it is applied;
  * `amount` vs `amount_merchant` (we read `amount` as what the subscriber
    paid) and the name/format of the currency field (`currency`, "RUB");
  * there is no documented method to SEND an SMS (needed for a one-time
    code on /cancel-by-phone) — none is used.

Disabled (NotConfiguredError) until BILLING_MIXPLAT_PROJECT_ID and
BILLING_MIXPLAT_API_KEY are set.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Dict, Mapping, Optional, Sequence

from api.billing.crypto import msisdn_digits
from api.billing.models import FailureReason
from api.billing.providers.base import (
    BillingEvent,
    CheckoutStart,
    EventKind,
    InvalidSignature,
    NotConfiguredError,
    ProviderError,
    ProviderUnavailable,
)

API_VERSION = 3
PAYMENT_METHOD_MOBILE = "mobile"
DEFAULT_TIMEOUT_SECONDS = 10.0

# status_extended → our reason. Undocumented operator codes fall to OTHER.
_FAILURE_MAP: Mapping[str, FailureReason] = {
    "failure_no_money": FailureReason.NO_MONEY,
    "failure_canceled_by_user": FailureReason.USER_DECLINED,
    "failure_timeout": FailureReason.TIMEOUT,
}


def md5_signature(*parts: Any, api_key: str) -> str:
    """md5 of the string concatenation of `parts` followed by the API key."""
    joined = "".join("" if p is None else str(p) for p in parts) + api_key
    # md5 is MIXPLAT's scheme, not a security choice of ours; the key never leaves the process.
    return hashlib.md5(joined.encode("utf-8"), usedforsecurity=False).hexdigest()


def failure_reason(status_extended: Optional[str]) -> FailureReason:
    return _FAILURE_MAP.get(status_extended or "", FailureReason.OTHER)


def parse_payment_status(payload: Mapping[str, Any], *, api_key: str) -> BillingEvent:
    """Turn a `payment_status` notification into a BillingEvent, checking its md5.

    The md5 covers `payment_id` only — status, amount and currency are NOT
    signed. The service therefore never applies a success on the strength of
    this notification alone: it asks `get_payment_status` and compares the
    answer with its own payment row (service/webhooks.py, 2026-10 fix).
    """
    if payload.get("request") not in (None, "payment_status"):
        raise InvalidSignature(f"unexpected notification type {payload.get('request')!r}")
    payment_id = str(payload.get("payment_id") or "")
    presented = str(payload.get("signature") or "")
    if not payment_id or not hmac.compare_digest(presented, md5_signature(payment_id, api_key=api_key)):
        raise InvalidSignature("bad payment_status signature")
    return _event(payload, payment_id=payment_id)


def _event(payload: Mapping[str, Any], *, payment_id: Optional[str],
           merchant_payment_id: Optional[str] = None) -> BillingEvent:
    status = payload.get("status")
    if status == "success":
        kind = EventKind.PAYMENT_SUCCEEDED
    elif status == "failure":
        kind = EventKind.PAYMENT_FAILED
    elif status == "pending":
        kind = EventKind.PAYMENT_PENDING
    else:
        raise InvalidSignature(f"unknown status {status!r}")
    # `amount` is what the subscriber paid; `amount_merchant` is what reaches us after the
    # aggregator's commission (to confirm with the MIXPLAT manager) — the former is compared
    # with the price, the latter only when the former is missing.
    amount = payload.get("amount", payload.get("amount_merchant"))
    merchant = _opt_str(payload.get("merchant_payment_id")) or merchant_payment_id
    return BillingEvent(
        provider=MixplatProvider.code,
        provider_event_id=f"{payment_id}:{status}" if payment_id else f"merchant:{merchant}:{status}",
        kind=kind,
        occurred_at=_epoch(payload.get("date_processed") or payload.get("date_created")),
        provider_subscription_id=_opt_str(payload.get("recurrent_id")),
        provider_payment_id=payment_id or None,
        merchant_payment_id=merchant,
        amount_kopecks=int(amount) if amount not in (None, "") else None,
        failure=failure_reason(payload.get("status_extended")) if kind is EventKind.PAYMENT_FAILED else None,
        test=str(payload.get("test", "0")) in ("1", "true", "True"),
        currency=_opt_str(payload.get("currency")),
    )


def _opt_str(value: Any) -> Optional[str]:
    return None if value in (None, "") else str(value)


def _epoch(value: Any) -> float:
    """MIXPLAT sends 'YYYY-MM-DD HH:MM:SS' (Moscow time per docs); fall back to now."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                from datetime import datetime, timedelta, timezone

                moscow = timezone(timedelta(hours=3))
                return datetime.strptime(value, fmt).replace(tzinfo=moscow).timestamp()
            except ValueError:
                continue
    return time.time()


class MixplatProvider:
    code = "mixplat"
    initiates_renewals = True
    # The notification's md5 does not cover status or amount: a success is applied only
    # after get_payment_status confirms it (service/webhooks.py).
    confirms_success_by_status = True

    def __init__(self, *, project_id: int, api_key: str, test: bool = True,
                 base_url: str = "https://api.mixplat.com", http_post=None) -> None:
        self._project_id = project_id
        self._api_key = api_key
        self._test = test
        self._base_url = base_url.rstrip("/")
        self._post = http_post or self._default_post

    @property
    def configured(self) -> bool:
        return bool(self._project_id and self._api_key)

    def _require(self) -> None:
        if not self.configured:
            raise NotConfiguredError("MIXPLAT credentials are not configured")

    # ── Requests (docs: /methods) ──

    def checkout_request(self, *, amount_kopecks: int, msisdn: Optional[str], merchant_payment_id: str,
                         return_url: str, description: str) -> Dict[str, Any]:
        request_id = merchant_payment_id
        body: Dict[str, Any] = {
            "api_version": API_VERSION,
            "project_id": self._project_id,
            "request_id": request_id,
            "merchant_payment_id": merchant_payment_id,
            "amount": amount_kopecks,
            "payment_method": PAYMENT_METHOD_MOBILE,
            "recurrent_payment": 1,
            "description": description,
            "test": 1 if self._test else 0,
            "success_url": return_url,
            "fail_url": return_url,
            "signature": md5_signature(request_id, self._project_id, merchant_payment_id, api_key=self._api_key),
        }
        if msisdn:
            body["user_phone"] = msisdn_digits(msisdn)
        return body

    def recurrent_request(self, *, recurrent_id: str, amount_kopecks: int, merchant_payment_id: str) -> Dict[str, Any]:
        return {
            "api_version": API_VERSION,
            "recurrent_id": recurrent_id,
            "amount": amount_kopecks,
            "merchant_payment_id": merchant_payment_id,
            "signature": md5_signature(recurrent_id, api_key=self._api_key),
        }

    def status_request(self, *, payment_id: str = "", merchant_payment_id: str = "") -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "api_version": API_VERSION,
            "signature": md5_signature(payment_id, merchant_payment_id, api_key=self._api_key),
        }
        if payment_id:
            body["payment_id"] = payment_id
        if merchant_payment_id:
            body["merchant_payment_id"] = merchant_payment_id
        return body

    def refund_request(self, *, payment_id: str, amount_kopecks: Optional[int]) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "api_version": API_VERSION,
            "payment_id": payment_id,
            "signature": md5_signature(payment_id, api_key=self._api_key),
        }
        if amount_kopecks is not None:
            body["amount"] = amount_kopecks
        return body

    # ── BillingProvider ──

    async def start_checkout(self, *, plan_product_id: str, amount_kopecks: int, msisdn: Optional[str],
                             idempotency_key: str, return_url: str) -> CheckoutStart:
        self._require()
        body = self.checkout_request(
            amount_kopecks=amount_kopecks, msisdn=msisdn, merchant_payment_id=idempotency_key,
            return_url=return_url, description=f"Cleanway {plan_product_id}",
        )
        reply = await self._call("create_payment_form", body)
        payment_id = str(reply.get("payment_id") or "")
        if not payment_id:
            raise ProviderError("create_payment_form returned no payment_id")
        return CheckoutStart(kind="redirect", provider_ref=payment_id, url=reply.get("redirect_url"))

    async def charge_renewal(self, *, provider_subscription_id: str, amount_kopecks: int, idempotency_key: str) -> str:
        self._require()
        reply = await self._call("create_recurrent_payment", self.recurrent_request(
            recurrent_id=provider_subscription_id, amount_kopecks=amount_kopecks, merchant_payment_id=idempotency_key,
        ))
        payment_id = str(reply.get("payment_id") or "")
        if not payment_id:
            raise ProviderError("create_recurrent_payment returned no payment_id")
        return payment_id

    async def cancel(self, *, provider_subscription_id: str) -> None:
        # No documented "stop recurrent" call: we are the initiator, so we stop initiating.
        return None

    async def refund(self, *, provider_payment_id: str, amount_kopecks: int, idempotency_key: str) -> None:
        self._require()
        await self._call("refund_payment", self.refund_request(payment_id=provider_payment_id, amount_kopecks=amount_kopecks))

    def parse_webhook(self, headers: Mapping[str, str], body: bytes) -> Sequence[BillingEvent]:
        self._require()
        try:
            payload = json.loads(body)
        except ValueError as e:
            raise InvalidSignature("body is not JSON") from e
        if not isinstance(payload, dict):
            raise InvalidSignature("body is not an object")
        return (parse_payment_status(payload, api_key=self._api_key),)

    def ack_body(self) -> Mapping[str, Any]:
        return {"result": "ok"}

    async def fetch_status(self, *, provider_ref: Optional[str] = None,
                           merchant_payment_id: Optional[str] = None) -> Optional[BillingEvent]:
        """get_payment_status by MIXPLAT's payment_id, or — when we never learnt it (a renewal
        call that timed out) — by our merchant_payment_id, which the method also accepts."""
        self._require()
        if not provider_ref and not merchant_payment_id:
            return None
        if provider_ref:
            body = self.status_request(payment_id=provider_ref)
        else:
            body = self.status_request(merchant_payment_id=merchant_payment_id or "")
        reply = await self._call("get_payment_status", body)
        if reply.get("status") not in ("success", "failure", "pending"):
            return None
        # get_payment_status answers are not signed; they come over our own TLS request.
        payment_id = _opt_str(reply.get("payment_id")) or provider_ref
        return _event(reply, payment_id=payment_id, merchant_payment_id=merchant_payment_id)

    # ── HTTP ──

    async def _call(self, method: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            reply = await self._post(f"{self._base_url}/{method}", body)
        except ProviderError:
            raise
        except Exception as e:  # noqa: BLE001 — network layer
            raise ProviderUnavailable(f"MIXPLAT {method}: {type(e).__name__}") from e
        if not isinstance(reply, Mapping):
            raise ProviderError(f"MIXPLAT {method}: non-object reply")
        if reply.get("result") != "ok":
            raise ProviderError(f"MIXPLAT {method}: {reply.get('result')} {reply.get('error_description', '')}".strip())
        return reply

    @staticmethod
    async def _default_post(url: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        import httpx

        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT_SECONDS) as client:
            response = await client.post(url, json=dict(body))
            response.raise_for_status()
            return response.json()
