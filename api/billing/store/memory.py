"""In-memory billing store — for tests and the local Fake-provider demo.

Every transaction takes one lock, so two concurrent `/claim` calls for the
last seat are serialised exactly as Postgres would serialise them with
`SELECT … FOR UPDATE`. A transaction that raises is rolled back by
restoring the snapshot taken at its start (the rows are frozen dataclasses,
so copying the dicts is a full snapshot).
"""
from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from api.billing.models import (
    IDEMPOTENCY_IN_PROGRESS,
    AuditRow,
    BillingEventRow,
    ClaimCode,
    Consent,
    Device,
    IdempotentResponse,
    Payment,
    PaymentStatus,
    Plan,
    ProviderCode,
    Seat,
    Subscription,
    SubscriptionStatus,
    Trial,
)
from api.billing.store.base import ConflictError

# Fixed-term grants: never renewed, so their period end is their end.
GRANT_PROVIDERS = (ProviderCode.PROMO, ProviderCode.T2_OPTION)


@dataclass
class _Tables:
    plans: Dict[Tuple[str, int], Plan] = field(default_factory=dict)
    accounts: Dict[str, Optional[str]] = field(default_factory=dict)
    devices: Dict[str, Device] = field(default_factory=dict)
    trials: Dict[str, Trial] = field(default_factory=dict)
    subscriptions: Dict[str, Subscription] = field(default_factory=dict)
    seats: List[Seat] = field(default_factory=list)
    claim_codes: Dict[str, ClaimCode] = field(default_factory=dict)
    payments: Dict[str, Payment] = field(default_factory=dict)
    events: Dict[Tuple[str, str], Dict[str, Any]] = field(default_factory=dict)
    consents: List[Consent] = field(default_factory=list)
    audit: List[AuditRow] = field(default_factory=list)
    idempotent: Dict[Tuple[str, str], IdempotentResponse] = field(default_factory=dict)
    sequence: int = 0

    def snapshot(self) -> "_Tables":
        return _Tables(
            plans=dict(self.plans), accounts=dict(self.accounts), devices=dict(self.devices),
            trials=dict(self.trials), subscriptions=dict(self.subscriptions), seats=list(self.seats),
            claim_codes=dict(self.claim_codes), payments=dict(self.payments),
            events={k: dict(v) for k, v in self.events.items()}, consents=list(self.consents),
            audit=list(self.audit), idempotent=dict(self.idempotent), sequence=self.sequence,
        )


def _now() -> datetime:
    return datetime.now(timezone.utc)


class MemoryStore:
    def __init__(self) -> None:
        self._tables = _Tables()
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def transaction(self):
        async with self._lock:
            snapshot = self._tables.snapshot()
            try:
                yield MemoryTx(self._tables)
            except BaseException:
                self._tables = snapshot
                raise

    async def close(self) -> None:
        return None

    # Test helpers (not part of Tx): peek without a transaction.
    @property
    def tables(self) -> _Tables:
        return self._tables


class MemoryTx:
    def __init__(self, t: _Tables) -> None:
        self._t = t

    def _next_id(self) -> int:
        self._t.sequence += 1
        return self._t.sequence

    # ── plans ──

    async def upsert_plan(self, plan: Plan) -> None:
        self._t.plans[(plan.code.value, plan.version)] = plan

    async def list_plans(self, *, active_only: bool = True) -> Sequence[Plan]:
        plans = [p for p in self._t.plans.values() if p.active or not active_only]
        return sorted(plans, key=lambda p: (p.seats, p.version))

    async def get_plan(self, code: str, version: int) -> Optional[Plan]:
        return self._t.plans.get((code, version))

    # ── accounts / devices ──

    async def create_account(self, *, display_label: Optional[str] = None) -> str:
        account_id = str(uuid.uuid4())
        self._t.accounts[account_id] = display_label
        return account_id

    async def create_device(self, *, account_id: str, secret_sha256: str, platform: str,
                            app_version: Optional[str], legacy_free: bool) -> Device:
        if any(d.secret_sha256 == secret_sha256 for d in self._t.devices.values()):
            raise ConflictError("device secret already registered")
        device = Device(
            id=str(uuid.uuid4()), account_id=account_id, secret_sha256=secret_sha256, platform=platform,
            created_at=_now(), app_version=app_version, legacy_free=legacy_free,
        )
        self._t.devices[device.id] = device
        return device

    async def get_device(self, device_id: str) -> Optional[Device]:
        return self._t.devices.get(device_id)

    async def get_device_by_secret_hash(self, secret_sha256: str) -> Optional[Device]:
        return next((d for d in self._t.devices.values() if d.secret_sha256 == secret_sha256), None)

    async def touch_device(self, device_id: str, *, seen_at: datetime, app_version: Optional[str]) -> None:
        device = self._t.devices[device_id]
        self._t.devices[device_id] = replace(device, last_seen=seen_at, app_version=app_version or device.app_version)

    # ── trials ──

    async def get_trial_by_fingerprint(self, fingerprint_hmac: str) -> Optional[Trial]:
        return self._t.trials.get(fingerprint_hmac)

    async def get_trial_for_device(self, device_id: str) -> Optional[Trial]:
        return next((t for t in self._t.trials.values() if t.device_id == device_id), None)

    async def create_trial(self, trial: Trial) -> None:
        if trial.device_fingerprint_hmac in self._t.trials:
            raise ConflictError("trial already used for this phone")
        self._t.trials[trial.device_fingerprint_hmac] = trial

    async def rebind_trial(self, fingerprint_hmac: str, device_id: str) -> None:
        trial = self._t.trials.get(fingerprint_hmac)
        if trial is not None:
            self._t.trials[fingerprint_hmac] = replace(trial, device_id=device_id)

    # ── subscriptions ──

    async def create_subscription(self, sub: Subscription) -> Subscription:
        if sub.provider_subscription_id and any(
            s.provider == sub.provider and s.provider_subscription_id == sub.provider_subscription_id
            for s in self._t.subscriptions.values()
        ):
            raise ConflictError("provider subscription id already known")
        self._t.subscriptions[sub.id] = sub
        return sub

    async def get_subscription(self, sub_id: str, *, for_update: bool = False) -> Optional[Subscription]:
        return self._t.subscriptions.get(sub_id)

    async def update_subscription(self, sub: Subscription, *, expected_version: int) -> Subscription:
        current = self._t.subscriptions.get(sub.id)
        if current is None or current.row_version != expected_version:
            raise ConflictError("subscription changed concurrently")
        updated = replace(sub, row_version=expected_version + 1, updated_at=_now())
        self._t.subscriptions[sub.id] = updated
        return updated

    async def delete_subscription(self, sub_id: str) -> None:
        self._t.subscriptions.pop(sub_id, None)
        self._t.seats = [s for s in self._t.seats if s.subscription_id != sub_id]
        self._t.claim_codes = {k: c for k, c in self._t.claim_codes.items() if c.subscription_id != sub_id}
        self._t.payments = {k: p for k, p in self._t.payments.items() if p.subscription_id != sub_id}

    async def get_subscription_by_provider_ref(self, provider: str, provider_subscription_id: str) -> Optional[Subscription]:
        return next(
            (s for s in self._t.subscriptions.values()
             if s.provider.value == provider and s.provider_subscription_id == provider_subscription_id),
            None,
        )

    async def list_subscriptions_by_msisdn_hmac(self, msisdn_hmac: str) -> Sequence[Subscription]:
        return [s for s in self._t.subscriptions.values() if s.msisdn_hmac == msisdn_hmac]

    async def list_subscriptions_for_account(self, account_id: str) -> Sequence[Subscription]:
        subs = [s for s in self._t.subscriptions.values() if s.payer_account_id == account_id]
        return sorted(subs, key=lambda s: s.created_at)

    async def list_due_renewals(self, *, now: datetime, limit: int = 100) -> Sequence[Subscription]:
        due = [
            s for s in self._t.subscriptions.values()
            if s.status in (SubscriptionStatus.ACTIVE, SubscriptionStatus.GRACE)
            and s.next_charge_at is not None and s.next_charge_at <= now and s.cancel_requested_at is None
        ]
        return sorted(due, key=lambda s: s.next_charge_at)[:limit]

    async def list_pending_older_than(self, *, cutoff: datetime, limit: int = 100) -> Sequence[Subscription]:
        pending = [
            s for s in self._t.subscriptions.values()
            if s.status is SubscriptionStatus.PENDING and s.created_at <= cutoff
        ]
        return sorted(pending, key=lambda s: s.created_at)[:limit]

    async def list_expiring(self, *, now: datetime, limit: int = 100) -> Sequence[Subscription]:
        """Grace periods, cancelled periods and fixed-term grants that have run out."""
        rows = [
            s for s in self._t.subscriptions.values()
            if (s.status is SubscriptionStatus.GRACE and s.grace_until is not None and s.grace_until <= now)
            or (s.status is SubscriptionStatus.CANCEL_AT_PERIOD_END and s.current_period_end is not None
                and s.current_period_end <= now)
            or (s.status is SubscriptionStatus.ACTIVE and s.provider in GRANT_PROVIDERS
                and s.current_period_end is not None and s.current_period_end <= now)
        ]
        return sorted(rows, key=lambda s: s.created_at)[:limit]

    # ── seats ──

    async def list_seats(self, sub_id: str, *, active_only: bool = True) -> Sequence[Seat]:
        return [s for s in self._t.seats if s.subscription_id == sub_id and (s.released_at is None or not active_only)]

    async def get_active_seat_for_device(self, device_id: str) -> Optional[Seat]:
        return next((s for s in self._t.seats if s.device_id == device_id and s.released_at is None), None)

    async def add_seat(self, seat: Seat) -> None:
        if await self.get_active_seat_for_device(seat.device_id) is not None:
            raise ConflictError("device already has a seat")
        self._t.seats.append(seat)

    async def release_seat(self, sub_id: str, device_id: str, *, released_at: datetime) -> bool:
        for i, seat in enumerate(self._t.seats):
            if seat.subscription_id == sub_id and seat.device_id == device_id and seat.released_at is None:
                self._t.seats[i] = replace(seat, released_at=released_at)
                return True
        return False

    # ── claim codes ──

    async def create_claim_code(self, code: ClaimCode) -> None:
        if code.code_hmac in self._t.claim_codes:
            raise ConflictError("claim code collision")
        self._t.claim_codes[code.code_hmac] = code

    async def get_claim_code(self, code_hmac: str, *, for_update: bool = False) -> Optional[ClaimCode]:
        return self._t.claim_codes.get(code_hmac)

    async def redeem_claim_code(self, code_id: str, *, device_id: str, redeemed_at: datetime) -> bool:
        for key, code in self._t.claim_codes.items():
            if code.id == code_id:
                if code.redeemed_at is not None:
                    return False
                self._t.claim_codes[key] = replace(code, redeemed_at=redeemed_at, redeemed_by_device=device_id)
                return True
        return False

    # ── payments ──

    async def create_payment(self, payment: Payment) -> Payment:
        existing = await self.get_payment_by_idempotency_key(payment.idempotency_key)
        if existing is not None:
            return existing
        self._t.payments[payment.id] = payment
        return payment

    async def get_payment(self, payment_id: str) -> Optional[Payment]:
        return self._t.payments.get(payment_id)

    async def get_payment_by_idempotency_key(self, key: str) -> Optional[Payment]:
        return next((p for p in self._t.payments.values() if p.idempotency_key == key), None)

    async def get_payment_by_provider_id(self, provider: str, provider_payment_id: str) -> Optional[Payment]:
        return next(
            (p for p in self._t.payments.values()
             if p.provider.value == provider and p.provider_payment_id == provider_payment_id),
            None,
        )

    async def update_payment(self, payment: Payment) -> None:
        self._t.payments[payment.id] = payment

    async def list_pending_payments_older_than(self, *, cutoff: datetime, limit: int = 100) -> Sequence[Payment]:
        rows = [p for p in self._t.payments.values() if p.status is PaymentStatus.PENDING and p.created_at <= cutoff]
        return sorted(rows, key=lambda p: p.created_at)[:limit]

    async def list_payments(self, sub_id: str) -> Sequence[Payment]:
        rows = [p for p in self._t.payments.values() if p.subscription_id == sub_id]
        return sorted(rows, key=lambda p: p.created_at)

    # ── webhooks, consents, audit ──

    async def insert_event(self, *, provider: str, provider_event_id: str, signature_ok: bool,
                           payload_ciphertext: bytes, event_ciphertext: Optional[bytes] = None) -> Optional[int]:
        key = (provider, provider_event_id)
        if key in self._t.events:
            return None
        event_id = self._next_id()
        self._t.events[key] = {
            "id": event_id, "signature_ok": signature_ok, "payload_ciphertext": payload_ciphertext,
            "received_at": _now(), "processed_at": None, "outcome": None,
            "event_ciphertext": event_ciphertext, "attempts": 0,
        }
        return event_id

    async def mark_event_processed(self, event_id: int, *, processed_at: datetime, outcome: str) -> None:
        for row in self._t.events.values():
            if row["id"] == event_id:
                row["processed_at"] = processed_at
                row["outcome"] = outcome

    async def list_retryable_events(self, *, limit: int = 100) -> Sequence[BillingEventRow]:
        rows = [
            BillingEventRow(
                id=row["id"], provider=ProviderCode(provider), provider_event_id=event_id,
                received_at=row["received_at"], signature_ok=row["signature_ok"],
                payload_ciphertext=row["payload_ciphertext"], processed_at=row["processed_at"],
                outcome=row["outcome"], event_ciphertext=row["event_ciphertext"], attempts=row["attempts"],
            )
            for (provider, event_id), row in self._t.events.items()
            if row["outcome"] == "unmatched" and row["signature_ok"] and row["event_ciphertext"] is not None
        ]
        return sorted(rows, key=lambda r: r.id)[:limit]

    async def retry_event(self, event_id: int, *, processed_at: datetime, outcome: str) -> None:
        for row in self._t.events.values():
            if row["id"] == event_id:
                row["processed_at"] = processed_at
                row["outcome"] = outcome
                row["attempts"] += 1

    async def add_consent(self, consent: Consent) -> Consent:
        stored = replace(consent, id=self._next_id())
        self._t.consents.append(stored)
        return stored

    async def list_consents(self, account_id: str) -> Sequence[Consent]:
        return [c for c in self._t.consents if c.account_id == account_id]

    async def add_audit(self, *, actor: str, action: str, target: str, meta: Mapping[str, Any]) -> AuditRow:
        row = AuditRow(id=self._next_id(), actor=actor, action=action, target=target, created_at=_now(), meta=dict(meta))
        self._t.audit.append(row)
        return row

    async def list_audit(self, target: str) -> Sequence[AuditRow]:
        return [a for a in self._t.audit if a.target == target]

    # ── idempotent responses ──

    async def get_idempotent_response(self, scope: str, key: str) -> Optional[IdempotentResponse]:
        return self._t.idempotent.get((scope, key))

    async def reserve_idempotency_key(self, scope: str, key: str, *, now: datetime,
                                      stale_before: datetime) -> Optional[IdempotentResponse]:
        existing = self._t.idempotent.get((scope, key))
        if existing is not None and not (existing.in_progress and existing.created_at < stale_before):
            return existing
        self._t.idempotent[(scope, key)] = IdempotentResponse(
            scope=scope, key=key, status_code=IDEMPOTENCY_IN_PROGRESS, body={}, created_at=now,
        )
        return None

    async def put_idempotent_response(self, response: IdempotentResponse) -> None:
        existing = self._t.idempotent.get((response.scope, response.key))
        if existing is None or existing.in_progress:
            self._t.idempotent[(response.scope, response.key)] = response

    async def release_idempotency_key(self, scope: str, key: str) -> None:
        existing = self._t.idempotent.get((scope, key))
        if existing is not None and existing.in_progress:
            del self._t.idempotent[(scope, key)]
