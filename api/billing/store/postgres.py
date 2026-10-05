"""Postgres billing store (asyncpg) — the production implementation.

Connects to `DATABASE_URL_BILLING` (a Russian-hosted Postgres) and maps the
schema in `api/billing/migrations/` to the frozen dataclasses of
`api/billing/models.py`. Every `transaction()` is one asyncpg transaction;
`get_subscription(for_update=True)` takes the row lock the seat-limit and
webhook paths rely on.

asyncpg is imported lazily so the `api` role never needs it installed.
"""
from __future__ import annotations

import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Mapping, Optional, Sequence

from api.billing.models import (
    AuditRow,
    CancelChannel,
    ClaimCode,
    ClaimPurpose,
    Consent,
    ConsentKind,
    Device,
    FailureReason,
    IdempotentResponse,
    Payment,
    PaymentStatus,
    Plan,
    PlanCode,
    ProviderCode,
    Seat,
    SeatRole,
    Subscription,
    SubscriptionStatus,
    Trial,
)
from api.billing.store.base import ConflictError


async def _init_connection(conn) -> None:
    await conn.set_type_codec("jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")


class PostgresStore:
    def __init__(self, pool) -> None:
        self._pool = pool

    @classmethod
    async def connect(cls, dsn: str, *, min_size: int = 1, max_size: int = 5) -> "PostgresStore":
        import asyncpg

        pool = await asyncpg.create_pool(dsn, min_size=min_size, max_size=max_size, init=_init_connection)
        return cls(pool)

    @asynccontextmanager
    async def transaction(self):
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                yield PostgresTx(conn)

    async def close(self) -> None:
        await self._pool.close()


# ── Row mappers ──


def _s(value: Any) -> Optional[str]:
    return None if value is None else str(value)


def _plan(r) -> Plan:
    return Plan(code=PlanCode(r["code"]), version=r["version"], seats=r["seats"], price_kopecks=r["price_kopecks"],
                period=r["period"], provider_product_ids=r["provider_product_ids"] or {}, active=r["active"])


def _device(r) -> Device:
    return Device(id=_s(r["id"]), account_id=_s(r["account_id"]), secret_sha256=r["secret_sha256"],
                  platform=r["platform"], created_at=r["created_at"], app_version=r["app_version"],
                  legacy_free=r["legacy_free"], last_seen=r["last_seen"])


def _trial(r) -> Trial:
    return Trial(device_fingerprint_hmac=r["device_fingerprint_hmac"], device_id=_s(r["device_id"]),
                 started_at=r["started_at"], ends_at=r["ends_at"])


def _sub(r) -> Subscription:
    return Subscription(
        id=_s(r["id"]), payer_account_id=_s(r["payer_account_id"]), plan_code=PlanCode(r["plan_code"]),
        plan_version=r["plan_version"], provider=ProviderCode(r["provider"]), status=SubscriptionStatus(r["status"]),
        created_at=r["created_at"], updated_at=r["updated_at"], provider_subscription_id=r["provider_subscription_id"],
        current_period_start=r["current_period_start"], current_period_end=r["current_period_end"],
        grace_until=r["grace_until"], next_charge_at=r["next_charge_at"], cancel_requested_at=r["cancel_requested_at"],
        cancel_channel=CancelChannel(r["cancel_channel"]) if r["cancel_channel"] else None,
        msisdn_ciphertext=bytes(r["msisdn_ciphertext"]) if r["msisdn_ciphertext"] is not None else None,
        msisdn_hmac=r["msisdn_hmac"], operator=r["operator"], attempt=r["attempt"],
        charge_pending=r["charge_pending"], row_version=r["row_version"],
    )


def _seat(r) -> Seat:
    return Seat(subscription_id=_s(r["subscription_id"]), device_id=_s(r["device_id"]), role=SeatRole(r["role"]),
                claimed_at=r["claimed_at"], released_at=r["released_at"])


def _code(r) -> ClaimCode:
    return ClaimCode(id=_s(r["id"]), subscription_id=_s(r["subscription_id"]), code_hmac=r["code_hmac"],
                     purpose=ClaimPurpose(r["purpose"]), expires_at=r["expires_at"], redeemed_at=r["redeemed_at"],
                     redeemed_by_device=_s(r["redeemed_by_device"]))


def _payment(r) -> Payment:
    return Payment(
        id=_s(r["id"]), subscription_id=_s(r["subscription_id"]), provider=ProviderCode(r["provider"]),
        idempotency_key=r["idempotency_key"], amount_kopecks=r["amount_kopecks"], status=PaymentStatus(r["status"]),
        created_at=r["created_at"], provider_payment_id=r["provider_payment_id"],
        failure_reason=FailureReason(r["failure_reason"]) if r["failure_reason"] else None,
        period_start=r["period_start"], period_end=r["period_end"], receipt_url=r["receipt_url"],
    )


def _consent(r) -> Consent:
    return Consent(
        id=r["id"], account_id=_s(r["account_id"]), kind=ConsentKind(r["kind"]), doc_version=r["doc_version"],
        doc_sha256=r["doc_sha256"], method=r["method"], created_at=r["created_at"],
        subscription_id=_s(r["subscription_id"]), shown_price_kopecks=r["shown_price_kopecks"],
        shown_plan_code=PlanCode(r["shown_plan_code"]) if r["shown_plan_code"] else None,
        provider_confirmation_ref=r["provider_confirmation_ref"], ip_hmac=r["ip_hmac"],
    )


def _audit(r) -> AuditRow:
    return AuditRow(id=r["id"], actor=r["actor"], action=r["action"], target=r["target"],
                    created_at=r["created_at"], meta=r["meta"] or {})


_SUB_COLUMNS = (
    "id, payer_account_id, plan_code, plan_version, provider, provider_subscription_id, status, "
    "current_period_start, current_period_end, grace_until, next_charge_at, cancel_requested_at, cancel_channel, "
    "msisdn_ciphertext, msisdn_hmac, operator, attempt, charge_pending, row_version, created_at, updated_at"
)


class PostgresTx:
    def __init__(self, conn) -> None:
        self._c = conn

    # ── plans ──

    async def upsert_plan(self, plan: Plan) -> None:
        await self._c.execute(
            "INSERT INTO plans (code, version, seats, price_kopecks, period, provider_product_ids, active) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (code, version) DO UPDATE SET seats = EXCLUDED.seats, "
            "price_kopecks = EXCLUDED.price_kopecks, period = EXCLUDED.period, "
            "provider_product_ids = EXCLUDED.provider_product_ids, active = EXCLUDED.active",
            plan.code.value, plan.version, plan.seats, plan.price_kopecks, plan.period,
            dict(plan.provider_product_ids), plan.active,
        )

    async def list_plans(self, *, active_only: bool = True) -> Sequence[Plan]:
        rows = await self._c.fetch(
            "SELECT * FROM plans WHERE active OR NOT $1 ORDER BY seats, version", active_only,
        )
        return [_plan(r) for r in rows]

    async def get_plan(self, code: str, version: int) -> Optional[Plan]:
        r = await self._c.fetchrow("SELECT * FROM plans WHERE code = $1 AND version = $2", code, version)
        return _plan(r) if r else None

    # ── accounts / devices ──

    async def create_account(self, *, display_label: Optional[str] = None) -> str:
        return str(await self._c.fetchval("INSERT INTO accounts (display_label) VALUES ($1) RETURNING id", display_label))

    async def create_device(self, *, account_id: str, secret_sha256: str, platform: str,
                            app_version: Optional[str], legacy_free: bool) -> Device:
        import asyncpg

        try:
            async with self._c.transaction():   # savepoint: a conflict must not abort the outer transaction
                r = await self._c.fetchrow(
                    "INSERT INTO devices (account_id, secret_sha256, platform, app_version, legacy_free) "
                    "VALUES ($1, $2, $3, $4, $5) RETURNING *",
                    uuid.UUID(account_id), secret_sha256, platform, app_version, legacy_free,
                )
        except asyncpg.UniqueViolationError as e:
            raise ConflictError("device secret already registered") from e
        return _device(r)

    async def get_device(self, device_id: str) -> Optional[Device]:
        r = await self._c.fetchrow("SELECT * FROM devices WHERE id = $1", uuid.UUID(device_id))
        return _device(r) if r else None

    async def get_device_by_secret_hash(self, secret_sha256: str) -> Optional[Device]:
        r = await self._c.fetchrow("SELECT * FROM devices WHERE secret_sha256 = $1", secret_sha256)
        return _device(r) if r else None

    async def touch_device(self, device_id: str, *, seen_at: datetime, app_version: Optional[str]) -> None:
        await self._c.execute(
            "UPDATE devices SET last_seen = $2, app_version = COALESCE($3, app_version) WHERE id = $1",
            uuid.UUID(device_id), seen_at, app_version,
        )

    # ── trials ──

    async def get_trial_by_fingerprint(self, fingerprint_hmac: str) -> Optional[Trial]:
        r = await self._c.fetchrow("SELECT * FROM trials WHERE device_fingerprint_hmac = $1", fingerprint_hmac)
        return _trial(r) if r else None

    async def get_trial_for_device(self, device_id: str) -> Optional[Trial]:
        r = await self._c.fetchrow("SELECT * FROM trials WHERE device_id = $1", uuid.UUID(device_id))
        return _trial(r) if r else None

    async def create_trial(self, trial: Trial) -> None:
        import asyncpg

        try:
            async with self._c.transaction():
                await self._c.execute(
                    "INSERT INTO trials (device_fingerprint_hmac, device_id, started_at, ends_at) VALUES ($1, $2, $3, $4)",
                    trial.device_fingerprint_hmac, uuid.UUID(trial.device_id), trial.started_at, trial.ends_at,
                )
        except asyncpg.UniqueViolationError as e:
            raise ConflictError("trial already used for this phone") from e

    # ── subscriptions ──

    async def create_subscription(self, sub: Subscription) -> Subscription:
        import asyncpg

        try:
            async with self._c.transaction():
                r = await self._c.fetchrow(
                    f"INSERT INTO subscriptions ({_SUB_COLUMNS}) VALUES "
                    "($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21) "
                    "RETURNING *",
                    *_sub_values(sub),
                )
        except asyncpg.UniqueViolationError as e:
            raise ConflictError("provider subscription id already known") from e
        return _sub(r)

    async def get_subscription(self, sub_id: str, *, for_update: bool = False) -> Optional[Subscription]:
        suffix = " FOR UPDATE" if for_update else ""
        r = await self._c.fetchrow(f"SELECT * FROM subscriptions WHERE id = $1{suffix}", uuid.UUID(sub_id))
        return _sub(r) if r else None

    async def update_subscription(self, sub: Subscription, *, expected_version: int) -> Subscription:
        r = await self._c.fetchrow(
            "UPDATE subscriptions SET plan_code = $2, plan_version = $3, provider = $4, provider_subscription_id = $5, "
            "status = $6, current_period_start = $7, current_period_end = $8, grace_until = $9, next_charge_at = $10, "
            "cancel_requested_at = $11, cancel_channel = $12, msisdn_ciphertext = $13, msisdn_hmac = $14, operator = $15, "
            "attempt = $16, charge_pending = $17, row_version = row_version + 1, updated_at = now() "
            "WHERE id = $1 AND row_version = $18 RETURNING *",
            uuid.UUID(sub.id), sub.plan_code.value, sub.plan_version, sub.provider.value, sub.provider_subscription_id,
            sub.status.value, sub.current_period_start, sub.current_period_end, sub.grace_until, sub.next_charge_at,
            sub.cancel_requested_at, sub.cancel_channel.value if sub.cancel_channel else None, sub.msisdn_ciphertext,
            sub.msisdn_hmac, sub.operator, sub.attempt, sub.charge_pending, expected_version,
        )
        if r is None:
            raise ConflictError("subscription changed concurrently")
        return _sub(r)

    async def delete_subscription(self, sub_id: str) -> None:
        await self._c.execute("DELETE FROM subscriptions WHERE id = $1", uuid.UUID(sub_id))

    async def get_subscription_by_provider_ref(self, provider: str, provider_subscription_id: str) -> Optional[Subscription]:
        r = await self._c.fetchrow(
            "SELECT * FROM subscriptions WHERE provider = $1 AND provider_subscription_id = $2", provider, provider_subscription_id,
        )
        return _sub(r) if r else None

    async def list_subscriptions_by_msisdn_hmac(self, msisdn_hmac: str) -> Sequence[Subscription]:
        rows = await self._c.fetch("SELECT * FROM subscriptions WHERE msisdn_hmac = $1", msisdn_hmac)
        return [_sub(r) for r in rows]

    async def list_subscriptions_for_account(self, account_id: str) -> Sequence[Subscription]:
        rows = await self._c.fetch(
            "SELECT * FROM subscriptions WHERE payer_account_id = $1 ORDER BY created_at", uuid.UUID(account_id),
        )
        return [_sub(r) for r in rows]

    async def list_due_renewals(self, *, now: datetime, limit: int = 100) -> Sequence[Subscription]:
        rows = await self._c.fetch(
            "SELECT * FROM subscriptions WHERE status IN ('active', 'grace') AND next_charge_at <= $1 "
            "AND cancel_requested_at IS NULL ORDER BY next_charge_at LIMIT $2 FOR UPDATE SKIP LOCKED",
            now, limit,
        )
        return [_sub(r) for r in rows]

    async def list_pending_older_than(self, *, cutoff: datetime, limit: int = 100) -> Sequence[Subscription]:
        rows = await self._c.fetch(
            "SELECT * FROM subscriptions WHERE status = 'pending' AND created_at <= $1 ORDER BY created_at LIMIT $2",
            cutoff, limit,
        )
        return [_sub(r) for r in rows]

    async def list_expiring(self, *, now: datetime, limit: int = 100) -> Sequence[Subscription]:
        rows = await self._c.fetch(
            "SELECT * FROM subscriptions WHERE (status = 'grace' AND grace_until <= $1) "
            "OR (status = 'cancel_at_period_end' AND current_period_end <= $1) ORDER BY created_at LIMIT $2",
            now, limit,
        )
        return [_sub(r) for r in rows]

    # ── seats ──

    async def list_seats(self, sub_id: str, *, active_only: bool = True) -> Sequence[Seat]:
        rows = await self._c.fetch(
            "SELECT * FROM seats WHERE subscription_id = $1 AND (released_at IS NULL OR NOT $2) ORDER BY claimed_at",
            uuid.UUID(sub_id), active_only,
        )
        return [_seat(r) for r in rows]

    async def get_active_seat_for_device(self, device_id: str) -> Optional[Seat]:
        r = await self._c.fetchrow("SELECT * FROM seats WHERE device_id = $1 AND released_at IS NULL", uuid.UUID(device_id))
        return _seat(r) if r else None

    async def add_seat(self, seat: Seat) -> None:
        import asyncpg

        try:
            async with self._c.transaction():
                await self._c.execute(
                    "INSERT INTO seats (subscription_id, device_id, role, claimed_at) VALUES ($1, $2, $3, $4)",
                    uuid.UUID(seat.subscription_id), uuid.UUID(seat.device_id), seat.role.value, seat.claimed_at,
                )
        except asyncpg.UniqueViolationError as e:
            raise ConflictError("device already has a seat") from e

    async def release_seat(self, sub_id: str, device_id: str, *, released_at: datetime) -> bool:
        status = await self._c.execute(
            "UPDATE seats SET released_at = $3 WHERE subscription_id = $1 AND device_id = $2 AND released_at IS NULL",
            uuid.UUID(sub_id), uuid.UUID(device_id), released_at,
        )
        return status.endswith(" 1")

    # ── claim codes ──

    async def create_claim_code(self, code: ClaimCode) -> None:
        import asyncpg

        try:
            async with self._c.transaction():
                await self._c.execute(
                    "INSERT INTO claim_codes (id, subscription_id, code_hmac, purpose, expires_at) VALUES ($1, $2, $3, $4, $5)",
                    uuid.UUID(code.id), uuid.UUID(code.subscription_id), code.code_hmac, code.purpose.value, code.expires_at,
                )
        except asyncpg.UniqueViolationError as e:
            raise ConflictError("claim code collision") from e

    async def get_claim_code(self, code_hmac: str, *, for_update: bool = False) -> Optional[ClaimCode]:
        suffix = " FOR UPDATE" if for_update else ""
        r = await self._c.fetchrow(f"SELECT * FROM claim_codes WHERE code_hmac = $1{suffix}", code_hmac)
        return _code(r) if r else None

    async def redeem_claim_code(self, code_id: str, *, device_id: str, redeemed_at: datetime) -> bool:
        r = await self._c.fetchrow(
            "UPDATE claim_codes SET redeemed_at = $2, redeemed_by_device = $3 WHERE id = $1 AND redeemed_at IS NULL "
            "RETURNING id",
            uuid.UUID(code_id), redeemed_at, uuid.UUID(device_id),
        )
        return r is not None

    # ── payments ──

    async def create_payment(self, payment: Payment) -> Payment:
        r = await self._c.fetchrow(
            "INSERT INTO payments (id, subscription_id, provider, provider_payment_id, idempotency_key, amount_kopecks, "
            "status, failure_reason, period_start, period_end, receipt_url, created_at) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) ON CONFLICT (idempotency_key) DO NOTHING RETURNING *",
            uuid.UUID(payment.id), uuid.UUID(payment.subscription_id), payment.provider.value, payment.provider_payment_id,
            payment.idempotency_key, payment.amount_kopecks, payment.status.value,
            payment.failure_reason.value if payment.failure_reason else None, payment.period_start, payment.period_end,
            payment.receipt_url, payment.created_at,
        )
        if r is not None:
            return _payment(r)
        existing = await self.get_payment_by_idempotency_key(payment.idempotency_key)
        assert existing is not None
        return existing

    async def get_payment(self, payment_id: str) -> Optional[Payment]:
        r = await self._c.fetchrow("SELECT * FROM payments WHERE id = $1", uuid.UUID(payment_id))
        return _payment(r) if r else None

    async def get_payment_by_idempotency_key(self, key: str) -> Optional[Payment]:
        r = await self._c.fetchrow("SELECT * FROM payments WHERE idempotency_key = $1", key)
        return _payment(r) if r else None

    async def get_payment_by_provider_id(self, provider: str, provider_payment_id: str) -> Optional[Payment]:
        r = await self._c.fetchrow(
            "SELECT * FROM payments WHERE provider = $1 AND provider_payment_id = $2", provider, provider_payment_id,
        )
        return _payment(r) if r else None

    async def update_payment(self, payment: Payment) -> None:
        await self._c.execute(
            "UPDATE payments SET provider_payment_id = $2, status = $3, failure_reason = $4, period_start = $5, "
            "period_end = $6, receipt_url = $7 WHERE id = $1",
            uuid.UUID(payment.id), payment.provider_payment_id, payment.status.value,
            payment.failure_reason.value if payment.failure_reason else None, payment.period_start, payment.period_end,
            payment.receipt_url,
        )

    async def list_pending_payments_older_than(self, *, cutoff: datetime, limit: int = 100) -> Sequence[Payment]:
        rows = await self._c.fetch(
            "SELECT * FROM payments WHERE status = 'pending' AND created_at <= $1 ORDER BY created_at LIMIT $2", cutoff, limit,
        )
        return [_payment(r) for r in rows]

    async def list_payments(self, sub_id: str) -> Sequence[Payment]:
        rows = await self._c.fetch("SELECT * FROM payments WHERE subscription_id = $1 ORDER BY created_at", uuid.UUID(sub_id))
        return [_payment(r) for r in rows]

    # ── webhooks, consents, audit ──

    async def insert_event(self, *, provider: str, provider_event_id: str, signature_ok: bool,
                           payload_ciphertext: bytes) -> Optional[int]:
        event_id = await self._c.fetchval(
            "INSERT INTO billing_events (provider, provider_event_id, signature_ok, payload_ciphertext) "
            "VALUES ($1, $2, $3, $4) ON CONFLICT (provider, provider_event_id) DO NOTHING RETURNING id",
            provider, provider_event_id, signature_ok, payload_ciphertext,
        )
        return int(event_id) if event_id is not None else None

    async def mark_event_processed(self, event_id: int, *, processed_at: datetime, outcome: str) -> None:
        await self._c.execute(
            "UPDATE billing_events SET processed_at = $2, outcome = $3 WHERE id = $1", event_id, processed_at, outcome,
        )

    async def add_consent(self, consent: Consent) -> Consent:
        r = await self._c.fetchrow(
            "INSERT INTO consents (account_id, subscription_id, kind, doc_version, doc_sha256, shown_price_kopecks, "
            "shown_plan_code, method, provider_confirmation_ref, ip_hmac, created_at) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *",
            uuid.UUID(consent.account_id), uuid.UUID(consent.subscription_id) if consent.subscription_id else None,
            consent.kind.value, consent.doc_version, consent.doc_sha256, consent.shown_price_kopecks,
            consent.shown_plan_code.value if consent.shown_plan_code else None, consent.method,
            consent.provider_confirmation_ref, consent.ip_hmac, consent.created_at,
        )
        return _consent(r)

    async def list_consents(self, account_id: str) -> Sequence[Consent]:
        rows = await self._c.fetch("SELECT * FROM consents WHERE account_id = $1 ORDER BY id", uuid.UUID(account_id))
        return [_consent(r) for r in rows]

    async def add_audit(self, *, actor: str, action: str, target: str, meta: Mapping[str, Any]) -> AuditRow:
        r = await self._c.fetchrow(
            "INSERT INTO billing_audit (actor, action, target, meta) VALUES ($1, $2, $3, $4) RETURNING *",
            actor, action, target, dict(meta),
        )
        return _audit(r)

    async def list_audit(self, target: str) -> Sequence[AuditRow]:
        rows = await self._c.fetch("SELECT * FROM billing_audit WHERE target = $1 ORDER BY id", target)
        return [_audit(r) for r in rows]

    # ── idempotent responses ──

    async def get_idempotent_response(self, scope: str, key: str) -> Optional[IdempotentResponse]:
        r = await self._c.fetchrow("SELECT * FROM idempotency_keys WHERE scope = $1 AND key = $2", scope, key)
        if r is None:
            return None
        return IdempotentResponse(scope=r["scope"], key=r["key"], status_code=r["status_code"], body=r["body"],
                                  created_at=r["created_at"])

    async def put_idempotent_response(self, response: IdempotentResponse) -> None:
        await self._c.execute(
            "INSERT INTO idempotency_keys (scope, key, status_code, body, created_at) VALUES ($1, $2, $3, $4, $5) "
            "ON CONFLICT (scope, key) DO NOTHING",
            response.scope, response.key, response.status_code, dict(response.body), response.created_at,
        )


def _sub_values(sub: Subscription) -> tuple:
    return (
        uuid.UUID(sub.id), uuid.UUID(sub.payer_account_id), sub.plan_code.value, sub.plan_version, sub.provider.value,
        sub.provider_subscription_id, sub.status.value, sub.current_period_start, sub.current_period_end,
        sub.grace_until, sub.next_charge_at, sub.cancel_requested_at,
        sub.cancel_channel.value if sub.cancel_channel else None, sub.msisdn_ciphertext, sub.msisdn_hmac,
        sub.operator, sub.attempt, sub.charge_pending, sub.row_version, sub.created_at, sub.updated_at,
    )

