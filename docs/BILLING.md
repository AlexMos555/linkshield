# Operator-billed subscriptions (Russia) — `api/billing`

**Status: built, switched off.** `BILLING_ENABLED=false` is the default; with it
nothing in this package is mounted, scheduled or connected. Flipping it is the
founder's decision and is gated on five conditions (plan §3): a working
aggregator contract, the database in Russia, the published offer, a one-tap
cancel verified on a real number, and the MAX/VPN question closed.

Product rules this package implements (from the founder's plan, 2026-09-29):

| Rule | Where |
|---|---|
| 99 ₽ / 1 phone, 270 ₽ / up to 3, 399 ₽ / up to 5, monthly, billed to the phone account | `BILLING_PRICE_*_RUB` settings → `context.plan_catalog` |
| Trial: 14 days, full protection, **no phone number and no consent asked** | `BILLING_TRIAL_DAYS`, `service/trial.py` |
| One trial per phone (HMAC of the app's fingerprint; a reinstall gets the **same** trial back — same start, same end — moved to the new install, never a second one) | `trials.device_fingerprint_hmac`, `service/trial.py` |
| Non-payment: 7-day grace with full protection, retries on days 1/3/5/7, never "in the red" | `BILLING_GRACE_DAYS`, `BILLING_RETRY_DAYS`, `state_machine.py` |
| After grace: `lapse_policy = basic` (blocking continues, weekly list, yellow shield) or `off` — **default `basic`, founder undecided, both built** | `BILLING_LAPSE_POLICY`, carried in every device pass |
| Promo and partner (`t2_option`) grants end at their period end and lapse into the same policy | `scheduler.run_expiries`, `state_machine.TermEnded` |
| One paying subscription per phone number: a reinstall cannot buy again while the old subscription charges the same number | `service/checkout.py` (`subscription_exists_for_number`) |
| Cancel = not one more charge (376-ФЗ); five channels, one tap in the app, phone number on the website | `service/cancel.py`, `/subscription/cancel`, `/cancel-by-phone` |
| The seller proves consent: what text, what price, how confirmed | `consents` table, `consent_texts/ru/v1.md`, `service/effects.py` |
| Phone numbers and payments live in a **separate database** (152-ФЗ, Russian host), encrypted at rest; card data is never stored | `DATABASE_URL_BILLING`, `migrations/`, `crypto.py` |
| The main API never sees a phone number: the phone carries a signed pass with no personal data | `entitlement.py` |
| The landing's "blocking stays free" promise is untouched; grandfathering is `devices.legacy_free` | `service/passes.py` |

## Architecture

```
 phone (RN app)                      ROLE=billing (Russia)                         providers
 ┌──────────────────┐   HTTPS   ┌──────────────────────────────────┐   HTTPS   ┌─────────────┐
 │ device secret    │ ────────► │ /billing/v1                       │ ◄───────► │ MIXPLAT     │
 │ signed pass      │ ◄──────── │ plans · trial · checkout · seats  │  webhook  │ Promo       │
 │ (offline rule)   │           │ cancel · webhooks · partner       │ ◄──────── │ T2 (stub)   │
 └──────────────────┘           │ Postgres: numbers encrypted       │           │ Fake (dev)  │
        │ X-Cleanway-Entitlement└──────────────────────────────────┘           └─────────────┘
        ▼
 ROLE=api (Railway): verifies the pass with the public key; no phone numbers, no billing tables.
```

One image, two roles. `ROLE=billing` mounts `/billing/v1` and opens
`DATABASE_URL_BILLING`; `ROLE=api` (Railway today) never does, even if the
flag leaks into its environment (`BillingSettings.routes_enabled()` needs both).

## Layout

```
api/billing/
  settings.py        BillingSettings — every number the founder may change (env names below)
  models.py          frozen dataclasses, one per table
  state_machine.py   apply(state, event, now, policy) → Transition(state, effects)   [pure]
  entitlement.py     the device pass: Ed25519 JWS, key rotation, the app's offline rule
  crypto.py          E.164 normalisation, AES-256-GCM at rest, domain-separated HMACs, codes
  consents.py + consent_texts/ru/v1.md   versioned confirmation-screen text, sha256 in every consent row
  store/             repository interface; memory.py (tests/demo) and postgres.py (asyncpg)
  migrations/        001 schema, 002 append-only grants + msisdn purge function, 003 webhook retry columns
  migrate.py         `python -m api.billing.migrate` — applies migrations once each
  providers/         base.py (interface), fake.py, promo.py, mixplat.py, t2.py, registry.py
  service/           devices, trial, passes, checkout (+ provider events), webhooks, seats, cancel, effects, plan_change
  scheduler.py       renewals · pending timeouts · expiries · reconciliation · unmatched-webhook retries (run_once; NOT wired to cron)
  partner.py         /partner/licenses skeleton (T2 "option" model)
  router.py, deps.py, mount.py, bootstrap.py, context.py
tests/billing/       state machine (exhaustive + random sequences), pass, crypto, settings,
                     store (memory always, Postgres when BILLING_TEST_DATABASE_URL is set),
                     providers (MIXPLAT signatures against the docs' own examples), flows, router
```

## Subscription lifecycle (plan A.4)

States: `pending → active ⇄ grace → lapsed`, `active|grace → cancel_at_period_end → lapsed`,
`refunded`. `state_machine.apply` is a pure function with an explicit table; a
(status, event) pair outside the table raises `InvalidTransition`.

Invariants pinned by tests (`tests/billing/test_state_machine.py`, 300 random
sequences): no `Charge` after `cancel_requested_at`; a `Charge` only in
`active`/`grace`; a period is paid at most once (a success extends the period
only when a charge for it is pending, settles one of our own charge rows that
had no final answer yet, or the provider itself initiated it); after grace the
device mode is exactly `policy.lapse_policy`. `TermEnded` lapses an `active`
fixed-term grant (promo, `t2_option`) at its period end.

Renewals are keyed `{subscription}:{period_start}:{attempt}` (`payments.idempotency_key`
UNIQUE), so a scheduler pass that runs twice cannot charge twice.

## Money safety: no provider call inside a transaction (2026-10)

A provider call is never made while a database transaction is open, so a
later failure can never roll back the record of money that moved.

| Flow | Step 1 — commit | Step 2 — call (nothing locked) | Step 3 — commit |
|---|---|---|---|
| Renewal (`scheduler._renew_one`, one unit per subscription) | payment row `pending` under the key + `charge_pending` on the subscription | `charge_renewal(idempotency_key=key)` | provider payment id; or a refusal → payment `failed`, `PaymentFailed` (grace, retries); or no answer → row stays `pending` |
| Checkout (`service/checkout.start_checkout`, outbox-style) | pending subscription, owner seat, consent, checkout payment row (`{sub}:checkout`) | `start_checkout(idempotency_key=…)` | provider reference; or a refusal → intent closed (`checkout.closed`); or no answer → intent kept, the app gets `provider_error` |

- **No answer (timeout, 5xx, adapter crash)** means *we do not know whether
  money moved*. The provider is never called again for that key. The
  reconciler (`run_reconciliation`, payments pending ≥ 30 min) asks
  `fetch_status` with the provider's reference when we have one **and our own
  key** (`merchant_payment_id` — MIXPLAT's `get_payment_status` accepts it),
  so a renewal whose answer was lost is found. A payment still unresolved
  after 24 h is logged at error level (`billing.payment.unresolved`).
- **A late success is applied.** A success for one of our renewal rows that is
  still `pending` (or that we marked `failed` after a refusal) extends the
  period (`PaymentSucceeded.settles_charge`), instead of being ignored as
  `payment.unexpected_success` and leaving the key blocked as `charge.already_settled`.
- **Pending timeout** (`run_pending_timeouts`) asks the provider first; a
  checkout the provider still reports as in progress is kept up to 24 h
  (`CHECKOUT_MAX_WAIT`) before it is closed.
- **One failing subscription does not stop the pass**: each renewal is
  wrapped, logged (`billing.renewal.failed`) and the pass moves on.

## Webhooks

1. Optional source allowlist: `BILLING_MIXPLAT_WEBHOOK_IPS` (comma-separated
   IPs / CIDRs; **empty = off**, the default — MIXPLAT does not publish its
   addresses, ask the manager). The client address is the one the rate limiter
   uses (`X-Forwarded-For` only from `TRUSTED_PROXY_CIDRS`). Outside the list → 403.
2. Signature. MIXPLAT's `payment_status` md5 covers **only `payment_id` + API key**
   — not the status, the amount or the currency.
3. **Every MIXPLAT success is re-checked**: the service calls `get_payment_status`
   and uses *its* status, amount and currency. It must say `success`, the amount
   must equal our payment row's `amount_kopecks` (the plan version's price) and
   the currency, when given, must be roubles (`RUB`/`RUR`/`643`); a missing amount
   or a missing payment row is a mismatch too. A mismatch is not applied
   (`amount_mismatch` / `not_confirmed`, audit row, error-level log). When the
   status call fails the webhook is answered 503 and nothing is stored, so the
   redelivery is processed in full (and the reconciler asks on its own anyway).
   To confirm with the MIXPLAT manager: that `amount` (not `amount_merchant`)
   is what the subscriber paid, the currency field's name, and that
   `get_payment_status` returns `recurrent_id` (until then the notification's
   value is used when the status lacks it).
4. Stored once per `(provider, event id)`; applied on the locked subscription.
5. **Unmatched** (no subscription or payment found): the event is kept with its
   normalised form encrypted (`billing_events.event_ciphertext`), logged at
   error level (`billing.webhook.unmatched` → Sentry) and retried by
   `run_unmatched_events` on every scheduler pass, ≈ 7 days
   (`UNMATCHED_MAX_ATTEMPTS`), then marked `unmatched_abandoned` with another
   error-level log — a person must look (refund or attach by hand).

## The device pass (plan A.5)

Compact JWS, `alg=EdDSA`, header `kid`; payload
`{v, dev, mode, src, plan, until, grace_until, lapse_policy, iat, exp}` — no
personal data. Signed by the billing role (`BILLING_ENTITLEMENT_PRIVATE_KEY`,
32-byte seed, base64); verified by the app and the api role with
`BILLING_ENTITLEMENT_PUBLIC_KEYS` (`{"kid": "<base64>"}`, several keys during
rotation). `entitlement.generate_keypair()` prints a pair.

Offline rule (`entitlement.offline_mode`, to be ported 1:1 to `mobile/src/lib/entitlement.ts`):
the device clock is clamped to `≥ iat`; before `until` → the issued mode; inside
the grace window → still the issued mode; after both → `lapse_policy`;
`until = null` → the mode holds until a newer pass (legacy free, lapsed).
`exp` (7 days) is the signature's validity for the **server**; the app keeps
using an expired pass offline because that is all it has.

## API — `/billing/v1` (plan A.6)

Envelope `{success, data, error:{code,message}}`. Device auth: `Authorization: Bearer <device_secret>`
(the server keeps SHA-256). `Idempotency-Key` (≤128 chars) on the POSTs marked ⟲ replays the stored answer.

| Method | Path | Auth | Limits |
|---|---|---|---|
| POST | `/devices` | — | per IP |
| POST | `/trial` | device | — |
| GET | `/entitlement` | device | — |
| GET | `/plans` | — | per IP |
| POST ⟲ | `/checkout` `{plan_code, provider, msisdn?, consent_doc_version, consent_method}` — 409 `subscription_exists_for_number` / `checkout_in_progress_for_number` with `error.details.msisdn_masked` | device | per device, per phone (HMAC) |
| GET | `/checkout/{id}` | device | — |
| POST | `/subscription/cancel` | payer | — |
| POST | `/cancel-by-phone` `{msisdn}` | — (no proof of the number yet — see open questions) | per IP; **per number, 3 a day**; always the same answer |
| POST ⟲ | `/subscription/codes` | payer | — |
| POST | `/claim` `{code}` | device | per device, per IP |
| GET | `/subscription/devices` | device | — |
| DELETE | `/subscription/seats/{device_id}` | payer | — |
| POST | `/webhooks/{provider}` | provider signature | per IP / minute |
| POST | `/partner/licenses` | `X-Partner-Signature` HMAC | per IP |

Limits reuse `api/services/rate_limiter.py` (Redis; fail-open in dev,
fail-closed with `RATE_LIMIT_FAIL_CLOSED=true`). The billing role therefore
needs a Redis too.

## Providers (plan A.7)

| Adapter | State | Notes |
|---|---|---|
| `FakeProvider` | dev/tests only (`BILLING_FAKE_PROVIDER_ENABLED=true`) | outcome scripted by number: `+79030000000` no money, `…0001` payments banned, `…0002` passport, `…0003` corporate, `…0004` declined, `…0005` never answers; webhooks signed with `X-Fake-Signature` |
| `PromoProvider` | ready | support/partner grants, no money, no webhooks, every grant in `billing_audit` |
| `MixplatProvider` | code ready, **disabled without `BILLING_MIXPLAT_PROJECT_ID` + `_API_KEY`** | written against docs.mixplat.ru (2026-09-29); the four md5 signature formulas are pinned to the docs' own examples. Uncertain, to confirm with the MIXPLAT manager: `request_id` in the `create_payment_form` signature; operator-specific failure codes (banned / passport / corporate map to `other`); no documented "stop recurrent" call (we simply stop initiating); webhook source IPs; `amount` vs `amount_merchant`; the currency field; `recurrent_id` in `get_payment_status`; no documented method to send an SMS |
| `T2DirectProvider` | stub | `NotConfiguredError` everywhere; contract test only |
| T2 "option" | skeleton | `/partner/licenses` → activation code; first phone to redeem becomes the owner |
| RuStore Pay | not started | needs the founder's RuStore account (plan A.14 item 8) |

## Scheduler (plan A.8) — not wired

`python -m api.billing.scheduler` runs one pass: unmatched-webhook retries,
reconciliation (payments pending ≥30 min → `fetch_status` by reference and by
our key), pending timeouts (30 min; never while the provider says the payment
is under way, up to 24 h), renewals (only providers with `initiates_renewals`;
one committed unit per subscription, see "Money safety"), expiries (grace →
lapsed, cancelled period end → lapsed, promo / `t2_option` term end → lapsed).
Wire it as a 15-minute job on the billing host **only after the flag is on**;
nothing calls it today.

## Settings (env names)

| Env | Default | Meaning |
|---|---|---|
| `BILLING_ENABLED` | `false` | the founder's switch |
| `ROLE` | `api` | `billing` mounts the routes |
| `ENVIRONMENT` | `development` | the main API's variable; `production` makes startup refuse test-mode payments and the Fake provider |
| `DATABASE_URL_BILLING` | — | the Russian Postgres; `memory://` for a local demo |
| `BILLING_PRICE_SOLO_RUB` / `_FAMILY3_RUB` / `_FAMILY5_RUB` | 99 / 270 / 399 | prices (a change never touches running subscriptions: plans are versioned) |
| `BILLING_PLAN_VERSION` | `1` | catalogue version for new sales; bump it with any price change (startup refuses a new price under a stored version); renewals charge the subscription's own version |
| `BILLING_TRIAL_DAYS` / `BILLING_GRACE_DAYS` | 14 / 7 | |
| `BILLING_LAPSE_POLICY` | `basic` | `basic` or `off` |
| `BILLING_RETRY_DAYS` | `1,3,5,7` | days after period end |
| `BILLING_PENDING_TIMEOUT_MINUTES` / `BILLING_CLAIM_CODE_TTL_HOURS` / `BILLING_PASS_TTL_DAYS` | 30 / 24 / 7 | |
| `BILLING_ENTITLEMENT_PRIVATE_KEY` / `_KEY_ID` / `_PUBLIC_KEYS` | — / `2026-09` / — | pass keys |
| `BILLING_MSISDN_KEY` / `BILLING_HMAC_KEY` | — | AES-256-GCM key, HMAC key (base64, 32 bytes) |
| `BILLING_FAKE_PROVIDER_ENABLED` | `false` | never in production |
| `BILLING_MIXPLAT_PROJECT_ID` / `_API_KEY` / `_TEST` / `_BASE_URL` | — / — / `true` / `https://api.mixplat.com` | `_TEST=true` is the sandbox (no real money): **refused at startup in `ENVIRONMENT=production`** |
| `BILLING_MIXPLAT_TEST_ALLOWED_IN_PRODUCTION` | `false` | the explicit override for a deliberate sandbox run on the production host (logged as a warning) |
| `BILLING_MIXPLAT_WEBHOOK_IPS` | — (off) | optional webhook source allowlist, comma-separated IPs / CIDRs; malformed → startup fails |
| `BILLING_PARTNER_HMAC_KEY` | — | `/partner/licenses` |
| `BILLING_CONSENT_DOC_VERSION` | `ru/v1` | the app must echo the version it showed |
| `BILLING_*_PER_HOUR` | see `settings.py` | rate limits |
| `BILLING_CANCEL_BY_PHONE_PER_PHONE_PER_DAY` | `3` | `/cancel-by-phone` per number (HMAC), whatever the IP |

`validate_billing_settings` fails at startup (ConfigError) when the billing
role is on without a database URL, with malformed keys or a malformed webhook
allowlist, or — in `ENVIRONMENT=production` — with `BILLING_MIXPLAT_TEST=true`
(unless `BILLING_MIXPLAT_TEST_ALLOWED_IN_PRODUCTION=true`) or the Fake provider on.

## Running locally with the Fake provider

```bash
pip install -r requirements-dev.txt          # cryptography, asyncpg are in requirements.txt
python - <<'EOF'
from api.billing.entitlement import generate_keypair; print(generate_keypair())
EOF
export BILLING_ENABLED=true ROLE=billing DATABASE_URL_BILLING=memory:// \
       BILLING_FAKE_PROVIDER_ENABLED=true \
       BILLING_ENTITLEMENT_PRIVATE_KEY=<seed from above> \
       BILLING_MSISDN_KEY=$(openssl rand -base64 32) BILLING_HMAC_KEY=$(openssl rand -base64 32)
uvicorn api.main:app --reload
```

Then: `POST /billing/v1/devices` → `POST /trial` → `POST /checkout` with
`provider: "fake"`, `msisdn: "+79150000000"`, `consent_doc_version: "ru/v1"`
→ deliver the "SMS" yourself: build the body with
`FakeProvider().event_payload(<provider_subscription_id>)` and `sign()`, POST it
to `/webhooks/fake` → `GET /entitlement` shows `mode: full, src: subscription`.
Use `+79030000000` to see the "no money" path. With a real Postgres:
`DATABASE_URL_BILLING=postgresql://… python -m api.billing.migrate` first.

Tests: `pytest tests/billing` (memory store); set
`BILLING_TEST_DATABASE_URL=postgresql://…/billing_test` to also run the store
contract and the migrations against Postgres (the schema is dropped and recreated).

## Not in this PR (open)

- `POST /subscription/change-plan` (the day arithmetic is in `service/plan_change.py`, tested; the endpoint and its second consent are not).
- `/support/*` (search by number, promo issue, refunds with audit) — the service functions exist (`PromoProvider`, `allow_grant`), the routes and the support token do not.
- RuStore Pay adapter; the real T2 integration.
- Receipts (54-ФЗ): who issues them is an aggregator question.
- **Re-linking a number to a new install** (TODO, design only). Today a reinstalled
  app that names a number with a live subscription gets `subscription_exists_for_number`
  and is not charged; the old subscription stays on the old (uninstalled) device's
  account. Planned flow: `POST /subscription/relink {msisdn}` (device auth; per-number
  and per-device limits; the same answer whether or not a subscription exists) sends a
  one-time code to the number → `POST /subscription/relink/confirm {code}` in ONE
  transaction locks the subscription, releases the old owner seat, adds an `owner` seat
  for the new device, sets `payer_account_id` to the new device's account (relatives'
  seats stay), and writes `subscription.relinked` to `billing_audit`. It needs the same
  SMS channel as below; until then support re-links by hand after checking the
  operator's charge SMS, with an audit row.
- **`/cancel-by-phone` proof of the number** (open legal/ops question). The endpoint
  stays (consumer protection: cancelling must be as easy as subscribing). It cannot
  send a one-time code: `providers/mixplat.py` and the MIXPLAT documentation it was
  written from describe payments, recurrents, statuses and refunds — **no method to
  send an SMS** — and no other SMS gateway is contracted. So anyone who knows a number
  can cancel its renewal; the payer keeps access to the end of the paid period, sees
  `cancelled_until_period_end` in the app and can subscribe again. Mitigation built: a
  strict per-number limit (`BILLING_CANCEL_BY_PHONE_PER_PHONE_PER_DAY`, 3) on top of the
  per-IP one. To decide: whether a confirmation step is lawful for a cancel at all
  (376-ФЗ / ЗоЗПП — ask the lawyer), and if so which channel sends the code (ask the
  MIXPLAT manager about SMS; otherwise an SMS gateway contract).
- `subscription_exists_for_number` tells a device that a number has a live subscription
  (needed to stop a double charge); it is bounded by the per-device and per-number
  checkout limits.
- Hosting: Yandex Cloud Managed PostgreSQL + Lockbox for the keys (plan A.14 item 5) — needs the founder's account.
