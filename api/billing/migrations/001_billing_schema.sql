-- Cleanway billing schema — the SEPARATE Russian database (152-ФЗ).
--
-- Applied by `python -m api.billing.migrate` (tracks itself in
-- billing_schema_migrations). Never applied to Supabase. Phone numbers are
-- stored only as AES-256-GCM ciphertext plus an HMAC; card data is never
-- stored anywhere. See docs/BILLING.md and docs/PRIVACY.md.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Catalogue. A price is a version: changing it never touches running subscriptions.
CREATE TABLE IF NOT EXISTS plans (
  code TEXT NOT NULL CHECK (code IN ('solo', 'family3', 'family5')),
  version INT NOT NULL,
  seats INT NOT NULL CHECK (seats BETWEEN 1 AND 10),
  price_kopecks INT NOT NULL CHECK (price_kopecks > 0),
  period TEXT NOT NULL DEFAULT 'P1M',
  provider_product_ids JSONB NOT NULL DEFAULT '{}',   -- {"mixplat": "...", "rustore": "..."}
  active BOOLEAN NOT NULL DEFAULT true,
  PRIMARY KEY (code, version)
);

-- An account is a random UUID: no e-mail, no password (plan A.2).
CREATE TABLE IF NOT EXISTS accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  display_label TEXT,                  -- how relatives see the payer ("Ирина"), optional
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id UUID NOT NULL REFERENCES accounts(id),
  secret_sha256 TEXT NOT NULL UNIQUE,  -- bearer secret; the raw value lives only in the phone's Keystore
  platform TEXT NOT NULL CHECK (platform IN ('android', 'ios')),
  app_version TEXT,
  legacy_free BOOLEAN NOT NULL DEFAULT false,   -- installed before the paid release (§2.3)
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen TIMESTAMPTZ
);

-- One trial per phone: HMAC(ANDROID_ID, server key). The raw id is never stored.
CREATE TABLE IF NOT EXISTS trials (
  device_fingerprint_hmac TEXT PRIMARY KEY,
  device_id UUID NOT NULL REFERENCES devices(id),
  started_at TIMESTAMPTZ NOT NULL,
  ends_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  payer_account_id UUID NOT NULL REFERENCES accounts(id),
  plan_code TEXT NOT NULL,
  plan_version INT NOT NULL,
  provider TEXT NOT NULL CHECK (provider IN ('fake', 'promo', 'mixplat', 'rustore', 't2_direct', 't2_option')),
  provider_subscription_id TEXT,
  status TEXT NOT NULL CHECK (status IN
    ('pending', 'active', 'grace', 'cancel_at_period_end', 'lapsed', 'refunded')),
  current_period_start TIMESTAMPTZ,
  current_period_end TIMESTAMPTZ,
  grace_until TIMESTAMPTZ,
  next_charge_at TIMESTAMPTZ,
  cancel_requested_at TIMESTAMPTZ,
  cancel_channel TEXT CHECK (cancel_channel IS NULL OR cancel_channel IN ('app', 'web', 'support', 'operator_stop', 'provider')),
  msisdn_ciphertext BYTEA,             -- AES-256-GCM; key in Lockbox/KMS, never in this database
  msisdn_hmac TEXT,                    -- lookup for support and /cancel-by-phone without decryption
  operator TEXT,                       -- t2 | mts | beeline | megafon | other
  attempt INT NOT NULL DEFAULT 0,      -- renewal attempt within the current period (state machine)
  charge_pending BOOLEAN NOT NULL DEFAULT false,
  row_version INT NOT NULL DEFAULT 0,  -- optimistic locking
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  FOREIGN KEY (plan_code, plan_version) REFERENCES plans(code, version),
  UNIQUE (provider, provider_subscription_id)
);
CREATE INDEX IF NOT EXISTS subscriptions_due_idx ON subscriptions (next_charge_at)
  WHERE status IN ('active', 'grace');
CREATE INDEX IF NOT EXISTS subscriptions_msisdn_idx ON subscriptions (msisdn_hmac);
CREATE INDEX IF NOT EXISTS subscriptions_pending_idx ON subscriptions (created_at) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS seats (
  subscription_id UUID NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
  device_id UUID NOT NULL REFERENCES devices(id),
  role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'member')),
  claimed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  released_at TIMESTAMPTZ
);
-- A device sits in at most one live subscription. The seat COUNT is enforced
-- in the service inside a transaction that locks the subscription row.
CREATE UNIQUE INDEX IF NOT EXISTS seats_one_active_per_device ON seats (device_id) WHERE released_at IS NULL;
CREATE INDEX IF NOT EXISTS seats_subscription_idx ON seats (subscription_id);

CREATE TABLE IF NOT EXISTS claim_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subscription_id UUID NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
  code_hmac TEXT NOT NULL UNIQUE,      -- 6 digits → HMAC; brute force is bounded by the rate limiter
  purpose TEXT NOT NULL DEFAULT 'seat' CHECK (purpose IN ('seat', 'owner_transfer', 'partner_license')),
  expires_at TIMESTAMPTZ NOT NULL,
  redeemed_at TIMESTAMPTZ,
  redeemed_by_device UUID REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS payments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subscription_id UUID NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  provider_payment_id TEXT,
  idempotency_key TEXT NOT NULL UNIQUE,   -- '{sub_id}:{period_start}:{attempt}'
  amount_kopecks INT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'succeeded', 'failed', 'refunded', 'partially_refunded')),
  failure_reason TEXT,                    -- no_money | payments_banned | passport | corporate | user_declined | timeout | other
  period_start TIMESTAMPTZ,
  period_end TIMESTAMPTZ,
  receipt_url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (provider, provider_payment_id)
);
CREATE INDEX IF NOT EXISTS payments_pending_idx ON payments (created_at) WHERE status = 'pending';

-- Inbound webhooks, append-only. The body may carry a phone number → encrypted.
CREATE TABLE IF NOT EXISTS billing_events (
  id BIGSERIAL PRIMARY KEY,
  provider TEXT NOT NULL,
  provider_event_id TEXT NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  signature_ok BOOLEAN NOT NULL,
  payload_ciphertext BYTEA NOT NULL,
  processed_at TIMESTAMPTZ,
  outcome TEXT,
  UNIQUE (provider, provider_event_id)   -- redelivery = one effect
);

-- Proof of consent, append-only (§2.6: the seller proves consent).
CREATE TABLE IF NOT EXISTS consents (
  id BIGSERIAL PRIMARY KEY,
  account_id UUID NOT NULL,
  subscription_id UUID,
  kind TEXT NOT NULL CHECK (kind IN ('subscription_offer', 'plan_change', 'pd_processing', 'cancel')),
  doc_version TEXT NOT NULL,
  doc_sha256 TEXT NOT NULL,            -- which offer text and confirmation screen was shown
  shown_price_kopecks INT,
  shown_plan_code TEXT,
  method TEXT NOT NULL,                -- sms_code | ussd | rustore | app_button | web_form | ...
  provider_confirmation_ref TEXT,
  ip_hmac TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS consents_account_idx ON consents (account_id);

-- Who did what, including support staff. Append-only.
CREATE TABLE IF NOT EXISTS billing_audit (
  id BIGSERIAL PRIMARY KEY,
  actor TEXT NOT NULL,                 -- device:<id> | support:<login> | system | provider:<code> | partner:<code>
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  meta JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS billing_audit_target_idx ON billing_audit (target);

-- Replayed responses for repeated Idempotency-Key headers (plan A.6).
CREATE TABLE IF NOT EXISTS idempotency_keys (
  scope TEXT NOT NULL,                 -- device id (or another caller identity)
  key TEXT NOT NULL,
  status_code INT NOT NULL,
  body JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (scope, key)
);
