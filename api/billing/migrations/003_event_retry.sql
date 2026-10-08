-- Money-safety fixes (2026-10): a verified webhook that matches no
-- subscription is kept for the reconciler instead of being dropped.
--
-- event_ciphertext  the normalised event (AES-256-GCM JSON), so it can be
--                   applied again without the request headers that carried
--                   its signature (the raw body stays in payload_ciphertext);
-- attempts          how many reconciler passes tried it (given up loudly
--                   after the budget in scheduler.UNMATCHED_MAX_ATTEMPTS).

ALTER TABLE billing_events ADD COLUMN IF NOT EXISTS event_ciphertext BYTEA;
ALTER TABLE billing_events ADD COLUMN IF NOT EXISTS attempts INT NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS billing_events_unmatched_idx ON billing_events (id) WHERE outcome = 'unmatched';

-- Fixed-term grants are found by the expiry pass (status active, provider promo / t2_option).
CREATE INDEX IF NOT EXISTS subscriptions_grant_end_idx ON subscriptions (current_period_end)
  WHERE status = 'active' AND provider IN ('promo', 't2_option');

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cleanway_billing_app') THEN
    -- billing_events stays append-only; a retry updates only these three columns.
    GRANT UPDATE (processed_at, outcome, attempts) ON billing_events TO cleanway_billing_app;
  END IF;
END $$;
