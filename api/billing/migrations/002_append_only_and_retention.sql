-- Append-only tables and the application role.
--
-- Run AFTER creating the application role the service connects as:
--   CREATE ROLE cleanway_billing_app LOGIN PASSWORD '...';
-- The migration runner skips the GRANT/REVOKE block when the role is
-- absent (local development), and applies it in production so that the
-- consent journal, the audit trail and the webhook log can only grow.

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cleanway_billing_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON plans, accounts, devices, trials, subscriptions,
      seats, claim_codes, payments, idempotency_keys TO cleanway_billing_app;
    GRANT SELECT, INSERT ON consents, billing_audit, billing_events TO cleanway_billing_app;
    -- billing_events is updated exactly once (processed_at, outcome) after a webhook is applied.
    GRANT UPDATE (processed_at, outcome) ON billing_events TO cleanway_billing_app;
    REVOKE DELETE ON consents, billing_audit, billing_events FROM cleanway_billing_app;
    REVOKE UPDATE ON consents, billing_audit FROM cleanway_billing_app;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO cleanway_billing_app;
  END IF;
END $$;

-- Retention helper: once a subscription is over and the accounting period
-- (default 5 years, confirm with the accountant) has passed, the phone
-- number ciphertext is nulled while the payment rows stay for the books.
CREATE OR REPLACE FUNCTION billing_purge_msisdn(retention INTERVAL DEFAULT INTERVAL '5 years')
RETURNS INT
LANGUAGE plpgsql AS $$
DECLARE
  purged INT;
BEGIN
  UPDATE subscriptions
     SET msisdn_ciphertext = NULL, msisdn_hmac = NULL, updated_at = now()
   WHERE status IN ('lapsed', 'refunded')
     AND msisdn_ciphertext IS NOT NULL
     AND COALESCE(current_period_end, updated_at) < now() - retention;
  GET DIAGNOSTICS purged = ROW_COUNT;
  RETURN purged;
END $$;
