-- Migration 020: revoke the over-broad RLS UPDATE policy on
-- typosquat_alerts (adversarial-review #17 finding).
--
-- The original migration 019 added a policy:
--
--   "users update auto_block on own brands"
--
-- gated by EXISTS (subquery into brand_watchlist where user_id =
-- auth.uid() AND brand_root_domain = typosquat_alerts.brand_root_domain).
--
-- That predicate looks correct in isolation but the typosquat_alerts
-- table has NO user_id column — one row is SHARED across every user
-- who watches the same brand. So Alice (watcher of paypal.com) could
-- toggle auto_block=false on the alert for suspect 'paypal-secure.com',
-- and Bob (also watching paypal.com) would silently stop seeing that
-- threat flagged on his /check calls. One user can demote a threat
-- for everyone watching the same brand.
--
-- Until we add per-user dismissals (a new dismissed_alerts table
-- scoped to user_id), the safe move is to REVOKE the UPDATE entirely.
-- The router's PATCH /alerts/{id} endpoint is updated to return 410
-- in the same release. SELECT still works — users see the same
-- alerts they always did.
--
-- Idempotent: only drops if exists.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'typosquat_alerts'
          AND policyname = 'users update auto_block on own brands'
    ) THEN
        DROP POLICY "users update auto_block on own brands"
            ON public.typosquat_alerts;
    END IF;
END$$;
