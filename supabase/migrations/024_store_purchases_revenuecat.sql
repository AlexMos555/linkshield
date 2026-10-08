-- Migration 024: store purchases (Google Play, App Store) via RevenueCat.
--
-- docs/ACCOUNTS_BILLING_PLAN.md §11, docs/runbooks/revenuecat.md. The
-- RevenueCat webhook (api/routers/revenuecat.py) writes google_play /
-- app_store rows into `entitlements` (migration 023). It needs:
--
--   * entitlements.product_id      — the store product the row was bought
--     as (e.g. 'cleanway.devices:monthly'): picks the right "manage your
--     subscription" link, and lets "Restore purchases" find the row again.
--   * entitlements.source_event_at — time of the newest source event applied
--     to the row. RevenueCat retries a failed delivery for hours, so an older
--     event (a RENEWAL) can arrive after a newer one (the EXPIRATION); the
--     webhook skips events older than this instead of resurrecting the row.
--   * revenuecat_events            — ids of webhook events already applied.
--     Process-then-mark (like the Stripe webhook): the id is written only
--     AFTER every entitlement write succeeded, so a failed write answers 5xx
--     and RevenueCat's retry is processed again. Holds no personal data
--     (event id, type, time) — nothing to purge on account deletion.
--
-- Idempotent: ADD COLUMN IF NOT EXISTS, CREATE ... IF NOT EXISTS,
-- DROP POLICY IF EXISTS.

BEGIN;

ALTER TABLE public.entitlements
    ADD COLUMN IF NOT EXISTS product_id TEXT
        CHECK (product_id IS NULL OR char_length(product_id) BETWEEN 1 AND 255);
ALTER TABLE public.entitlements
    ADD COLUMN IF NOT EXISTS source_event_at TIMESTAMPTZ;

COMMENT ON COLUMN public.entitlements.product_id IS
    'Store product id the purchase was made as (RevenueCat product_id). NULL for Stripe / operator / promo rows.';
COMMENT ON COLUMN public.entitlements.source_event_at IS
    'Time of the newest source event applied to this row; older (retried, out-of-order) events are skipped.';

CREATE TABLE IF NOT EXISTS public.revenuecat_events (
    event_id     TEXT PRIMARY KEY CHECK (char_length(event_id) BETWEEN 1 AND 255),
    event_type   TEXT NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.revenuecat_events IS
    'RevenueCat webhook event ids already applied (dedupe). Written by the API after a successful entitlement write.';

CREATE INDEX IF NOT EXISTS idx_revenuecat_events_processed_at
    ON public.revenuecat_events(processed_at);

-- Service role only: RLS on, no policies, no grants to anon/authenticated.
ALTER TABLE public.revenuecat_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.revenuecat_events FROM anon, authenticated;

COMMIT;
