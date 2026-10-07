-- Migration 023: entitlements — one table for "this account has paid".
--
-- docs/ACCOUNTS_BILLING_PLAN.md §1: an account is the only owner of a
-- purchase. Every way of paying (Stripe on the web, Google Play, App Store,
-- RuStore, the Russian operator subscription, promo codes, partners) writes
-- ONE row here: which account, which source, which external id, until when,
-- how many devices. The API reads the best active row of an account
-- (api/services/entitlements.py); free is the absence of one.
--
-- Today only Stripe writes rows (the webhook, api/routers/payments.py).
-- The other sources are listed so their writers can be added without a
-- schema change. TODO hooks: google_play / app_store (RevenueCat webhook),
-- rustore, operator_ru (api/billing — linking an operator subscription to
-- an account), promo, partner.
--
-- Relationship to public.subscriptions (001/013/021): kept and still written
-- by the Stripe webhook (dual write) because the tier resolver
-- (api/services/auth.py) and the Stripe customer lookups read it. Migration
-- plan:
--   1. (this PR) dual write; entitlements backfilled below from Stripe rows;
--      the API reads entitlements and falls back to subscriptions.
--   2. tier resolver reads entitlements; stripe_customer_id / trial_used_at
--      move to a small stripe_customers table.
--   3. subscriptions becomes a read-only view, then is dropped.
--
-- device_limit is the TOTAL number of devices the row covers (included +
-- extras). Statuses that grant access: active, trialing, past_due (Stripe
-- dunning, same as the old resolver). Writes: service role only.
--
-- Idempotent: IF NOT EXISTS / DROP ... IF EXISTS; the backfill is
-- ON CONFLICT DO NOTHING.

BEGIN;

CREATE TABLE IF NOT EXISTS public.entitlements (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id   UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    source       TEXT NOT NULL CHECK (source IN (
                     'stripe', 'google_play', 'app_store', 'rustore',
                     'operator_ru', 'promo', 'partner')),
    external_id  TEXT NOT NULL CHECK (char_length(external_id) BETWEEN 1 AND 255),
    plan         TEXT NOT NULL DEFAULT 'personal',
    status       TEXT NOT NULL CHECK (status IN (
                     'active', 'trialing', 'past_due', 'pending', 'paused',
                     'cancelled', 'expired', 'refunded')),
    device_limit INTEGER NOT NULL DEFAULT 3 CHECK (device_limit BETWEEN 1 AND 100),
    period_end   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT entitlements_source_external_id_key UNIQUE (source, external_id)
);

COMMENT ON TABLE public.entitlements IS
    'What an account has paid for, one row per purchase per source. Effective plan = best active row. Written by the API only.';
COMMENT ON COLUMN public.entitlements.external_id IS
    'The purchase id at the source: Stripe subscription id, Play purchase token id, operator subscription id, promo code id, ...';
COMMENT ON COLUMN public.entitlements.device_limit IS
    'Total devices this purchase covers (PLAN_INCLUDED_DEVICES + bought extras).';

CREATE INDEX IF NOT EXISTS idx_entitlements_account
    ON public.entitlements(account_id);

-- updated_at follows every write, whoever forgets to send it.
CREATE OR REPLACE FUNCTION public.entitlements_touch_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS entitlements_touch_updated_at ON public.entitlements;
CREATE TRIGGER entitlements_touch_updated_at
    BEFORE UPDATE ON public.entitlements
    FOR EACH ROW EXECUTE FUNCTION public.entitlements_touch_updated_at();

-- RLS: an account reads its own rows; nobody but the service role writes.
ALTER TABLE public.entitlements ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Users read own entitlements" ON public.entitlements;
CREATE POLICY "Users read own entitlements" ON public.entitlements
    FOR SELECT USING ((SELECT auth.uid()) = account_id);
REVOKE INSERT, UPDATE, DELETE ON public.entitlements FROM anon, authenticated;

-- Backfill: every Stripe subscription the old table knows about. A row the
-- webhook set back to tier 'free' (cancelled / customer deleted) carries no
-- plan any more and is skipped — it grants nothing either way.
INSERT INTO public.entitlements
    (account_id, source, external_id, plan, status, device_limit, period_end)
SELECT
    s.user_id,
    'stripe',
    s.provider_subscription_id,
    s.tier,
    CASE s.status
        WHEN 'active'    THEN 'active'
        WHEN 'past_due'  THEN 'past_due'
        WHEN 'cancelled' THEN 'cancelled'
        ELSE 'expired'
    END,
    3,
    s.current_period_end
FROM public.subscriptions s
WHERE s.provider = 'stripe'
  AND s.provider_subscription_id IS NOT NULL
  AND s.tier <> 'free'
ON CONFLICT (source, external_id) DO NOTHING;

COMMIT;
