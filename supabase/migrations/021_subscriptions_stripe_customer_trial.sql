-- Migration 021: subscriptions.stripe_customer_id + subscriptions.trial_used_at.
--
-- Why:
--   * stripe_customer_id — checkout passed `customer_email`, so Stripe
--     minted a NEW customer on every purchase; the Customer Portal then
--     looked the customer up by email with limit=1 (emails aren't unique
--     in Stripe → could open a stale or someone else's customer); and
--     refund / dispute webhooks couldn't find the user at all, because
--     invoice charges carry no metadata.user_id. Storing the customer id
--     on the user's one subscriptions row fixes all three: checkout and
--     the portal reuse it, webhooks resolve the user by it.
--   * trial_used_at — every checkout granted a fresh 14-day trial. The
--     trial is now offered once per user; this records when it was used
--     (written by the checkout.session.completed webhook).
--
-- Both columns are written only by the API with the service key (no
-- RLS write policy exists on subscriptions — users can only read their
-- own row, see migrations 001 / 016).
--
-- Idempotent: IF NOT EXISTS everywhere; the backfill only touches rows
-- that are still NULL.

ALTER TABLE public.subscriptions
    ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT,
    ADD COLUMN IF NOT EXISTS trial_used_at TIMESTAMPTZ;

COMMENT ON COLUMN public.subscriptions.stripe_customer_id IS
    'Stripe customer (cus_...) for this user. Reused by checkout + the Customer Portal; webhooks resolve the user by it.';
COMMENT ON COLUMN public.subscriptions.trial_used_at IS
    'When the user started their one free trial (NULL = trial still available).';

-- Webhook lookups: refund / dispute / customer.deleted resolve the user
-- by customer id; subscription events without our metadata resolve by
-- subscription id. Non-unique on purpose — a data glitch must not make
-- every webhook upsert for that customer fail.
CREATE INDEX IF NOT EXISTS idx_subs_stripe_customer
    ON public.subscriptions(stripe_customer_id)
    WHERE stripe_customer_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_subs_provider_subscription
    ON public.subscriptions(provider_subscription_id)
    WHERE provider_subscription_id IS NOT NULL;

-- Backfill: anyone who already had a provider subscription has had
-- their trial (every checkout so far granted one). The API applies the
-- same rule at runtime; this just makes the column truthful.
UPDATE public.subscriptions
SET trial_used_at = COALESCE(created_at, now())
WHERE provider_subscription_id IS NOT NULL
  AND trial_used_at IS NULL;
