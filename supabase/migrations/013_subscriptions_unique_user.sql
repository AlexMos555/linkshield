-- Migration 013: subscriptions.user_id must be UNIQUE.
--
-- Until now the table allowed multiple rows per user. The Stripe webhook
-- handler used POST with `Prefer: resolution=merge-duplicates`, but
-- without a UNIQUE constraint that header is a no-op — every event
-- INSERTed a fresh row. Result: on cancellation we'd insert a new
-- status='cancelled' row alongside the original status='active' row.
-- The tier resolver (status IN ('active','past_due') ORDER BY created_at
-- DESC LIMIT 1) still found the old active row and the user kept paid
-- access forever.
--
-- Fix in three parts:
--   1. Dedup any existing duplicates (defensive — production should be
--      mostly empty pre-launch, but staging has test artifacts).
--   2. Add UNIQUE(user_id) so future merge-duplicates upserts actually
--      merge instead of inserting.
--   3. Webhook handler updated separately to pass `on_conflict=user_id`
--      so the constraint is exercised.
--
-- Idempotent: every step uses IF NOT EXISTS / WHERE NOT EXISTS / etc.

-- ── Step 1: dedup ──────────────────────────────────────────────
-- For each user_id keep only the most recent row (by created_at);
-- delete the rest.
DELETE FROM public.subscriptions
WHERE id IN (
    SELECT id FROM (
        SELECT id,
               ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY created_at DESC, id DESC) AS rn
        FROM public.subscriptions
    ) ranked
    WHERE rn > 1
);

-- ── Step 2: enforce uniqueness ────────────────────────────────
-- One subscription row per user. The row is mutated in place by every
-- subsequent Stripe event (active → past_due → cancelled → resubscribed
-- back to active → …). History lives in the Stripe dashboard; we keep
-- only the current state.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'subscriptions_user_id_unique'
    ) THEN
        ALTER TABLE public.subscriptions
            ADD CONSTRAINT subscriptions_user_id_unique UNIQUE (user_id);
    END IF;
END$$;

COMMENT ON CONSTRAINT subscriptions_user_id_unique ON public.subscriptions IS
    'One subscription row per user. Stripe events upsert via ON CONFLICT (user_id).';
