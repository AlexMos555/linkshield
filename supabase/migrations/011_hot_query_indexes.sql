-- Migration 011: missing hot-query indexes
--
-- Audit of pg_indexes on prod (May 4, 2026) showed two query patterns
-- that can't use any existing index:
--
--   1. /api/v1/family/mine — filters family_members on user_id alone.
--      Existing PK is composite (family_id, user_id); a query on
--      user_id ONLY does a sequential scan because user_id is the
--      secondary column of the PK. Hot path on every Family Hub
--      page load + every webhook that needs to know "what families
--      does this user belong to".
--
--   2. (future) "alerts I sent" — family_alerts has indexes on
--      (recipient_user_id, created_at DESC) and family_id, but
--      nothing on sender_user_id. Adding it is cheap (small column,
--      mostly unique by definition) and unblocks future UX.
--
-- Strategy: CONCURRENTLY would let us avoid table locks, but
-- migrations are run one-shot via Supabase Management API which
-- doesn't support CONCURRENTLY at the moment. Both indexes target
-- empty / near-empty tables today (cleanway just shipped Family
-- Hub), so a brief lock is fine.
--
-- Idempotent: IF NOT EXISTS on every CREATE.

-- ═══════════════════════════════════════════════════════════
-- family_members: forward path is (family_id, user_id) via PK;
-- reverse path was missing.
-- ═══════════════════════════════════════════════════════════
CREATE INDEX IF NOT EXISTS idx_family_members_user
    ON public.family_members (user_id);

COMMENT ON INDEX public.idx_family_members_user IS
    'Reverse-of-PK lookup for /family/mine and any "what families does this user belong to" query.';

-- ═══════════════════════════════════════════════════════════
-- family_alerts: round out the (sender_user_id) coverage so a
-- future "sent" view doesn't seq-scan.
-- ═══════════════════════════════════════════════════════════
CREATE INDEX IF NOT EXISTS idx_family_alerts_sender
    ON public.family_alerts (sender_user_id, created_at DESC)
    WHERE sender_user_id IS NOT NULL;

COMMENT ON INDEX public.idx_family_alerts_sender IS
    'For "alerts I sent" history view — partial on non-null because legacy rows from migration 001 don''t have sender_user_id set.';
