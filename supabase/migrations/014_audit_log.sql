-- Migration 014: audit log table for compliance / SOC2 / GDPR readiness.
--
-- Enterprise customers (and any GDPR Subject Access Request answer)
-- expect a record of WHO did WHAT and WHEN to privileged objects.
-- Use cases:
--   * Account deletion / restoration audit trail
--   * Payment / subscription tier changes
--   * Family invite creation, acceptance, member removal
--   * Org member add / remove / role change
--   * Admin / support-tool actions (when we add them)
--
-- Design notes:
--   * One narrow table — no joins required to render an audit feed
--   * actor_user_id NULLABLE because Stripe webhooks (no user session)
--     and the periodic purge job (no actor) need to write rows too
--   * target_kind + target_id replace a polymorphic FK so we can
--     reference users, subscriptions, family_alerts, etc. without a
--     table-per-target proliferation
--   * meta JSONB carries event-specific extras (e.g. old/new tier)
--   * RLS gates read access; service_role bypass writes
--
-- Append-only by design — no DELETE / UPDATE policies. The hard-purge
-- job (api/services/account_purge.py) will be extended to also wipe
-- audit rows older than the longest retention horizon. For now the
-- table grows unbounded; rotation is a follow-up.

CREATE TABLE IF NOT EXISTS public.audit_log (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Who initiated the action. NULL = system event (Stripe webhook,
    -- cron purge, etc.). When non-NULL points at auth.users (the
    -- Supabase Auth table), NOT public.users — we want to keep audit
    -- rows even after hard-delete of public.users (cascading on
    -- public.users would defeat the purpose of an audit log).
    actor_user_id UUID NULL,
    -- Stable string like "user", "subscription", "family", "org",
    -- "family_invite", "stripe_customer". Free-form rather than enum
    -- so new event types don't need a migration.
    target_kind  TEXT NOT NULL,
    target_id    TEXT NOT NULL,
    -- The verb. Examples: "account.delete_requested", "account.restored",
    -- "account.hard_deleted", "subscription.upgraded", "family.invite_created",
    -- "family.member_removed", "org.role_changed".
    action       TEXT NOT NULL,
    -- Event-specific payload. For subscription changes:
    --   {"from_tier": "free", "to_tier": "personal", "stripe_event_id": "..."}
    -- For family.invite_created:
    --   {"family_id": "...", "expires_at": "..."}
    meta         JSONB NOT NULL DEFAULT '{}'::JSONB,
    -- The IP of the caller, when available. NULL for system events.
    -- Hashed via SHA-256 hex (not stored raw) so a leaked audit table
    -- can't be used to deanonymise users; raw IPs were never logged
    -- to begin with per our privacy policy.
    actor_ip_hash TEXT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes for the common query patterns:
--   * Render an audit feed for a specific user: per-actor scan
--   * Investigate "what happened to family X": per-target scan
--   * Time-range filters across either of the above
CREATE INDEX IF NOT EXISTS idx_audit_actor_time
    ON public.audit_log (actor_user_id, created_at DESC)
    WHERE actor_user_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_target_time
    ON public.audit_log (target_kind, target_id, created_at DESC);

-- RLS: only the service_role (our backend with the secret service key)
-- can read or write. End users never see this table directly — they
-- request their own audit slice via the GDPR export endpoint, which
-- filters server-side.
ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'audit_log'
          AND policyname = 'service role only'
    ) THEN
        CREATE POLICY "service role only" ON public.audit_log
            FOR ALL
            USING (false)
            WITH CHECK (false);
    END IF;
END$$;

COMMENT ON TABLE public.audit_log IS
    'Append-only audit trail for compliance / SOC2 / GDPR SARs. '
    'Service-role only. Read access goes through /api/v1/user/export '
    '(GDPR Art. 15) which filters server-side by the authenticated user.';
