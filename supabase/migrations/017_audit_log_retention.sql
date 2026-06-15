-- audit_log retention policy.
--
-- Audit finding backend MEDIUM "audit_log table has no retention
-- policy or row cap, and the GDPR purge cron is not wired to clean
-- it". Without a hard ceiling the table grows unbounded and an
-- attacker who can trigger arbitrary audit-relevant events (e.g.
-- repeated soft-delete + restore cycles) could blow up storage.
--
-- Two layers:
--
-- 1. A retention helper function that delete rows older than 2 years.
--    2y matches our terms-of-service retention commitment for
--    financial / fraud-relevant events (chargebacks can be filed for
--    up to 18 months under most card networks; 2y gives a comfortable
--    buffer beyond that). Anything older has no operational value.
--
-- 2. An index on created_at so the retention scan is bounded.
--    Without this the periodic cleanup degenerates to a full table
--    scan as the table grows.
--
-- The actual cron-style invocation can be scheduled via Supabase's
-- pg_cron extension or run from api/services/account_purge.py as a
-- secondary step. We DON'T wire the cron directly here — that's
-- environment-specific.

BEGIN;

CREATE INDEX IF NOT EXISTS idx_audit_log_created_at
    ON public.audit_log (created_at);

CREATE OR REPLACE FUNCTION public.purge_old_audit_log(
    retention_days integer DEFAULT 730
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    deleted_count bigint;
BEGIN
    -- 730d default = 2 years; caller can override for environment-
    -- specific policies (dev maybe wants 30d, compliance review may
    -- want a one-time wider window).
    DELETE FROM public.audit_log
        WHERE created_at < (now() - (retention_days || ' days')::interval);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$;

COMMENT ON FUNCTION public.purge_old_audit_log(integer) IS
    'GDPR-friendly audit log retention. Deletes rows older than the
     given retention window (default 730 days = 2 years). Returns the
     count of deleted rows. Safe to call from a periodic job or
     manually during compliance review.';

-- Grant execute to service_role only — this is a privileged operation.
-- The anon / authenticated roles cannot trigger it.
REVOKE ALL ON FUNCTION public.purge_old_audit_log(integer) FROM public;
GRANT EXECUTE ON FUNCTION public.purge_old_audit_log(integer) TO service_role;

COMMIT;
