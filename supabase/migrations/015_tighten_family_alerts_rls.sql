-- Tighten family_alerts SELECT RLS to per-recipient (audit backend-security HIGH).
--
-- Before: any member of a family could SELECT every row in that family's
-- alert stream — including sender_device_hash, sender_pubkey, encrypted_payload,
-- nonce, alert_type, created_at, expires_at. The payload itself is E2E
-- encrypted (server-blind by design), but the metadata leaked broad
-- behavioral signal: a teenager could see how often their parent had
-- alerts fire, an estranged family member could time-correlate, etc.
--
-- After: each row in family_alerts is only readable by the recipient
-- it was addressed to (via the recipient_user_id column added in 008).
-- The Family Hub fan-out already creates one row per recipient, so
-- this is the correct per-envelope contract.
--
-- Service role (used by the backend) bypasses RLS, so api/routers/family.py
-- continues to work unchanged.
--
-- Also: rewrites the policy to (SELECT auth.uid()) — Supabase's
-- initplan-cached form — instead of bare auth.uid(). At family scale
-- the per-row evaluation overhead doesn't matter, but it's the
-- pattern the rest of new policies should follow. (Audit medium
-- backend-db rls-perf.)

BEGIN;

DROP POLICY IF EXISTS "Family members read alerts" ON public.family_alerts;

CREATE POLICY "Recipients read own alerts" ON public.family_alerts
    FOR SELECT
    USING (recipient_user_id = (SELECT auth.uid()));

-- INSERT policy left in place — backend writes via service_role
-- (bypasses RLS) and the existing "Family members insert alerts"
-- check covers any direct-client write path with the same
-- "must be in this family" invariant we already enforce.

COMMENT ON POLICY "Recipients read own alerts" ON public.family_alerts IS
    'E2E privacy: each alert envelope is per-recipient; only the addressed user can read it. Replaces 001s blanket family-wide policy.';

COMMIT;
