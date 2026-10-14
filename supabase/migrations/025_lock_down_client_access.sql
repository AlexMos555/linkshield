-- Migration 025: no client writes (or reads) through PostgREST; RLS stays
-- as the second wall.
--
-- Security audit 2026-10 findings fixed here:
--
--   1. public.users had a row-wide UPDATE policy ("Users update own data",
--      001 → 016): any signed-in user could PATCH /rest/v1/users?id=eq.<self>
--      with the anon key + their JWT and rewrite their own email,
--      deletion_requested_at (dodging or faking the deletion grace window),
--      parental_pin_hash (unlocking Kids Mode without the PIN), etc. The same
--      pattern let a family owner raise families.max_members, an org admin
--      rewrite orgs / org_members, and a user rewrite user_settings
--      (threats_blocked_lifetime / threshold_nudge_* drive the paywall) and
--      weekly_aggregates.
--   2. anon and authenticated held full table privileges (arwdDxtm) on almost
--      every public table, so RLS was the only barrier.
--   3. sms_reports was world-readable (USING (true)) including
--      reporter_user_id; its insert check only required "signed in".
--   4. family_alerts inserts only checked "sender is in this family" — not
--      who the sender is, nor that the recipient is in the family; reads did
--      not include the sender's own envelopes.
--   5. orgs <-> org_members policies referenced each other: any query on
--      orgs failed with 42P17 (infinite recursion detected in policy).
--   6. Trigger function handle_new_auth_user() and report_phone() were
--      executable by anon / authenticated through /rest/v1/rpc.
--
-- Who uses PostgREST directly? Only the API, with the service_role key
-- (bypasses grants and RLS). Checked 2026-10-14: mobile/, landing/ and the
-- extensions use @supabase/supabase-js for Auth only and call no
-- .from() / .rpc(); every data path goes through api.cleanway.ai. So
-- clients need no table privileges at all, and none are granted back. The
-- RLS policies below are kept (tightened) so a future accidental GRANT still
-- meets a per-row wall.
--
-- Idempotent: REVOKE / DROP ... IF EXISTS / CREATE OR REPLACE. Safe to re-run.

BEGIN;

-- ─── 1. Table privileges: none for anon / authenticated ─────────────────────

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon, authenticated;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon, authenticated;

-- Tables created later by the role running migrations (postgres) start with
-- no client privileges either; Supabase's defaults would grant them all.
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM anon, authenticated;

-- ─── 2. Policies: owners READ their rows; every write goes through the API ──
--
-- Drop every non-SELECT policy on these tables by catalogue, not by name:
-- 001, 006 and 016 created overlapping policies under different names
-- ("Owners manage own family" and "Family owners manage" both exist on a
-- project that ran every migration).

DO $$
DECLARE
    p record;
BEGIN
    FOR p IN
        SELECT tablename, policyname
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename IN ('users', 'families', 'user_settings', 'weekly_aggregates')
          AND cmd <> 'SELECT'
    LOOP
        EXECUTE format('DROP POLICY %I ON public.%I', p.policyname, p.tablename);
    END LOOP;
END $$;

-- user_settings / weekly_aggregates only had the FOR ALL policy, which was
-- also their read path: give them a read-only one.
DROP POLICY IF EXISTS "Users read own settings" ON public.user_settings;
CREATE POLICY "Users read own settings" ON public.user_settings
    FOR SELECT USING ((SELECT auth.uid()) = user_id);

DROP POLICY IF EXISTS "Users read own aggregates" ON public.weekly_aggregates;
CREATE POLICY "Users read own aggregates" ON public.weekly_aggregates
    FOR SELECT USING ((SELECT auth.uid()) = user_id);

-- families: the owner's FOR ALL policy also served the owner's reads.
DROP POLICY IF EXISTS "Family owners read" ON public.families;
CREATE POLICY "Family owners read" ON public.families
    FOR SELECT USING ((SELECT auth.uid()) = owner_id);

-- ─── 3. orgs / org_members: no client writes, no policy recursion ──────────

CREATE OR REPLACE FUNCTION public.is_org_member(org UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.org_members
        WHERE org_id = org AND user_id = (SELECT auth.uid())
    );
$$;

COMMENT ON FUNCTION public.is_org_member(UUID) IS
    'True when the calling user is a member of the org. SECURITY DEFINER so RLS policies on orgs can ask without re-entering org_members policies (the 42P17 recursion of 006/016).';

REVOKE ALL ON FUNCTION public.is_org_member(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.is_org_member(UUID) TO authenticated, service_role;

DO $$
DECLARE
    p record;
BEGIN
    FOR p IN
        SELECT tablename, policyname
        FROM pg_policies
        WHERE schemaname = 'public' AND tablename IN ('orgs', 'org_members')
    LOOP
        EXECUTE format('DROP POLICY %I ON public.%I', p.policyname, p.tablename);
    END LOOP;
END $$;

CREATE POLICY "Org admins and members read orgs" ON public.orgs
    FOR SELECT USING (
        (SELECT auth.uid()) = admin_user_id OR public.is_org_member(id)
    );

CREATE POLICY "Users read own org membership" ON public.org_members
    FOR SELECT USING ((SELECT auth.uid()) = user_id);

-- ─── 4. sms_reports: no public read, reporter must be the caller ────────────

DROP POLICY IF EXISTS "sms_reports_public_read" ON public.sms_reports;
DROP POLICY IF EXISTS "sms_reports_authenticated_insert" ON public.sms_reports;
DROP POLICY IF EXISTS "sms_reports_own_insert" ON public.sms_reports;
DROP POLICY IF EXISTS "sms_reports_own_read" ON public.sms_reports;

CREATE POLICY "sms_reports_own_insert" ON public.sms_reports
    FOR INSERT WITH CHECK (reporter_user_id = (SELECT auth.uid()));

CREATE POLICY "sms_reports_own_read" ON public.sms_reports
    FOR SELECT USING (reporter_user_id = (SELECT auth.uid()));

-- ─── 5. family_alerts: sender is the caller, recipient is in the family ────

DROP POLICY IF EXISTS "Family members insert alerts" ON public.family_alerts;
DROP POLICY IF EXISTS "Family members read alerts" ON public.family_alerts;
DROP POLICY IF EXISTS "Recipients read own alerts" ON public.family_alerts;
DROP POLICY IF EXISTS "Senders insert alerts to family members" ON public.family_alerts;
DROP POLICY IF EXISTS "Recipients and senders read own alerts" ON public.family_alerts;

-- family_members has RLS and no client policy, so a plain subquery on it
-- from a policy sees no rows. This SECURITY DEFINER helper answers only
-- "do I and `other` both belong to `fam`" — never anything about a family
-- the caller is not in.
CREATE OR REPLACE FUNCTION public.shares_family_with(fam UUID, other UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1 FROM public.family_members me
        JOIN public.family_members them ON them.family_id = me.family_id
        WHERE me.family_id = fam
          AND me.user_id = (SELECT auth.uid())
          AND them.user_id = other
    );
$$;

COMMENT ON FUNCTION public.shares_family_with(UUID, UUID) IS
    'True when the calling user and `other` are both members of family `fam`. Used by the family_alerts insert policy.';

REVOKE ALL ON FUNCTION public.shares_family_with(UUID, UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.shares_family_with(UUID, UUID) TO authenticated, service_role;

CREATE POLICY "Senders insert alerts to family members" ON public.family_alerts
    FOR INSERT WITH CHECK (
        sender_user_id = (SELECT auth.uid())
        AND public.shares_family_with(family_id, recipient_user_id)
    );

CREATE POLICY "Recipients and senders read own alerts" ON public.family_alerts
    FOR SELECT USING (
        recipient_user_id = (SELECT auth.uid())
        OR sender_user_id = (SELECT auth.uid())
    );

-- ─── 6. Functions clients must not call through /rest/v1/rpc ────────────────

REVOKE ALL ON FUNCTION public.handle_new_auth_user() FROM PUBLIC, anon, authenticated;

-- The API records phone reports with the service key (api/routers/phone.py).
REVOKE ALL ON FUNCTION public.report_phone(TEXT, TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.report_phone(TEXT, TEXT, TEXT, TEXT) TO service_role;

COMMIT;
