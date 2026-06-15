-- Wrap auth.uid() in (SELECT auth.uid()) across every RLS policy
-- defined in migrations 001 / 002 / 005 / 006 / 008.
--
-- Why this matters (audit backend-db MEDIUM rls-perf):
-- Supabase's RLS engine re-evaluates a bare auth.uid() FOR EVERY ROW
-- visited by a query. With a wide SELECT (think /history pagination,
-- weekly aggregates trend, family members list), that's one JWT
-- parse + claim lookup per row. (SELECT auth.uid()) is recognised by
-- Postgres' planner as an initplan and cached for the entire query —
-- the function fires exactly once.
--
-- The semantic is identical: same value, same authorisation outcome.
-- Performance difference is documented and benchmarked in Supabase's
-- own RLS performance guide. Migration 015 used the cached form when
-- it was created; this catches up the older policies.
--
-- We DROP + recreate each policy because Postgres has no way to alter
-- the USING / WITH CHECK expression in place.

BEGIN;

-- ───────────────────────────────────────────────────────────────
-- 001_initial_schema
-- ───────────────────────────────────────────────────────────────

DROP POLICY IF EXISTS "Users read own data" ON public.users;
CREATE POLICY "Users read own data" ON public.users
    FOR SELECT USING ((SELECT auth.uid()) = id);

DROP POLICY IF EXISTS "Users update own data" ON public.users;
CREATE POLICY "Users update own data" ON public.users
    FOR UPDATE USING ((SELECT auth.uid()) = id);

DROP POLICY IF EXISTS "Users read own subscription" ON public.subscriptions;
CREATE POLICY "Users read own subscription" ON public.subscriptions
    FOR SELECT USING ((SELECT auth.uid()) = user_id);

DROP POLICY IF EXISTS "Users manage own devices" ON public.devices;
CREATE POLICY "Users manage own devices" ON public.devices
    FOR ALL USING ((SELECT auth.uid()) = user_id);

DROP POLICY IF EXISTS "Users manage own aggregates" ON public.weekly_aggregates;
CREATE POLICY "Users manage own aggregates" ON public.weekly_aggregates
    FOR ALL USING ((SELECT auth.uid()) = user_id);

DROP POLICY IF EXISTS "Users manage own settings" ON public.user_settings;
CREATE POLICY "Users manage own settings" ON public.user_settings
    FOR ALL USING ((SELECT auth.uid()) = user_id);

DROP POLICY IF EXISTS "Family members insert alerts" ON public.family_alerts;
CREATE POLICY "Family members insert alerts" ON public.family_alerts
    FOR INSERT WITH CHECK (
        family_id IN (
            SELECT family_id FROM public.family_members
            WHERE user_id = (SELECT auth.uid())
        )
    );

DROP POLICY IF EXISTS "Users read own rate limits" ON public.rate_limits;
CREATE POLICY "Users read own rate limits" ON public.rate_limits
    FOR SELECT USING ((SELECT auth.uid()) = user_id);

-- ───────────────────────────────────────────────────────────────
-- 002_feedback_reports
-- ───────────────────────────────────────────────────────────────

DROP POLICY IF EXISTS "Users write own feedback" ON public.feedback_reports;
CREATE POLICY "Users write own feedback" ON public.feedback_reports
    FOR INSERT WITH CHECK ((SELECT auth.uid()) = user_id);

DROP POLICY IF EXISTS "Users read own feedback" ON public.feedback_reports;
CREATE POLICY "Users read own feedback" ON public.feedback_reports
    FOR SELECT USING ((SELECT auth.uid()) = user_id);

-- ───────────────────────────────────────────────────────────────
-- 006_enable_rls_families_orgs (the families / orgs / org_members /
-- scam_reports / threat_status / etc. policies)
-- ───────────────────────────────────────────────────────────────

DROP POLICY IF EXISTS "Family owners manage" ON public.families;
CREATE POLICY "Family owners manage" ON public.families
    FOR ALL
    USING ((SELECT auth.uid()) = owner_id)
    WITH CHECK ((SELECT auth.uid()) = owner_id);

DROP POLICY IF EXISTS "Family members read families" ON public.families;
CREATE POLICY "Family members read families" ON public.families
    FOR SELECT
    USING (
        id IN (
            SELECT family_id FROM public.family_members
            WHERE user_id = (SELECT auth.uid())
        )
    );

DROP POLICY IF EXISTS "Org admins manage" ON public.orgs;
CREATE POLICY "Org admins manage" ON public.orgs
    FOR ALL
    USING ((SELECT auth.uid()) = admin_user_id)
    WITH CHECK ((SELECT auth.uid()) = admin_user_id);

DROP POLICY IF EXISTS "Org members read orgs" ON public.orgs;
CREATE POLICY "Org members read orgs" ON public.orgs
    FOR SELECT
    USING (
        id IN (
            SELECT org_id FROM public.org_members
            WHERE user_id = (SELECT auth.uid())
        )
    );

DROP POLICY IF EXISTS "Org admins manage members" ON public.org_members;
CREATE POLICY "Org admins manage members" ON public.org_members
    FOR ALL
    USING (
        org_id IN (
            SELECT id FROM public.orgs WHERE admin_user_id = (SELECT auth.uid())
        )
    )
    WITH CHECK (
        org_id IN (
            SELECT id FROM public.orgs WHERE admin_user_id = (SELECT auth.uid())
        )
    );

DROP POLICY IF EXISTS "Users read own org membership" ON public.org_members;
CREATE POLICY "Users read own org membership" ON public.org_members
    FOR SELECT USING ((SELECT auth.uid()) = user_id);

-- ───────────────────────────────────────────────────────────────
-- 008_family_hub_e2e (family_member_keys + family_invites)
-- ───────────────────────────────────────────────────────────────

DROP POLICY IF EXISTS "Users write own key" ON public.family_member_keys;
CREATE POLICY "Users write own key" ON public.family_member_keys
    FOR INSERT WITH CHECK (user_id = (SELECT auth.uid()));

DROP POLICY IF EXISTS "Users update own key" ON public.family_member_keys;
CREATE POLICY "Users update own key" ON public.family_member_keys
    FOR UPDATE USING (user_id = (SELECT auth.uid()));

DROP POLICY IF EXISTS "Inviters read own invites" ON public.family_invites;
CREATE POLICY "Inviters read own invites" ON public.family_invites
    FOR SELECT USING (inviter_id = (SELECT auth.uid()));

-- ───────────────────────────────────────────────────────────────
-- 005_scam_protection — scam_reports + a couple of others.
--
-- The migration was authored against tables that may or may not exist
-- yet depending on whether scam-protection ran in this environment.
-- IF EXISTS guards keep this idempotent.
-- ───────────────────────────────────────────────────────────────

DO $$
BEGIN
    IF EXISTS (
        SELECT FROM pg_policies WHERE policyname = 'Authenticated users insert scam reports'
    ) THEN
        EXECUTE 'DROP POLICY "Authenticated users insert scam reports" ON public.scam_reports';
        EXECUTE 'CREATE POLICY "Authenticated users insert scam reports" ON public.scam_reports
            FOR INSERT WITH CHECK ((SELECT auth.uid()) IS NOT NULL)';
    END IF;
    IF EXISTS (
        SELECT FROM pg_policies WHERE policyname = 'Users read own scam reports'
    ) THEN
        EXECUTE 'DROP POLICY "Users read own scam reports" ON public.scam_reports';
        EXECUTE 'CREATE POLICY "Users read own scam reports" ON public.scam_reports
            FOR SELECT USING ((SELECT auth.uid()) = user_id)';
    END IF;
    IF EXISTS (
        SELECT FROM pg_policies WHERE policyname = 'Users write own scam reports'
    ) THEN
        EXECUTE 'DROP POLICY "Users write own scam reports" ON public.scam_reports';
        EXECUTE 'CREATE POLICY "Users write own scam reports" ON public.scam_reports
            FOR INSERT WITH CHECK ((SELECT auth.uid()) = user_id)';
    END IF;
END $$;

COMMIT;
