-- Migration 027: Supabase Auth's own sign-in log is purged too.
--
-- GoTrue (Supabase Auth) writes a row to auth.audit_log_entries for every
-- sign-in, token refresh, sign-out and Admin API action:
--
--   payload    json: actor_id (the account id; the nil UUID for a
--              service-role caller), actor_username (email or phone),
--              action, log_type, and for an admin action `traits` with the
--              subject's user_id / user_email / user_phone
--              (internal/models/audit_log_entry.go, internal/api/admin.go);
--   ip_address the caller's IP as is (GoTrue migration 20220614074223);
--   created_at.
--
-- Nothing deleted these rows. The 30-day account erase
-- (api/services/account_purge.py) deletes the identity through the Admin
-- API, which keeps the log — and adds a `user_deleted` row with the email
-- in traits — and the retention job (api/services/retention.py) only
-- reaches public tables through PostgREST; the auth schema is not exposed.
-- So both call these functions over /rest/v1/rpc with the service role:
--
--   purge_auth_audit_log(p_retention_days, p_dry_run)
--       rows older than the window. The retention job passes 730 days: the
--       policy names no period for Supabase's own log (section 9 only says
--       it may record the sign-in IP), so it gets our security log's 2
--       years (section 16). p_dry_run (the default) only counts; the job's
--       dry run calls it with GET, which PostgREST runs READ ONLY.
--   delete_auth_audit_log_for_users(p_user_ids)
--       every row about these accounts: as the actor, or as the subject of
--       an admin action. One call per purge run — the payload has no index
--       (the table is GoTrue's, not ours to index), so each call is a scan.
--
-- Both scan the whole log, which grows with every token refresh. On
-- Supabase, service_role has no statement_timeout of its own and a call
-- through PostgREST inherits authenticator's 8 seconds; past that the
-- database cancels it (57014, PostgREST answers 500). So each function sets
-- its own 50 seconds, which PostgREST (12+) applies to the call's
-- transaction — under the 60 seconds Supabase allows an API call, so the
-- database ends a call that runs too long, and the API (which waits longer)
-- sees the 500. Called from the SQL Editor, the session's own limit holds.
--
-- SECURITY DEFINER: they run as the role applying this migration (on
-- Supabase, `postgres`, which may read and delete auth tables). The
-- preflight below fails the migration if that role can't, rather than
-- leaving functions that fail on every call. Only service_role may execute
-- them (Supabase grants EXECUTE on new functions to anon and authenticated:
-- revoked). Re-running the migration is safe.

BEGIN;

DO $$
BEGIN
    IF to_regclass('auth.audit_log_entries') IS NULL THEN
        RAISE EXCEPTION 'auth.audit_log_entries does not exist: is this a Supabase project?';
    END IF;
    IF NOT has_table_privilege('auth.audit_log_entries', 'SELECT')
       OR NOT has_table_privilege('auth.audit_log_entries', 'DELETE') THEN
        RAISE EXCEPTION 'role % may not SELECT and DELETE auth.audit_log_entries; apply this migration as postgres',
            current_user;
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION public.purge_auth_audit_log(
    p_retention_days INTEGER,
    p_dry_run        BOOLEAN DEFAULT true
)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
SET statement_timeout = '50s'
AS $$
DECLARE
    v_cutoff TIMESTAMPTZ;
    v_count  BIGINT;
BEGIN
    IF p_retention_days IS NULL OR p_retention_days < 1 THEN
        RAISE EXCEPTION 'p_retention_days must be at least 1, got %', p_retention_days
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    v_cutoff := now() - make_interval(days => p_retention_days);

    IF p_dry_run IS DISTINCT FROM false THEN
        SELECT count(*) INTO v_count
        FROM auth.audit_log_entries
        WHERE created_at < v_cutoff;
        RETURN v_count;
    END IF;

    DELETE FROM auth.audit_log_entries WHERE created_at < v_cutoff;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

COMMENT ON FUNCTION public.purge_auth_audit_log(INTEGER, BOOLEAN) IS
    'Supabase Auth sign-in log rows older than p_retention_days: counted (p_dry_run, the default) or deleted. Returns the count. Service role only (retention job).';

CREATE OR REPLACE FUNCTION public.delete_auth_audit_log_for_users(
    p_user_ids UUID[]
)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
SET statement_timeout = '50s'
AS $$
DECLARE
    v_ids   TEXT[];
    v_count BIGINT;
BEGIN
    -- The nil UUID is the actor of every service-role action: nobody's
    -- account, and matching it would erase the log of all admin actions.
    IF p_user_ids IS NULL
       OR '00000000-0000-0000-0000-000000000000'::uuid = ANY (p_user_ids) THEN
        RAISE EXCEPTION 'p_user_ids must be account ids'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- GoTrue stores the ids as lowercase text, as uuid::text prints them.
    v_ids := ARRAY(SELECT DISTINCT u::text FROM unnest(p_user_ids) AS u WHERE u IS NOT NULL);
    IF cardinality(v_ids) = 0 THEN
        RETURN 0;
    END IF;

    DELETE FROM auth.audit_log_entries
    WHERE payload ->> 'actor_id' = ANY (v_ids)
       OR payload -> 'traits' ->> 'user_id' = ANY (v_ids);
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

COMMENT ON FUNCTION public.delete_auth_audit_log_for_users(UUID[]) IS
    'Delete the Supabase Auth sign-in log rows about these accounts (payload actor_id or traits.user_id). Returns the count. Service role only (account erase).';

REVOKE ALL ON FUNCTION public.purge_auth_audit_log(INTEGER, BOOLEAN) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.delete_auth_audit_log_for_users(UUID[]) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.purge_auth_audit_log(INTEGER, BOOLEAN) TO service_role;
GRANT EXECUTE ON FUNCTION public.delete_auth_audit_log_for_users(UUID[]) TO service_role;

-- PostgREST learns about new functions from its schema cache; Supabase
-- reloads it on DDL, this makes sure (delivered at COMMIT).
NOTIFY pgrst, 'reload schema';

COMMIT;
