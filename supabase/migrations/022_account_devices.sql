-- Migration 022: devices are what a subscription counts.
--
-- Founder decision 2026-10-07 (docs/ACCOUNTS_BILLING_PLAN.md §5): a paid
-- plan covers 3 devices, extra devices are bought on top, one account per
-- person. A "device" is one install of the app / extension / one browser
-- that is signed in to the account.
--
-- What changes on public.devices (created in 001):
--   * name        — "Pixel 8", "Chrome on Windows"; shown in the device list.
--   * revoked_at  — set when the owner unlinks the device. The row stays (the
--                   same install id can never quietly re-attach); a revoked
--                   install's API calls are refused with `device_revoked` and
--                   the app signs out locally and makes a new install id.
--   * session_id  — the Supabase Auth session the device last used. Unlinking
--                   deletes that session, so its refresh token stops working.
--   * platform    — now also accepts 'extension' (the API speaks android /
--                   ios / extension / web; the 001 values stay valid for old
--                   rows).
--   last_seen (001) is the heartbeat time; the API exposes it as last_seen_at.
--   device_hash (001) holds the client's random per-install id.
--
-- Writes now go ONLY through the API (service role) and the two functions
-- below: the device limit is enforced there, so the old "Users manage own
-- devices" FOR ALL policy — which let any signed-in client insert devices
-- straight through PostgREST and skip the limit — becomes read-only.
-- No client writes devices directly (checked 2026-10-07: mobile, landing and
-- the extensions only go through the API).
--
-- Idempotent: IF NOT EXISTS / DROP ... IF EXISTS / CREATE OR REPLACE.

BEGIN;

ALTER TABLE public.devices
    ADD COLUMN IF NOT EXISTS name TEXT,
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS session_id UUID;

ALTER TABLE public.devices DROP CONSTRAINT IF EXISTS devices_name_length;
ALTER TABLE public.devices
    ADD CONSTRAINT devices_name_length CHECK (name IS NULL OR char_length(name) <= 80);

-- 001 declared the CHECK inline, so Postgres named it devices_platform_check.
ALTER TABLE public.devices DROP CONSTRAINT IF EXISTS devices_platform_check;
ALTER TABLE public.devices
    ADD CONSTRAINT devices_platform_check CHECK (
        platform IN ('android', 'ios', 'extension', 'web',
                     'chrome_ext', 'firefox_ext', 'safari_ext')
    );

COMMENT ON COLUMN public.devices.name IS
    'Human name of the device ("Pixel 8", "Chrome on Windows"). Set at first registration, changed only by rename.';
COMMENT ON COLUMN public.devices.revoked_at IS
    'Set when the owner unlinked the device. Revoked rows do not count toward the device limit and are never re-activated.';
COMMENT ON COLUMN public.devices.session_id IS
    'Supabase Auth session the device last used (JWT session_id claim); deleted on unlink.';

-- Counting active devices per account is the hot path of registration.
CREATE INDEX IF NOT EXISTS idx_devices_user_active
    ON public.devices(user_id)
    WHERE revoked_at IS NULL;

-- RLS: owners may READ their devices; every write goes through the API.
DROP POLICY IF EXISTS "Users manage own devices" ON public.devices;
DROP POLICY IF EXISTS "Users read own devices" ON public.devices;
CREATE POLICY "Users read own devices" ON public.devices
    FOR SELECT USING ((SELECT auth.uid()) = user_id);
REVOKE INSERT, UPDATE, DELETE ON public.devices FROM anon, authenticated;


-- ─── register_device: idempotent register / heartbeat with the limit ──────
--
-- Returns jsonb {status, device?, devices_used?}:
--   'updated'       — this install was already linked; last_seen bumped.
--                     An already-linked device is never refused, even when
--                     the account is now over its limit (a lapsed plan must
--                     not lock people out of devices they already use).
--   'created'       — a new device took a free seat.
--   'limit_reached' — no free seat; nothing written.
--   'revoked'       — this install id was unlinked; nothing written.
-- The advisory lock serialises registrations of ONE account, so two new
-- devices racing for the last seat cannot both get it.
CREATE OR REPLACE FUNCTION public.register_device(
    p_user_id      UUID,
    p_device_hash  TEXT,
    p_platform     TEXT,
    p_name         TEXT,
    p_app_version  TEXT,
    p_session_id   UUID,
    p_device_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_row    public.devices%ROWTYPE;
    v_active INTEGER;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('devices:' || p_user_id::text, 0));

    SELECT * INTO v_row
    FROM public.devices
    WHERE user_id = p_user_id AND device_hash = p_device_hash;

    IF FOUND THEN
        IF v_row.revoked_at IS NOT NULL THEN
            RETURN jsonb_build_object('status', 'revoked');
        END IF;
        UPDATE public.devices
        SET platform    = p_platform,
            name        = COALESCE(name, p_name),
            app_version = COALESCE(p_app_version, app_version),
            session_id  = COALESCE(p_session_id, session_id),
            last_seen   = now()
        WHERE id = v_row.id
        RETURNING * INTO v_row;
        RETURN jsonb_build_object('status', 'updated', 'device', to_jsonb(v_row));
    END IF;

    SELECT count(*) INTO v_active
    FROM public.devices
    WHERE user_id = p_user_id AND revoked_at IS NULL;

    IF v_active >= p_device_limit THEN
        RETURN jsonb_build_object('status', 'limit_reached', 'devices_used', v_active);
    END IF;

    INSERT INTO public.devices
        (user_id, device_hash, platform, name, app_version, session_id, last_seen)
    VALUES
        (p_user_id, p_device_hash, p_platform, p_name, p_app_version, p_session_id, now())
    RETURNING * INTO v_row;
    RETURN jsonb_build_object('status', 'created', 'device', to_jsonb(v_row));
END;
$$;

COMMENT ON FUNCTION public.register_device(UUID, TEXT, TEXT, TEXT, TEXT, UUID, INTEGER) IS
    'Register or heartbeat one install of an account, enforcing the device limit atomically. Service role only.';


-- ─── revoke_device: unlink one device of one account ──────────────────────
--
-- Returns jsonb {status, device?}: 'revoked', 'already_revoked' or
-- 'not_found' (also when the device belongs to someone else). Deleting the
-- device's Auth session is best-effort: if this project's role may not touch
-- auth.sessions, the unlink still stands and the API refuses the install by
-- its id; the session's refresh token then simply lives out its own life.
CREATE OR REPLACE FUNCTION public.revoke_device(
    p_user_id   UUID,
    p_device_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_row public.devices%ROWTYPE;
BEGIN
    SELECT * INTO v_row
    FROM public.devices
    WHERE id = p_device_id AND user_id = p_user_id;

    IF NOT FOUND THEN
        RETURN jsonb_build_object('status', 'not_found');
    END IF;
    IF v_row.revoked_at IS NOT NULL THEN
        RETURN jsonb_build_object('status', 'already_revoked', 'device', to_jsonb(v_row));
    END IF;

    UPDATE public.devices
    SET revoked_at = now()
    WHERE id = v_row.id
    RETURNING * INTO v_row;

    IF v_row.session_id IS NOT NULL THEN
        BEGIN
            DELETE FROM auth.sessions
            WHERE id = v_row.session_id AND user_id = p_user_id;
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'revoke_device: could not delete auth session %: %',
                v_row.session_id, SQLERRM;
        END;
    END IF;

    RETURN jsonb_build_object('status', 'revoked', 'device', to_jsonb(v_row));
END;
$$;

COMMENT ON FUNCTION public.revoke_device(UUID, UUID) IS
    'Unlink one device of an account and end its Auth session. Service role only.';

-- SECURITY DEFINER functions are reachable through PostgREST /rpc by every
-- role that may EXECUTE them, and Supabase grants EXECUTE on new functions to
-- anon + authenticated by default. Only the API (service role) may call these.
REVOKE ALL ON FUNCTION public.register_device(UUID, TEXT, TEXT, TEXT, TEXT, UUID, INTEGER)
    FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.revoke_device(UUID, UUID)
    FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.register_device(UUID, TEXT, TEXT, TEXT, TEXT, UUID, INTEGER)
    TO service_role;
GRANT EXECUTE ON FUNCTION public.revoke_device(UUID, UUID)
    TO service_role;

COMMIT;
