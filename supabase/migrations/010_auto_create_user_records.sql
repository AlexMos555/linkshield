-- Migration 010: auto-create public.users + subscriptions + user_settings
--                on Supabase Auth signup
--
-- Background:
--   Supabase Auth creates rows in auth.users when a magic-link / OAuth
--   / password signup completes. Our application code keys everything
--   off public.users (FKs from subscriptions, devices, family_members,
--   user_settings, etc.). Without a row in public.users matching the
--   auth.users.id, the next authenticated request to the FastAPI
--   backend hits FK violations or empty rows.
--
--   This trigger closes that gap: every new auth.users insert
--   automatically materialises:
--     - public.users         (id + email + provider)
--     - public.subscriptions (free tier, active, stripe provider as default)
--     - public.user_settings (empty JSONB so welcome_sent_at + email_optout
--                             columns work without a race-condition INSERT)
--
-- Idempotency:
--   Every INSERT uses ON CONFLICT DO NOTHING. Safe to re-run the
--   migration; safe if a manual row already exists.
--
-- Security:
--   SECURITY DEFINER so the trigger runs as the table owner (bypasses
--   RLS). search_path pinned to public, pg_temp per migration 007's
--   convention (Supabase Security Advisor flags otherwise).

-- ═══════════════════════════════════════════════════════════
-- Trigger function
-- ═══════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.handle_new_auth_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    derived_provider TEXT;
    derived_display TEXT;
BEGIN
    -- Pull provider from auth metadata when present (Google → 'google',
    -- Apple → 'apple', email magic-link → 'email').
    derived_provider := COALESCE(
        NEW.raw_app_meta_data->>'provider',
        NEW.raw_user_meta_data->>'provider',
        'email'
    );

    -- Display name: full_name from OAuth providers, else email local-part.
    derived_display := COALESCE(
        NEW.raw_user_meta_data->>'full_name',
        NEW.raw_user_meta_data->>'name',
        split_part(NEW.email, '@', 1)
    );

    -- 1. public.users — same id as auth.users.id; email kept in sync.
    INSERT INTO public.users (id, email, auth_provider, display_name)
    VALUES (NEW.id, NEW.email, derived_provider, derived_display)
    ON CONFLICT (id) DO NOTHING;

    -- 2. public.subscriptions — default to free tier so /pricing,
    --    /threats/status, etc. don't return 404 on the very first call.
    INSERT INTO public.subscriptions (user_id, tier, status)
    VALUES (NEW.id, 'free', 'active')
    ON CONFLICT (user_id) DO NOTHING;

    -- 3. public.user_settings — empty JSONB so subsequent UPSERTs that
    --    merge into settings.email_optout / settings.welcome_sent_at
    --    don't have to first guess whether a row exists.
    INSERT INTO public.user_settings (user_id, settings)
    VALUES (NEW.id, '{}'::jsonb)
    ON CONFLICT (user_id) DO NOTHING;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION public.handle_new_auth_user() IS
    'Triggered after auth.users INSERT — materialises matching app-level rows in public.users, subscriptions (free), user_settings.';

-- ═══════════════════════════════════════════════════════════
-- Wire the trigger to auth.users INSERT
-- ═══════════════════════════════════════════════════════════
-- Drop first to make the migration re-runnable without errors.
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;

CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_new_auth_user();

-- ═══════════════════════════════════════════════════════════
-- Backfill — any existing auth.users without a public.users row
-- ═══════════════════════════════════════════════════════════
-- Wrap in a DO block so we can log how many rows we created.
DO $$
DECLARE
    inserted_count INTEGER := 0;
BEGIN
    WITH missing AS (
        SELECT au.id, au.email,
               COALESCE(
                   au.raw_app_meta_data->>'provider',
                   au.raw_user_meta_data->>'provider',
                   'email'
               ) AS provider,
               COALESCE(
                   au.raw_user_meta_data->>'full_name',
                   au.raw_user_meta_data->>'name',
                   split_part(au.email, '@', 1)
               ) AS display
        FROM auth.users au
        LEFT JOIN public.users pu ON pu.id = au.id
        WHERE pu.id IS NULL
          AND au.email IS NOT NULL
    ),
    inserted AS (
        INSERT INTO public.users (id, email, auth_provider, display_name)
        SELECT id, email, provider, display FROM missing
        ON CONFLICT (id) DO NOTHING
        RETURNING id
    )
    SELECT count(*) INTO inserted_count FROM inserted;

    -- Same backfill for subscriptions + user_settings.
    INSERT INTO public.subscriptions (user_id, tier, status)
    SELECT pu.id, 'free', 'active' FROM public.users pu
    LEFT JOIN public.subscriptions s ON s.user_id = pu.id
    WHERE s.user_id IS NULL
    ON CONFLICT (user_id) DO NOTHING;

    INSERT INTO public.user_settings (user_id, settings)
    SELECT pu.id, '{}'::jsonb FROM public.users pu
    LEFT JOIN public.user_settings us ON us.user_id = pu.id
    WHERE us.user_id IS NULL
    ON CONFLICT (user_id) DO NOTHING;

    RAISE NOTICE 'migration 010: backfilled % users from auth.users', inserted_count;
END $$;
