-- Migration 004: user-level defaults for Skill Levels UX
-- Adds user-scoped accessibility + parental fields so they can sync across devices.
-- Device-scoped overrides already exist (migration 003) — these are the *defaults*.

ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS voice_alerts_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS font_scale REAL NOT NULL DEFAULT 1.0
        CHECK (font_scale >= 0.8 AND font_scale <= 2.5),
    -- Scrypt / bcrypt hash of the parental 4-digit PIN.
    -- NULL means no PIN set (Kids Mode unlocked); non-null means locked.
    -- Hash, not PIN, is stored — it is NEVER returned to the client.
    ADD COLUMN IF NOT EXISTS parental_pin_hash TEXT;

COMMENT ON COLUMN public.users.voice_alerts_enabled IS
    'Default for Granny mode voice alerts; individual devices can override via devices.voice_alerts_enabled.';

COMMENT ON COLUMN public.users.font_scale IS
    'UI font multiplier (0.8-2.5); default 1.0. Granny mode defaults to 1.3 client-side.';

COMMENT ON COLUMN public.users.parental_pin_hash IS
    'Bcrypt/scrypt hash of parental PIN for Kids mode. Never returned to clients.';
