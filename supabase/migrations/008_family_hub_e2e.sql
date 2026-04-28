-- Migration 008: Family Hub E2E alerts + invites
--
-- The server is blind to alert content. It stores curve25519 public
-- keys and per-recipient ciphertexts only — clients do all encryption
-- with libsodium (TweetNaCl in JS, PyNaCl in mobile). A breach of our
-- DB leaks: who's in which family, when alerts were sent, and ciphertexts
-- nobody can decrypt without the private keys living on user devices.
--
-- Schema invariants:
--   1. One public key per (family_id, user_id). Rotation bumps key_version.
--   2. Each source alert spawns N rows in family_alerts — one per recipient,
--      each encrypted to that recipient's public key.
--   3. Invite codes are hashed (sha256) + PINs are bcrypt'd. Raw values
--      shown to inviter exactly once at creation time.

-- ═══════════════════════════════════════════════════════════
-- family_member_keys: curve25519 public key per (family, user)
-- ═══════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS public.family_member_keys (
    family_id UUID NOT NULL REFERENCES public.families(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    -- 32 bytes for curve25519 — enforce length so a malformed write is
    -- caught at the DB layer rather than producing useless ciphertexts.
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    key_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (family_id, user_id)
);

-- ═══════════════════════════════════════════════════════════
-- family_alerts: extend to per-recipient encrypted blobs
-- The pre-existing table from migration 001 had a single
-- encrypted_payload column shared across recipients. That model
-- doesn't fit libsodium's (sender_pubkey, recipient_pubkey, nonce)
-- envelope, so we add the missing columns. Old rows (if any) keep
-- the legacy single-payload shape — application reads the new
-- columns when present, falls back to the old one.
-- ═══════════════════════════════════════════════════════════
ALTER TABLE public.family_alerts
    ADD COLUMN IF NOT EXISTS sender_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS recipient_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS nonce BYTEA,
    ADD COLUMN IF NOT EXISTS sender_pubkey BYTEA,
    ADD COLUMN IF NOT EXISTS alert_type TEXT,
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

-- Index on recipient — the hottest query is "alerts for this user"
CREATE INDEX IF NOT EXISTS idx_family_alerts_recipient
    ON public.family_alerts (recipient_user_id, created_at DESC)
    WHERE recipient_user_id IS NOT NULL;

-- ═══════════════════════════════════════════════════════════
-- family_invites: code + PIN onboarding tokens
-- ═══════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS public.family_invites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    family_id UUID NOT NULL REFERENCES public.families(id) ON DELETE CASCADE,
    inviter_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    -- sha256 of the random invite code; raw shown once at creation
    invite_code_hash TEXT NOT NULL UNIQUE,
    -- bcrypt of the 4-digit PIN
    pin_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    redeemed_at TIMESTAMPTZ,
    redeemed_by_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Lookup index — bottlenecked path is hash → row during /accept
CREATE INDEX IF NOT EXISTS idx_family_invites_unredeemed
    ON public.family_invites (invite_code_hash)
    WHERE redeemed_at IS NULL;

-- ═══════════════════════════════════════════════════════════
-- RLS — server uses service_role for all writes, but readers use
-- their JWT so they only see their own data.
-- ═══════════════════════════════════════════════════════════
ALTER TABLE public.family_member_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.family_invites ENABLE ROW LEVEL SECURITY;

-- family_member_keys: family members can SELECT all keys for the
-- family (so they can encrypt to siblings). Users can INSERT/UPDATE
-- only their own key entry.
CREATE POLICY "Family members read keys" ON public.family_member_keys
    FOR SELECT USING (
        family_id IN (
            SELECT family_id FROM public.family_members
            WHERE user_id = auth.uid()
        )
    );

CREATE POLICY "Users write own key" ON public.family_member_keys
    FOR INSERT WITH CHECK (user_id = auth.uid());

CREATE POLICY "Users update own key" ON public.family_member_keys
    FOR UPDATE USING (user_id = auth.uid());

-- family_invites: read-by-creator only via JWT. All redemption goes
-- through the FastAPI backend with the service_role key — no
-- user-facing INSERT/UPDATE policy is intentional. RLS default-deny
-- blocks direct writes via the Supabase client SDK.
CREATE POLICY "Inviters read own invites" ON public.family_invites
    FOR SELECT USING (inviter_id = auth.uid());

COMMENT ON TABLE public.family_member_keys IS
    'Curve25519 public keys for E2E family alerts. Private keys stay on user devices.';

COMMENT ON TABLE public.family_invites IS
    'Code + PIN invite tokens. Raw values shown to inviter once at creation; only hashes persisted.';
