-- Migration 005: scam protection (Phase H)
-- Tables for:
--   H₁ — Caller ID + pre/post-call tips
--   H₂ — Crowd-source phone reports + verified bank numbers
--   H₃ — SMS phishing scanner (reports history)
--   H₄ — Scam pattern detection (text + voice analysis records)
--
-- Privacy stance: we NEVER store raw phone numbers — only SHA-256 hashes
-- (phone_hash). The client reports hash → we track counts + tags.
-- Trade-off: we can't reverse to show the number in an admin panel, which
-- is on purpose. For verified bank numbers the plaintext E.164 number
-- IS stored, because those are public knowledge (on the bank's website).

-- ═══════════════════════════════════════════════════════════════════════════
-- H₂: Crowd-sourced phone reports
-- ═══════════════════════════════════════════════════════════════════════════
-- One row per (phone_hash, country_code) — tally-style. Client increments
-- via a DB function so we avoid races on concurrent reports.

CREATE TABLE IF NOT EXISTS public.phone_reports (
    phone_hash       TEXT        NOT NULL,
    country_code     TEXT        NOT NULL CHECK (country_code ~ '^[A-Z]{2}$'),
    scam_count       INTEGER     NOT NULL DEFAULT 0,
    spam_count       INTEGER     NOT NULL DEFAULT 0,
    legit_count      INTEGER     NOT NULL DEFAULT 0,
    -- Aggregate tags picked by users — stored as counts so we can show
    -- "Most reported as: bank fraud (84), investment scam (12)".
    tags             JSONB       NOT NULL DEFAULT '{}'::jsonb,
    first_reported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_reported_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (phone_hash, country_code)
);

CREATE INDEX IF NOT EXISTS idx_phone_reports_last_seen
    ON public.phone_reports(last_reported_at DESC);

COMMENT ON TABLE public.phone_reports IS
    'Crowd-sourced scam call reports, keyed by SHA-256(phone) + country. Raw numbers are NEVER stored.';

-- Atomic upsert-and-increment. Clients call this via PostgREST.
CREATE OR REPLACE FUNCTION public.report_phone(
    p_hash TEXT,
    p_country TEXT,
    p_kind TEXT,   -- 'scam' | 'spam' | 'legit'
    p_tag TEXT DEFAULT NULL
) RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO public.phone_reports(phone_hash, country_code, scam_count, spam_count, legit_count, tags)
    VALUES (
        p_hash,
        p_country,
        CASE WHEN p_kind = 'scam' THEN 1 ELSE 0 END,
        CASE WHEN p_kind = 'spam' THEN 1 ELSE 0 END,
        CASE WHEN p_kind = 'legit' THEN 1 ELSE 0 END,
        CASE WHEN p_tag IS NOT NULL THEN jsonb_build_object(p_tag, 1) ELSE '{}'::jsonb END
    )
    ON CONFLICT (phone_hash, country_code) DO UPDATE SET
        scam_count       = public.phone_reports.scam_count  + EXCLUDED.scam_count,
        spam_count       = public.phone_reports.spam_count  + EXCLUDED.spam_count,
        legit_count      = public.phone_reports.legit_count + EXCLUDED.legit_count,
        last_reported_at = now(),
        tags = CASE
            WHEN p_tag IS NULL THEN public.phone_reports.tags
            ELSE jsonb_set(
                public.phone_reports.tags,
                ARRAY[p_tag],
                to_jsonb( COALESCE((public.phone_reports.tags->>p_tag)::int, 0) + 1 )
            )
        END;
END;
$$;

COMMENT ON FUNCTION public.report_phone IS
    'Atomically record a scam/spam/legit report for a hashed phone number. Safe against concurrent reports.';

-- ═══════════════════════════════════════════════════════════════════════════
-- H₂: Verified legitimate numbers (banks, gov services, mobile operators)
-- ═══════════════════════════════════════════════════════════════════════════
-- Operator-curated allowlist. Granny mode shows "📞 Official Sberbank number"
-- as a positive signal instead of "unknown caller".

CREATE TABLE IF NOT EXISTS public.verified_numbers (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    country_code     TEXT NOT NULL CHECK (country_code ~ '^[A-Z]{2}$'),
    -- E.164 or short code (e.g. "900" for Sberbank Russia)
    display_number   TEXT NOT NULL,
    -- SHA-256 of the normalized number — matches what the client computes
    phone_hash       TEXT NOT NULL,
    org_name         TEXT NOT NULL,
    org_category     TEXT NOT NULL CHECK (org_category IN (
        'bank', 'government', 'mobile_operator', 'utility', 'delivery', 'other'
    )),
    verified_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Source URL (e.g. bank's official "contact us" page) for auditability
    source_url       TEXT NOT NULL,
    active           BOOLEAN NOT NULL DEFAULT true,
    UNIQUE (phone_hash, country_code)
);

CREATE INDEX IF NOT EXISTS idx_verified_numbers_category
    ON public.verified_numbers(country_code, org_category) WHERE active;

COMMENT ON TABLE public.verified_numbers IS
    'Operator-curated allowlist of legitimate phone numbers (banks, gov, operators). Granny mode consults on incoming calls.';

-- ═══════════════════════════════════════════════════════════════════════════
-- H₃: SMS phishing reports
-- ═══════════════════════════════════════════════════════════════════════════
-- When the user's SMS Filter extension / default-SMS-app hook sees a message
-- that scores dangerous, it can report it so the URL / sender appear in
-- aggregate stats. We store derived features, NOT the raw SMS body.

CREATE TABLE IF NOT EXISTS public.sms_reports (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    sender_hash    TEXT NOT NULL,  -- SHA-256 of sender number or short code
    country_code   TEXT NOT NULL CHECK (country_code ~ '^[A-Z]{2}$'),
    -- Up to 5 bare domains found in the SMS (no path, no query)
    domains        TEXT[] NOT NULL DEFAULT '{}',
    pattern_tags   TEXT[] NOT NULL DEFAULT '{}',  -- e.g. {'delivery_scam','bank_impersonation'}
    risk_score     INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    reporter_user_id UUID REFERENCES public.users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_sms_reports_created ON public.sms_reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sms_reports_sender ON public.sms_reports(sender_hash, country_code);

COMMENT ON TABLE public.sms_reports IS
    'Smishing reports — features only, never raw SMS bodies. Powers per-sender reputation.';

-- ═══════════════════════════════════════════════════════════════════════════
-- H₄: Scam pattern analyses (text + voice)
-- ═══════════════════════════════════════════════════════════════════════════
-- Records of LLM-assisted scam detections. Used for:
--   - User's own history ("show me all suspect messages I asked about")
--   - Aggregate trend dashboard (which scam types are spiking this week)
-- Never stores the input — that's the user's private convo. Only keeps
-- the model's verdict + short reason codes.

CREATE TABLE IF NOT EXISTS public.scam_analyses (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID REFERENCES public.users(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    source          TEXT NOT NULL CHECK (source IN (
        'text_paste', 'voice_file', 'screenshot', 'sms', 'email'
    )),
    verdict         TEXT NOT NULL CHECK (verdict IN ('safe', 'suspicious', 'scam')),
    risk_score      INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    -- Model-produced reason codes, e.g.
    --   {'urgency', 'credential_request', 'crypto_investment', 'romance'}
    reason_codes    TEXT[] NOT NULL DEFAULT '{}',
    -- Language detected from the input (ISO 639-1) so we can build
    -- country-specific trend reports.
    language        TEXT CHECK (language IS NULL OR language ~ '^[a-z]{2}$'),
    -- Optional — country the user selected or we inferred from language
    country_code    TEXT CHECK (country_code IS NULL OR country_code ~ '^[A-Z]{2}$'),
    -- Approximate duration in seconds (for voice) or word count (for text)
    input_size      INTEGER
);

CREATE INDEX IF NOT EXISTS idx_scam_analyses_user ON public.scam_analyses(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scam_analyses_trend ON public.scam_analyses(country_code, created_at DESC) WHERE verdict = 'scam';

COMMENT ON TABLE public.scam_analyses IS
    'Per-user + aggregate record of LLM-assisted scam detections. Input payloads are never stored.';

-- ═══════════════════════════════════════════════════════════════════════════
-- Row-level security
-- ═══════════════════════════════════════════════════════════════════════════

ALTER TABLE public.phone_reports       ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.verified_numbers    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sms_reports         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scam_analyses       ENABLE ROW LEVEL SECURITY;

-- phone_reports: publicly readable (aggregate counts are the product),
-- writes only via the `report_phone` function (SECURITY DEFINER).
CREATE POLICY "phone_reports_public_read"
    ON public.phone_reports FOR SELECT
    USING (true);

-- verified_numbers: public read, operator-only write (restrict via dashboard)
CREATE POLICY "verified_numbers_public_read"
    ON public.verified_numbers FOR SELECT
    USING (active);

-- sms_reports: public aggregate read (for trend dashboards), authenticated write
CREATE POLICY "sms_reports_public_read"
    ON public.sms_reports FOR SELECT
    USING (true);

CREATE POLICY "sms_reports_authenticated_insert"
    ON public.sms_reports FOR INSERT
    WITH CHECK (auth.uid() IS NOT NULL);

-- scam_analyses: users read + write ONLY their own rows
CREATE POLICY "scam_analyses_own_read"
    ON public.scam_analyses FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "scam_analyses_own_write"
    ON public.scam_analyses FOR INSERT
    WITH CHECK (auth.uid() = user_id);
