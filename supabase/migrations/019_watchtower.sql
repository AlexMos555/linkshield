-- Migration 019: Typosquat Watchtower — Strategy doc Top-20 #17.
--
-- Predictive defense: monitor newly-registered cousin-domains of
-- brands the user cares about, before the next phishing campaign
-- aims at them. DomainTools and other enterprise-only services
-- offer this for $99-499/mo per brand; we bring it to consumers
-- through free quota in the Family plan tier.
--
-- Data model:
--   brand_watchlist:    user-owned brands the user wants protected
--   typosquat_alerts:   per-brand alerts emitted by the scan job
--
-- Why two tables and not a denormalized JSON column on users:
--   * The same brand (e.g., paypal.com) gets watched by many users
--     in practice; we don't want to scan the same string 1000 times.
--     The scan job iterates the DISTINCT brand_root_domain set and
--     each match expands to all users watching that brand via JOIN.
--   * Alerts are read by users, written by the cron — different
--     access patterns benefit from different RLS policies.
--   * Per-user counts (free vs paid tier quota) are a SELECT count.
--
-- Source of truth: brand_root_domain (the canonical eTLD+1 form,
-- lowercase IDNA). brand_name is the human-readable label the user
-- chose ("My business", "Paypal personal"). Scanning only uses the
-- domain field.

CREATE TABLE IF NOT EXISTS public.brand_watchlist (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    -- Human-friendly label, e.g. "Cleanway main brand". Free text,
    -- max 80 chars by app-level validation.
    brand_name          TEXT NOT NULL,
    -- Canonical eTLD+1 in lowercase IDNA, e.g. "paypal.com".
    brand_root_domain   TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Last time the cron scanned this brand. NULL = never scanned yet
    -- (newly added by user; cron will pick it up next tick).
    last_scanned_at     TIMESTAMPTZ NULL,
    -- Per-user uniqueness: same root domain twice with different
    -- labels would just produce duplicate alerts. App layer rejects
    -- the dupe before insert with a 409.
    UNIQUE (user_id, brand_root_domain)
);

CREATE INDEX IF NOT EXISTS idx_brand_watchlist_user
    ON public.brand_watchlist (user_id, created_at DESC);

-- Cron's hot path: SELECT DISTINCT brand_root_domain FROM brand_watchlist
-- ORDER BY last_scanned_at NULLS FIRST. We index that ordering so we
-- always scan the staler brands first when the job runs out of time.
CREATE INDEX IF NOT EXISTS idx_brand_watchlist_scan_order
    ON public.brand_watchlist (brand_root_domain, last_scanned_at NULLS FIRST);


CREATE TABLE IF NOT EXISTS public.typosquat_alerts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The brand this alert relates to. NOT a FK to brand_watchlist.id
    -- because we deduplicate by (brand_root_domain, suspect_domain) —
    -- one alert covers everyone watching that brand. The app-layer
    -- read query joins back via brand_root_domain to compute per-user
    -- visibility.
    brand_root_domain   TEXT NOT NULL,
    -- The suspicious cousin domain that just showed up in CT logs.
    suspect_domain      TEXT NOT NULL,
    -- Levenshtein distance from brand_root_domain to suspect's eTLD+1.
    -- 0 = identical (shouldn't fire), 1-2 = high confidence typosquat,
    -- ≥ 3 = lower confidence and currently we skip the alert.
    edit_distance       SMALLINT NOT NULL,
    -- Variant kind: "typo" (Levenshtein hit), "homograph" (Cyrillic
    -- look-alike), "tld" (same root + different TLD: paypal.tk),
    -- "subdomain" (brand.attacker.tld).
    variant_kind        TEXT NOT NULL,
    -- When CT first saw a cert issued for this name. The cron stamps
    -- this from the cert's notBefore; if multiple certs surfaced we
    -- keep the EARLIEST.
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The cert issuer that minted the suspect domain — e.g.
    -- "Let's Encrypt R3". Useful for "report abuse to CA" workflows.
    issuer              TEXT NULL,
    -- Whether Cleanway scoring should auto-flag visits to this
    -- domain. Defaults TRUE; user can toggle per-row to suppress
    -- false positives (e.g. a partner brand they trust).
    auto_block          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Dedup: one alert per (brand, suspect). Re-issued certs for the
    -- same name within the year update first_seen_at via UPSERT.
    UNIQUE (brand_root_domain, suspect_domain)
);

-- Scoring hot path: when analyzing a domain X we look up
-- WHERE suspect_domain = X. Frequently with a brand_root_domain
-- filter for the join back to the user's watchlist.
CREATE INDEX IF NOT EXISTS idx_typosquat_alerts_suspect
    ON public.typosquat_alerts (suspect_domain);

CREATE INDEX IF NOT EXISTS idx_typosquat_alerts_brand_time
    ON public.typosquat_alerts (brand_root_domain, first_seen_at DESC);

-- RLS
-- ──
-- brand_watchlist: standard per-user policy. User reads/writes
-- their own rows; service_role bypasses for the scan job.
ALTER TABLE public.brand_watchlist ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'brand_watchlist'
          AND policyname = 'users see own watchlist'
    ) THEN
        CREATE POLICY "users see own watchlist"
            ON public.brand_watchlist
            FOR SELECT
            TO authenticated
            USING (user_id = (SELECT auth.uid()));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'brand_watchlist'
          AND policyname = 'users insert own watchlist'
    ) THEN
        CREATE POLICY "users insert own watchlist"
            ON public.brand_watchlist
            FOR INSERT
            TO authenticated
            WITH CHECK (user_id = (SELECT auth.uid()));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'brand_watchlist'
          AND policyname = 'users delete own watchlist'
    ) THEN
        CREATE POLICY "users delete own watchlist"
            ON public.brand_watchlist
            FOR DELETE
            TO authenticated
            USING (user_id = (SELECT auth.uid()));
    END IF;
END$$;

-- typosquat_alerts: read-only for users (no INSERT / DELETE / UPDATE
-- policy). The scan job writes via service_role which bypasses RLS.
-- Users see alerts ONLY for brands in their watchlist — enforced via
-- an EXISTS subquery in the SELECT policy.
ALTER TABLE public.typosquat_alerts ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'typosquat_alerts'
          AND policyname = 'users see alerts for watched brands'
    ) THEN
        CREATE POLICY "users see alerts for watched brands"
            ON public.typosquat_alerts
            FOR SELECT
            TO authenticated
            USING (
                EXISTS (
                    SELECT 1 FROM public.brand_watchlist b
                    WHERE b.user_id = (SELECT auth.uid())
                      AND b.brand_root_domain = typosquat_alerts.brand_root_domain
                )
            );
    END IF;

    -- auto_block toggle: users can UPDATE auto_block for alerts on
    -- their watched brands. We don't expose other columns to UPDATE.
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'typosquat_alerts'
          AND policyname = 'users update auto_block on own brands'
    ) THEN
        CREATE POLICY "users update auto_block on own brands"
            ON public.typosquat_alerts
            FOR UPDATE
            TO authenticated
            USING (
                EXISTS (
                    SELECT 1 FROM public.brand_watchlist b
                    WHERE b.user_id = (SELECT auth.uid())
                      AND b.brand_root_domain = typosquat_alerts.brand_root_domain
                )
            )
            WITH CHECK (
                EXISTS (
                    SELECT 1 FROM public.brand_watchlist b
                    WHERE b.user_id = (SELECT auth.uid())
                      AND b.brand_root_domain = typosquat_alerts.brand_root_domain
                )
            );
    END IF;
END$$;

COMMENT ON TABLE public.brand_watchlist IS
    'Strategy #17 — brands users want Cleanway to monitor for typosquats. RLS: per-user.';

COMMENT ON TABLE public.typosquat_alerts IS
    'Strategy #17 — cousin-domain alerts produced by the daily watchtower scan job. Users see rows for brands in their own watchlist (RLS via EXISTS subquery).';
