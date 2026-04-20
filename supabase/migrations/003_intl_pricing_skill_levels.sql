-- Migration 003: intl + regional pricing + skill levels + freemium threshold
-- Adds fields needed for Phase C (i18n UX), Phase D (skill levels), and Pricing v2 (50-threat counter).

-- ═══════════════════════════════════════════════════════════
-- users: locale preference + skill level per user
-- ═══════════════════════════════════════════════════════════
ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS preferred_locale TEXT NOT NULL DEFAULT 'en'
        CHECK (preferred_locale IN ('en', 'es', 'hi', 'pt', 'ru', 'ar', 'fr', 'de', 'it', 'id')),
    ADD COLUMN IF NOT EXISTS skill_level TEXT NOT NULL DEFAULT 'regular'
        CHECK (skill_level IN ('kids', 'regular', 'granny', 'pro'));

-- ═══════════════════════════════════════════════════════════
-- subscriptions: billing country (для regional pricing)
-- Из Stripe customer.address.country (ISO 3166-1 alpha-2)
-- ═══════════════════════════════════════════════════════════
ALTER TABLE public.subscriptions
    ADD COLUMN IF NOT EXISTS billing_country TEXT
        CHECK (billing_country ~ '^[A-Z]{2}$' OR billing_country IS NULL),
    ADD COLUMN IF NOT EXISTS pricing_tier INTEGER
        CHECK (pricing_tier BETWEEN 1 AND 4 OR pricing_tier IS NULL),
    ADD COLUMN IF NOT EXISTS currency TEXT DEFAULT 'USD';

-- ═══════════════════════════════════════════════════════════
-- devices: per-device skill level (override user default for Family Hub)
-- Пример: бабушка использует семейный аккаунт, её устройство в Granny Mode
-- ═══════════════════════════════════════════════════════════
ALTER TABLE public.devices
    ADD COLUMN IF NOT EXISTS skill_level_override TEXT
        CHECK (skill_level_override IN ('kids', 'regular', 'granny', 'pro') OR skill_level_override IS NULL),
    ADD COLUMN IF NOT EXISTS voice_alerts_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS font_scale REAL NOT NULL DEFAULT 1.0
        CHECK (font_scale >= 0.8 AND font_scale <= 2.5);

-- ═══════════════════════════════════════════════════════════
-- user_settings: threat counter для 50-threshold freemium paywall
-- Server-side для cross-device sync. Девайс присылает increment после блокировки.
-- При hit 50 и free tier → показываем nudge на paywall.
-- ═══════════════════════════════════════════════════════════
ALTER TABLE public.user_settings
    ADD COLUMN IF NOT EXISTS threats_blocked_lifetime INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS threshold_nudge_shown_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS threshold_nudge_count INTEGER NOT NULL DEFAULT 0;

-- ═══════════════════════════════════════════════════════════
-- family_members: remote skill-level management
-- Admin может удалённо менять skill level у члена семьи
-- ═══════════════════════════════════════════════════════════
ALTER TABLE public.family_members
    ADD COLUMN IF NOT EXISTS managed_skill_level TEXT
        CHECK (managed_skill_level IN ('kids', 'regular', 'granny', 'pro') OR managed_skill_level IS NULL);

-- ═══════════════════════════════════════════════════════════
-- Indexes для новых полей в типичных запросах
-- ═══════════════════════════════════════════════════════════
CREATE INDEX IF NOT EXISTS idx_users_locale ON public.users(preferred_locale);
CREATE INDEX IF NOT EXISTS idx_subs_country ON public.subscriptions(billing_country) WHERE billing_country IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_subs_tier ON public.subscriptions(pricing_tier) WHERE pricing_tier IS NOT NULL;

-- ═══════════════════════════════════════════════════════════
-- Updated RLS policy: user_settings update (включая threat counter)
-- Существующая политика "Users manage own settings" уже покрывает ALL — не требует изменений
-- ═══════════════════════════════════════════════════════════

-- ═══════════════════════════════════════════════════════════
-- Function: get_pricing_tier(country_code TEXT) → INTEGER
-- Позволяет SQL запросам определять tier для страны без API
-- ═══════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION public.get_pricing_tier(country_code TEXT)
RETURNS INTEGER
LANGUAGE SQL
IMMUTABLE
AS $$
  SELECT CASE
    -- T1: Premium markets
    WHEN country_code IN (
      'US','CA','GB','DE','FR','AU','JP','SG','NL','NO','SE','CH',
      'DK','FI','AT','BE','IE','NZ','LU','IS'
    ) THEN 1
    -- T3: Mid-emerging
    WHEN country_code IN (
      'PE','CO','EC','BO','PY','VE','DO','GT','HN','SV','NI','CU',
      'TH','PH','MY','ZA','UA','BY','KZ','RS','MK','AL','BA','ME',
      'GE','AM','AZ','MD','TN','MA','JO','LB'
    ) THEN 3
    -- T4: Affordable
    WHEN country_code IN (
      'IN','ID','VN','PK','BD','EG','NG','KE','LK','MM','NP','KH',
      'LA','MW','UG','TZ','ZW','ZM','MZ','SN','CI','CM'
    ) THEN 4
    -- T2: Base (default)
    ELSE 2
  END;
$$;

COMMENT ON FUNCTION public.get_pricing_tier(TEXT) IS
  'Map ISO 3166-1 alpha-2 country code to pricing tier (1=Premium, 2=Base, 3=Mid, 4=Affordable).';
