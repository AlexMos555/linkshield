-- Cleanway "Boring Database" Schema
-- Server stores WHO you are. Device stores WHAT you do.
-- If this leaks: emails + subscription status. No URLs, no browsing data.

-- Users (minimal account info)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    auth_provider TEXT NOT NULL DEFAULT 'email', -- apple, google, email
    display_name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Subscriptions
CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tier TEXT NOT NULL DEFAULT 'free' CHECK (tier IN ('free', 'personal', 'family', 'business')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'cancelled', 'expired', 'past_due')),
    provider TEXT NOT NULL DEFAULT 'stripe' CHECK (provider IN ('stripe', 'apple_iap', 'google_play')),
    provider_subscription_id TEXT,
    current_period_start TIMESTAMPTZ,
    current_period_end TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id)
);

-- Devices (for sync + rate limiting)
CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_hash TEXT NOT NULL, -- anonymous device fingerprint
    platform TEXT NOT NULL CHECK (platform IN ('chrome_ext', 'firefox_ext', 'safari_ext', 'ios', 'android', 'web')),
    app_version TEXT,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, device_hash)
);

-- Weekly aggregates (NUMBERS ONLY — for percentile computation)
-- This is the most "interesting" server data, and it's just counters.
CREATE TABLE weekly_aggregates (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    week_start DATE NOT NULL, -- Monday of the week
    total_checks INTEGER NOT NULL DEFAULT 0,
    total_blocks INTEGER NOT NULL DEFAULT 0,
    total_trackers INTEGER NOT NULL DEFAULT 0,
    security_score INTEGER, -- 0-100, number only, no breakdown
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, week_start)
);

-- Families
CREATE TABLE families (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT 'My Family',
    max_members INTEGER NOT NULL DEFAULT 6,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE family_members (
    family_id UUID NOT NULL REFERENCES families(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'member')),
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (family_id, user_id)
);

-- Family alerts (E2E encrypted — server stores ciphertext only)
CREATE TABLE family_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    family_id UUID NOT NULL REFERENCES families(id) ON DELETE CASCADE,
    sender_device_hash TEXT NOT NULL,
    encrypted_payload BYTEA NOT NULL, -- E2E encrypted, server CANNOT read
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- User settings (synced across devices)
CREATE TABLE user_settings (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    settings JSONB NOT NULL DEFAULT '{"sensitivity": "balanced", "notifications": true, "weekly_report": true, "theme": "auto"}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- B2B Organizations
CREATE TABLE orgs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    admin_user_id UUID NOT NULL REFERENCES users(id),
    sso_config JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE org_members (
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);

-- API rate limiting tracking
CREATE TABLE rate_limits (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    date DATE NOT NULL DEFAULT CURRENT_DATE,
    api_calls INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, date)
);

-- Indexes
CREATE INDEX idx_devices_user ON devices(user_id);
CREATE INDEX idx_devices_last_seen ON devices(last_seen);
CREATE INDEX idx_weekly_agg_week ON weekly_aggregates(week_start);
CREATE INDEX idx_family_alerts_family ON family_alerts(family_id);
CREATE INDEX idx_family_alerts_created ON family_alerts(created_at);
CREATE INDEX idx_rate_limits_date ON rate_limits(date);

-- Auto-cleanup: delete family alerts older than 7 days
-- (Run as Supabase cron or pg_cron)
-- SELECT cron.schedule('cleanup-alerts', '0 3 * * *',
--   $$DELETE FROM family_alerts WHERE created_at < now() - interval '7 days'$$
-- );

-- Auto-cleanup: delete rate limit records older than 2 days
-- SELECT cron.schedule('cleanup-rates', '0 4 * * *',
--   $$DELETE FROM rate_limits WHERE date < CURRENT_DATE - 1$$
-- );

-- Row Level Security (users see only their own data)
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE weekly_aggregates ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE family_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE family_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY;

-- RLS Policies
CREATE POLICY "Users read own data" ON users FOR SELECT USING (auth.uid() = id);
CREATE POLICY "Users update own data" ON users FOR UPDATE USING (auth.uid() = id);

CREATE POLICY "Users read own subscription" ON subscriptions FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users manage own devices" ON devices FOR ALL USING (auth.uid() = user_id);

CREATE POLICY "Users manage own aggregates" ON weekly_aggregates FOR ALL USING (auth.uid() = user_id);

CREATE POLICY "Users manage own settings" ON user_settings FOR ALL USING (auth.uid() = user_id);

CREATE POLICY "Family members read alerts" ON family_alerts FOR SELECT
    USING (family_id IN (SELECT family_id FROM family_members WHERE user_id = auth.uid()));

CREATE POLICY "Family members insert alerts" ON family_alerts FOR INSERT
    WITH CHECK (family_id IN (SELECT family_id FROM family_members WHERE user_id = auth.uid()));

CREATE POLICY "Users read own rate limits" ON rate_limits FOR SELECT USING (auth.uid() = user_id);
