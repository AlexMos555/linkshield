-- Missing FK indexes on hot RLS subquery columns.
--
-- Audit backend-db LOW "Missing indexes on three FK columns used in
-- hot RLS subqueries: families.owner_id, orgs.admin_user_id,
-- family_alerts.sender_user_id".
--
-- Several RLS policies in migrations 001/006/008 issue subqueries
-- against these columns (most often during permission checks) but
-- Postgres won't auto-index foreign keys — every check degenerates
-- to a sequential scan once the table grows past a few thousand rows.
-- Adding the indexes is essentially free (small tables today) and
-- saves an inevitable perf regression later.
--
-- All three indexes are non-unique (a user can own multiple families,
-- admin multiple orgs, and send multiple alerts) and idempotent via
-- IF NOT EXISTS so the migration is safe to re-run.

BEGIN;

CREATE INDEX IF NOT EXISTS idx_families_owner_id
    ON public.families (owner_id);

CREATE INDEX IF NOT EXISTS idx_orgs_admin_user_id
    ON public.orgs (admin_user_id);

-- family_alerts.sender_user_id was added in migration 008. The
-- recipient index is already covered (idx_family_alerts_recipient in
-- 008); this one covers the symmetric "alerts I sent" lookup.
CREATE INDEX IF NOT EXISTS idx_family_alerts_sender_user_id
    ON public.family_alerts (sender_user_id)
    WHERE sender_user_id IS NOT NULL;

COMMIT;
