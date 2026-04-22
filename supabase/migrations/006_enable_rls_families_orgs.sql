-- Migration 006: Enable RLS on families, orgs, org_members
--
-- Fixes Supabase security advisor warning:
-- "Table publicly accessible — Row-Level Security is not enabled"
-- affecting LinkShield-EU (bpyqgzzclsbfvxthyfsf) and LinkShield-Staging
-- (dsjkfcllugmlegwymmth) as of 2026-04-19.
--
-- Without RLS, anyone with the project URL and anon key could read, edit,
-- or delete data in these tables. The backend is also a defense layer via
-- FastAPI JWT middleware, but RLS is defense-in-depth we should have had
-- from day one.

-- -----------------------------------------------------------------------------
-- families
-- -----------------------------------------------------------------------------
ALTER TABLE families ENABLE ROW LEVEL SECURITY;

-- Owner has full access (CRUD) to their own family row.
CREATE POLICY "Owners manage own family" ON families
    FOR ALL
    USING (auth.uid() = owner_id)
    WITH CHECK (auth.uid() = owner_id);

-- Family members can SELECT the family row they belong to.
CREATE POLICY "Members read their family" ON families
    FOR SELECT
    USING (id IN (SELECT family_id FROM family_members WHERE user_id = auth.uid()));

-- -----------------------------------------------------------------------------
-- orgs
-- -----------------------------------------------------------------------------
ALTER TABLE orgs ENABLE ROW LEVEL SECURITY;

-- Admin has full access to their own org row.
CREATE POLICY "Admins manage own org" ON orgs
    FOR ALL
    USING (auth.uid() = admin_user_id)
    WITH CHECK (auth.uid() = admin_user_id);

-- Members can SELECT the org they belong to.
CREATE POLICY "Members read their org" ON orgs
    FOR SELECT
    USING (id IN (SELECT org_id FROM org_members WHERE user_id = auth.uid()));

-- -----------------------------------------------------------------------------
-- org_members
-- -----------------------------------------------------------------------------
ALTER TABLE org_members ENABLE ROW LEVEL SECURITY;

-- Org admin can manage all memberships (add/remove/change role).
CREATE POLICY "Admins manage org memberships" ON org_members
    FOR ALL
    USING (org_id IN (SELECT id FROM orgs WHERE admin_user_id = auth.uid()))
    WITH CHECK (org_id IN (SELECT id FROM orgs WHERE admin_user_id = auth.uid()));

-- Users can read their own membership row.
CREATE POLICY "Members read own membership" ON org_members
    FOR SELECT
    USING (auth.uid() = user_id);
