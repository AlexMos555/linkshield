-- Migration 026: an org goes with the user who administers it.
--
-- Migration 001 declared `orgs.admin_user_id UUID NOT NULL REFERENCES
-- users(id)` with no ON DELETE (NO ACTION): deleting a user who administers
-- an org fails with a foreign-key violation. The GDPR purge
-- (api/services/account_purge.py) deletes a batch of users in one DELETE,
-- so a single org admin in the batch failed the whole batch — every run,
-- after the auth identities had already been deleted.
--
-- The purge now deletes those orgs itself before the users (and falls back
-- to one DELETE per user on a conflict); this migration makes the database
-- agree, so an org is deleted with its admin however the users row goes.
-- org_members already cascade from orgs (001), and orgs.admin_user_id is
-- indexed (018), so the cascade is an index lookup.
--
-- The constraint is dropped by whatever name it carries (001 left the name
-- to Postgres) and recreated under the default name, in one transaction.
-- Re-running the migration is safe.

BEGIN;

DO $$
DECLARE
    fk record;
BEGIN
    FOR fk IN
        SELECT c.conname
        FROM pg_constraint c
        JOIN pg_attribute a
          ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
        WHERE c.conrelid = 'public.orgs'::regclass
          AND c.contype = 'f'
          AND a.attname = 'admin_user_id'
    LOOP
        EXECUTE format('ALTER TABLE public.orgs DROP CONSTRAINT %I', fk.conname);
    END LOOP;
END
$$;

ALTER TABLE public.orgs
    ADD CONSTRAINT orgs_admin_user_id_fkey
    FOREIGN KEY (admin_user_id) REFERENCES public.users (id) ON DELETE CASCADE;

COMMENT ON CONSTRAINT orgs_admin_user_id_fkey ON public.orgs IS
    'ON DELETE CASCADE since migration 026: deleting the admin (the GDPR purge) deletes the org and, by cascade, its org_members.';

COMMIT;
