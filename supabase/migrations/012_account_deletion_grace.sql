-- Migration 012: GDPR-compliant account deletion with 30-day grace window.
--
-- Privacy Policy §9 promises: "Delete your account from Settings. All
-- server-side data is permanently removed within 30 days." We honour the
-- 30-day MAX by hard-deleting users.id (cascades wipe every row that
-- references it). The grace window has practical value:
--   * Accidental deletes (mistapped button) recoverable for 30 days
--   * Compliance with SAR / legal-hold processes that occasionally
--     surface after a deletion request
--   * Customers can revoke their deletion request from settings
--
-- This migration only adds the soft-delete marker. The actual purge
-- happens via a periodic job (see api/services/account_deletion.py)
-- that hard-deletes rows where deletion_requested_at <= now() - 30d.

ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS deletion_requested_at TIMESTAMPTZ NULL;

COMMENT ON COLUMN public.users.deletion_requested_at IS
    'When user requested account deletion via DELETE /api/v1/user/account. '
    'Auth dependency rejects requests from users with this set (410 Gone). '
    'Periodic purge job hard-deletes the row 30 days after this timestamp. '
    'Clearing the field (via POST /api/v1/user/account/restore within the '
    'grace window) cancels the deletion.';

-- Partial index: only rows with a deletion request, used by the purge
-- cron to find the small subset of users to actually delete. Full
-- table scan would be wasteful since 99.9% of rows have NULL here.
CREATE INDEX IF NOT EXISTS idx_users_deletion_requested
    ON public.users (deletion_requested_at)
    WHERE deletion_requested_at IS NOT NULL;
