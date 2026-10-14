# Restoring the database from the off-site backup

Nightly, `.github/workflows/db-backup.yml` stores an age-encrypted `pg_dump`
(schemas `public` and `auth`) in the Cloudflare R2 bucket `cleanway-db-backups`
(founder's Cloudflare account, 35-day retention). Supabase's own daily snapshots
stay the first choice; this copy is for when Supabase itself is unavailable,
suspended or compromised.

## What you need

- The decryption key: macOS Keychain item **"Cleanway DB backup decryption key
  (age)"** on the founder's Mac (a copy should also be in the founder's password
  manager). Public half: `age1yf0z2az8yrxf3zm50psnzyqker94y66dwllvpxnxrew6lxatwuksf6njkn`.
- Access to the Cloudflare account (R2 → `cleanway-db-backups` → download the
  newest `db/<date>.dump.age`), or `wrangler r2 object get`.
- `age` and PostgreSQL 17 client tools (`docker run --rm -it postgres:17` has them
  except age: `apt-get install age`).

## Steps

1. Download the newest object, e.g. `db/2026-10-15T01-17-04Z.dump.age`.
2. Decrypt:
   ```bash
   security find-generic-password -s "Cleanway DB backup decryption key (age)" -w > /tmp/age.key
   age -d -i /tmp/age.key -o db.dump db/2026-10-15T01-17-04Z.dump.age
   rm -P /tmp/age.key
   ```
3. Inspect: `pg_restore --list db.dump | head`.
4. Restore into a NEW Supabase project (or any Postgres 17):
   ```bash
   pg_restore --no-owner --no-privileges --schema=public -d "$NEW_DB_URL" db.dump
   # auth.* only into a fresh Supabase project whose auth schema matches:
   pg_restore --no-owner --no-privileges --schema=auth --data-only -d "$NEW_DB_URL" db.dump
   ```
5. Re-apply migrations 001+ if restoring schema-only elsewhere, point the API
   (`SUPABASE_URL`, keys) at the new project, redeploy Railway, update the mobile
   and landing env, and rotate every key.

## Drill

Once a quarter: run steps 1–3 on the latest object and record the date here.
A backup that was never restored is a hope, not a backup.

| Date | Object | Result |
|---|---|---|
| 2026-10-14 | first run `db/2026-10-14T16-32-17Z.dump.age` (194,946 B) in R2; drill on a fresh dump | encrypt → decrypt with the Keychain key → `pg_restore --list` 50 tables, byte-identical to the plaintext dump |
