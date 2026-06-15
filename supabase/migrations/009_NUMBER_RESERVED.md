# Migration 009 — number reserved (intentional gap)

This is a placeholder. There is no `009_*.sql` file by design.

## Why the gap exists

The original 009 migration was drafted during a Family Hub refactor
(Apr 2026) but rolled into 008_family_hub_e2e.sql before it ever ran
against any environment. We deliberately kept the number unused
rather than renumber 010+ because:

  - Several deployment environments had already imported 010+ by SHA
    when the rebase happened; renumbering would have triggered Supabase
    CLI to consider the existing 010 row in `schema_migrations` an
    unknown migration on the next sync.
  - The audit detection (backend-db LOW "Migration numbering gap (009
    missing) with no documentation — tooling and audit trails will
    infer a missing migration") flagged the silent gap as a real
    confusion source for future contributors. This file is the
    documentation pointer.

## What to do if you're adding a new migration

Use the next available number after the highest existing migration —
**do not reuse 009**. The Supabase CLI uses lexicographic filename
ordering, so 009 between 008 and 010 would re-run in dev environments
that snapshot from production.

## Future cleanup

Once every deployment environment is on migration ≥ 017 we can safely
rename this `.md` to a stub `.sql` if we want a fully-contiguous
numbering. Until then, this file IS the record of the gap.
