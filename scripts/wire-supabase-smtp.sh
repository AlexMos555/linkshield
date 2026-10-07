#!/usr/bin/env bash
# Point Supabase Auth at a real mail provider and install the Russian email
# templates — the one change that turns sign-in from "2 emails per hour,
# project members only" into something a T2 cohort can use.
#
# This is a thin launcher for scripts/supabase_mail.py (provider presets,
# config diff, templates, DNS records, verification). Dry run by default;
# nothing is written to Supabase until you pass --apply.
#
#   bash scripts/wire-supabase-smtp.sh                       # dry run, Яндекс 360 preset
#   bash scripts/wire-supabase-smtp.sh --apply               # write SMTP + templates, then verify
#   bash scripts/wire-supabase-smtp.sh --provider resend --apply
#   bash scripts/wire-supabase-smtp.sh --step dns --with-mx  # DNS records for cleanway.ai + support@
#   bash scripts/wire-supabase-smtp.sh --step dns --check-dns
#   bash scripts/wire-supabase-smtp.sh --step verify
#
# Inputs (environment or the git-ignored repo-root .env; never printed):
#   SUPABASE_ACCESS_TOKEN, SMTP_PROVIDER=yandex|resend|custom, SMTP_PASS,
#   SMTP_SENDER (default no-reply@cleanway.ai), optional SMTP_HOST/PORT/USER,
#   SMTP_SENDER_NAME, SMTP_RATE_LIMIT, SMTP_MIN_INTERVAL.
# Founder checklist: docs/EMAIL_SIGNIN.md.
set -euo pipefail
cd "$(dirname "$0")/.."

# No `set -x`, no echo of the environment: the password must never reach a
# terminal scrollback or a CI log. The Python side reads .env itself.
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "python3 is required (brew install python)" >&2
  exit 1
fi

exec "$PY" scripts/supabase_mail.py "$@"
