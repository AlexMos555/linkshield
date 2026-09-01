#!/usr/bin/env bash
# Point Supabase Auth at a real SMTP provider — the single change that turns
# sign-in from "2 emails per hour, project-wide" into something a Tele2 cohort
# can actually use. Nothing else in the launch is blocked by code; this is.
#
# Usage:
#   RESEND_API_KEY=re_xxx bash scripts/wire-supabase-smtp.sh
#
# Reads SUPABASE_ACCESS_TOKEN from the repo-root .env (git-ignored).
# Resend's SMTP bridge takes the literal username "resend" and the API key as
# the password, so no separate SMTP credential is needed.
set -euo pipefail
cd "$(dirname "$0")/.."

PROJECT_REF="${SUPABASE_PROJECT_REF:-bpyqgzzclsbfvxthyfsf}"
SENDER_EMAIL="${SMTP_SENDER_EMAIL:-noreply@cleanway.ai}"
SENDER_NAME="${SMTP_SENDER_NAME:-Cleanway}"

: "${RESEND_API_KEY:?set RESEND_API_KEY=re_... (Resend dashboard -> API Keys)}"
SB_TOKEN="$(grep -E '^SUPABASE_ACCESS_TOKEN=' .env | cut -d= -f2- | tr -d '"'"'"' ')"
: "${SB_TOKEN:?SUPABASE_ACCESS_TOKEN missing from .env}"

echo "→ sender domain must be VERIFIED in Resend, and cleanway.ai currently"
echo "  publishes SPF '-all' + DMARC p=reject, so add Resend to SPF first or"
echo "  every message will be rejected. (dig TXT cleanway.ai)"
echo

curl -sS -X PATCH \
  -H "Authorization: Bearer ${SB_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$(cat <<JSON
{
  "smtp_host": "smtp.resend.com",
  "smtp_port": 587,
  "smtp_user": "resend",
  "smtp_pass": "${RESEND_API_KEY}",
  "smtp_admin_email": "${SENDER_EMAIL}",
  "smtp_sender_name": "${SENDER_NAME}",
  "rate_limit_email_sent": 200
}
JSON
)" \
  "https://api.supabase.com/v1/projects/${PROJECT_REF}/config/auth" >/dev/null

echo "→ applied. verifying…"
curl -sS -H "Authorization: Bearer ${SB_TOKEN}" \
  "https://api.supabase.com/v1/projects/${PROJECT_REF}/config/auth" \
| python3 -c '
import sys, json
d = json.load(sys.stdin)
print("  smtp_host:", d.get("smtp_host") or "(still built-in!)")
print("  sender:   ", d.get("smtp_admin_email"))
print("  emails/h: ", d.get("rate_limit_email_sent"))
ok = bool(d.get("smtp_host")) and (d.get("rate_limit_email_sent") or 0) > 2
print("  =>", "SMTP wired — sign-in can scale" if ok else "NOT wired, check the response above")
'
echo
echo "Next: send yourself a code from the app and confirm the 6-digit token"
echo "arrives (templates already carry {{ .Token }}). Then enable CAPTCHA:"
echo "Supabase -> Authentication -> Bot and abuse protection."
