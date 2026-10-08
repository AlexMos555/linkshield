# Supabase Auth email templates (Russian, grandma-plain)

These are the emails Supabase Auth sends for Cleanway sign-in. They are applied
to the project with `bash scripts/wire-supabase-smtp.sh --step templates --apply`
(dry run without `--apply`), which writes `mailer_subjects_<type>` and
`mailer_templates_<type>_content` through the Management API. Nothing here is
read at runtime by our code — Supabase renders them.

| File | Supabase template | When it is sent | Primary action |
|---|---|---|---|
| `magic_link.*` | Magic Link | sign-in code for an existing account (app `POST /auth/v1/otp`, web `signInWithOtp`) | the 6-digit code |
| `confirmation.*` | Confirm signup | the same request for a brand-new address | the 6-digit code |
| `recovery.*` | Reset Password | `/auth/v1/recover` — not used by any Cleanway screen today | button (link) |
| `email_change.*` | Change Email Address | `PUT /auth/v1/user` with a new email — not used today | button (link) |

Per type: `<type>.subject.txt` (one line), `<type>.html` (what Supabase sends —
Auth templates are HTML only) and `<type>.txt` (the same wording in plain text,
for review and for a future provider that takes a text part).

## Rules the script enforces (`validate_template`)

- `magic_link` and `confirmation` **show `{{ .Token }}` and contain no
  `{{ .ConfirmationURL }}`** — the app and the site both accept the code, so the
  email carries no link or button at all. Habit we want to teach: a Cleanway
  code email never asks you to click anything.
- `recovery` and `email_change` keep `{{ .ConfirmationURL }}` because nothing
  in the product accepts a code for those flows.
- no `http://` anywhere.
- the subject is a single line.

## Copy rules

- Russian first, one short English line at the bottom.
- Large type (body 20 px, code 44 px, letter-spacing), dark text on white — many
  readers are on a phone with large system fonts.
- The code before anything else, then «Код действует 1 час», then
  «Никому не сообщайте этот код», then what to do if you did not ask for it.
- «1 час» is pinned by the script (`mailer_otp_exp = 3600`), so the copy and
  the config cannot drift.
- Sender name is `Cleanway` (`smtp_sender_name`); the address is
  `no-reply@cleanway.ai` unless `SMTP_SENDER` says otherwise.
- No `support@` address in the copy until the mailbox exists (MX); point at
  the «Поддержка» page instead.

Changing a template: edit the file, run the dry run (it prints the diff and
the validation result), then `--apply`.
