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
- Large type (body 19 px, code 40 px monospace with letter-spacing, 34 px on
  narrow screens) — many readers are on a phone with large system fonts.
- The code before anything else, then «Код действует 1 час», then
  «Никому не сообщайте этот код», then what to do if you did not ask for it.
- «1 час» is pinned by the script (`mailer_otp_exp = 3600`), so the copy and
  the config cannot drift.
- Sender name is `Cleanway` (`smtp_sender_name`); the address is
  `no-reply@cleanway.ai` unless `SMTP_SENDER` says otherwise.
- Footer: one line on why the email was sent, then «Помощь: support@cleanway.ai
  или раздел «Поддержка» на сайте cleanway.ai» — plain text, never a `mailto:`
  link (code emails carry no `<a>` at all).

## Visual style (matches the app)

Colors come from `mobile/src/utils/theme.ts`; keep them in sync when the app
palette moves.

| Role | Value | App token |
|---|---|---|
| Page background | `#0B1220` | `colors.bg` |
| Card | `#141A28`, 1 px border `#1E2536`, radius 20 | `bgCard` / `border` / `radius.card` |
| Headings, body | `#F1F5F9` | `textPrimary` |
| Secondary text | `#94A3B8`; fine print `#6B7A93` | `textSecondary` / `textMuted` |
| Code box | `#183136`, border `#1C4844` (green wash/stroke over the card) | `greenWash` / `greenStroke` |
| «Код действует 1 час» | `#34D399` | `green` |
| Warning box | `#302531`, border `#4D303A`, text `#F87171` | `dangerWash` / `dangerStroke` / `danger` |
| Button (link emails) | `#4C8DFF`, white text, radius 14 | `blue` / `radius.control` |

Logo: `https://cleanway.ai/icon-192.png` (served from `landing/public`) at
40 px next to the «Cleanway» wordmark. Mail-client rules: table layout, inline
CSS (the `<style>` block only adds narrow-screen and dark-mode extras), system
fonts, no SVG/background images/web fonts, `bgcolor` + inline
`background-color` on every filled cell, `color-scheme: light dark` meta so
Apple Mail does not invert the already-dark design, a hidden preheader.

Changing a template: edit the file, run the dry run (it prints the diff and
the validation result), then `--apply`.
