# @cleanway/email-templates

Transactional email templates — 7 templates × 10 languages, pre-rendered at build time, sent via provider-agnostic Python service.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ packages/i18n-strings/src/{locale}.json  (source of truth)  │
│   └── email.* namespace — 60 strings × 10 languages         │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ packages/email-templates/src/                               │
│   ├── helpers/i18n.ts        loads locale JSON at render    │
│   ├── components/Shell.tsx   shared HTML frame              │
│   └── templates/{template}.tsx  (7 files)                   │
└─────────────────────────────────────────────────────────────┘
                              ↓ node scripts/build-emails.mjs
┌─────────────────────────────────────────────────────────────┐
│ packages/email-templates/out/                               │
│   ├── manifest.json                (subjects + fixtures)    │
│   └── {template}/{locale}.html + .txt   (70 HTML + 70 txt)  │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ api/services/email.py                                       │
│   1. Read pre-rendered HTML from disk                       │
│   2. Substitute fixture strings with real user data         │
│   3. Send via Resend / SES / noop provider (env-switchable) │
└─────────────────────────────────────────────────────────────┘
```

## Why pre-render instead of server-side React

- **Python container never runs Node** — email service is a few hundred lines of stdlib + httpx
- **Snapshots lock the output** — `pytest tests/test_email_i18n.py` + visual diffs in CI
- **Per-locale changes visible in PR** — reviewer sees the actual HTML that customers will receive
- **Zero startup cost** — load file, replace strings, send. Sub-millisecond.

## Templates

| Template | Subject (EN) | Trigger |
|---|---|---|
| `welcome` | "Welcome to Cleanway — you're protected now" | Account created |
| `receipt` | "Your Cleanway receipt" | Stripe payment succeeded |
| `weekly_report` | "Your week on Cleanway" | Sunday 08:00 UTC cron |
| `family_invite` | "$NAME$ invited you to join their Cleanway family" | Family admin adds member |
| `breach_alert` | "Your email was found in a data breach" | HIBP webhook / breach check match |
| `subscription_cancel` | "Your Cleanway subscription was canceled" | Stripe subscription.deleted |
| `granny_mode_invite` | "$NAME$ set up Cleanway protection for you" | Family admin enables Granny mode on a member device |

Each template has a specific tone:
- `granny_mode_invite` uses simplest vocabulary, assumes recipient is 60+ and may not have seen Cleanway before
- `receipt` is formal ("Hello NAME") — contains financial info
- `weekly_report` is warm-casual ("Hi NAME") — retention-focused
- `breach_alert` is urgent but not scary — "change your password" with clear next step

## Adding a new template

1. Add strings to `packages/i18n-strings/src/en.json` under `email.{your_template}.*`
2. Translate into all 9 other locales in the same files
3. Create `src/templates/{your_template}.tsx`:
   ```tsx
   export interface YourTemplateProps { locale: Locale; /* ... */ unsubscribeUrl: string; }
   export function subject(locale: Locale, props: YourTemplateProps): string {
     return t(locale, "email.your_template.subject");
   }
   export default function YourTemplate(props: YourTemplateProps) { /* ... */ }
   ```
4. Register in `src/index.ts` `TEMPLATES` map
5. Add fixture in `scripts/build-emails.mjs` `FIXTURES` object
6. Add the template key to `TemplateKey` union in `api/services/email.py`
7. `node scripts/build-emails.mjs`
8. Verify `packages/email-templates/out/{your_template}/` has 10 HTML + 10 TXT
9. Add fixture usage test in `tests/test_email_i18n.py`

## Build

```bash
node scripts/build-emails.mjs
# or via npm workspaces:
npm run build -w @cleanway/email-templates
```

Output:
- `out/{template_key}/{locale}.html` (70 files)
- `out/{template_key}/{locale}.txt` (70 files, plaintext fallback)
- `out/manifest.json` (subjects per locale + fixture values used for substitution)

## Substitution model

Templates are rendered with FIXTURE values (`Alex`, `https://cleanway.ai/...`).
Backend substitutes by REPLACING the fixture string with the real value.

Example: template rendered with `firstName: "Alex"` → HTML contains "Hi Alex,".
At send time, `email.py` gets called with `{"Alex": "Maria"}` override, which
becomes `html.replace("Alex", "Maria")` → "Hi Maria,".

**Downside:** if the fixture name collides with real content ("Alex" appears elsewhere), substitution corrupts it. Mitigation: use fixtures unlikely to appear in template content (e.g. `__FIRSTNAME__` is tempting, but we keep realistic names for snapshot review quality).

**Better approach future work:** switch to `{{mustache}}` placeholders in the rendered HTML. Requires post-processing the React Email output to leave those intact. Deferred until we hit a real collision.

## Privacy

- Templates never contain user data in the static `out/` files — only fixture values
- Backend logs never include the recipient email (only `send_id` UUID + `template_key` + `locale`)
- Unsubscribe tokens are HMAC-signed; tampered tokens rejected server-side (see `api/routers/email_unsubscribe.py`)
- `List-Unsubscribe-Post` header enables one-click unsubscribe via Gmail/Apple without any site visit (RFC 8058)

## Security checklist before enabling prod provider

- [ ] DKIM configured on sending domain (selector + public key in DNS TXT)
- [ ] SPF record allows provider's sending IPs
- [ ] DMARC policy `p=quarantine; rua=mailto:dmarc@yourdomain` at minimum
- [ ] Bounce / complaint webhook wired (Resend + SES both support)
- [ ] Unsubscribe flow end-to-end tested with real inbox (Gmail / Apple Mail / Outlook)
- [ ] Rate limiting per user_id (don't send >3 emails/hour/user from any template)
- [ ] Suppression list: never send to emails that hard-bounced or marked spam
