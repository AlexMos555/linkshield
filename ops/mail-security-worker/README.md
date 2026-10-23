# Mail security: MTA-STS + TLS-RPT (Cloudflare Worker)

cleanway.ai receives mail through Cloudflare Email Routing (MX
`route1/2/3.mx.cloudflare.net`) and publishes DMARC `p=reject`. DMARC protects
other people from mail forged as us. **MTA-STS** (RFC 8461) protects mail sent
**to** us: a sender that supports it (Gmail, Outlook, Yahoo, ...) delivers to
cleanway.ai only over TLS, with a valid certificate, and only to the MX hosts
listed in our policy. Someone on the network path then cannot strip STARTTLS
or redirect the mail. **TLS-RPT** (RFC 8460) is how those senders tell us,
once a day, how their TLS sessions to us went.

`worker.js` runs as the Worker `cleanway-mail-security` and does three jobs:

| Where | What |
|---|---|
| `https://mta-sts.cleanway.ai/.well-known/mta-sts.txt` (custom domain) | serves the policy. Anything else on that host is a 404 |
| `tls-reports@cleanway.ai` (Email Routing rule → this Worker) | reads each TLS report, adds its session counts to the summary of the UTC day it arrived, and mails the founder when sessions failed |
| `https://cleanway-mail-security.amoskotin.workers.dev/` | `GET /`: the policy in force and the summaries of the last 30 days (counts only) |

The policy, as served with `MTA_STS_MODE` unset or `testing`:

```
version: STSv1
mode: testing
mx: route1.mx.cloudflare.net
mx: route2.mx.cloudflare.net
mx: route3.mx.cloudflare.net
max_age: 86400
```

Each line ends in CRLF. RFC 8461 §3.2 calls the fields "CRLF-separated" (its
ABNF also accepts a bare LF), and `mta-sts.google.com` serves CRLF too. The
response is `text/plain; charset=utf-8` with `cache-control: no-store`.
Senders cache the policy themselves for `max_age`, and RFC 8461 forbids HTTP
caching. `MTA_STS_MODE=enforce` serves `mode: enforce` with
`max_age: 604800` (one week). `none` retires the policy (see Rollout). Any
other value falls back to `testing`. The MX list is `MX_HOSTS` in `worker.js`
and must match the zone's MX records.

## What a report leaves behind

One KV key per UTC day the reports arrived on, `day:YYYY-MM-DD`, expiring
after 90 days:

| Field | Meaning |
|---|---|
| `reports`, `successful`, `failed` | reports read and their summed `total-successful-session-count` / `total-failure-session-count` |
| `policies` | the same sums per policy, e.g. `"sts cleanway.ai"` (the sender used our MTA-STS policy) or `"no-policy-found cleanway.ai"` (it did not see one) |
| `failures` | failed sessions per `result-type` and our MX host, e.g. `"certificate-host-mismatch route2.mx.cloudflare.net": 3` |
| `reporters` | reports per `organization-name` (Google Inc., Microsoft Corporation, ...) |
| `covers` | the days the reports describe (usually yesterday) |
| `errors`, `error_kinds` | mails that were not a readable report: `no report in the mail`, `bad base64`, `bad gzip`, `bad JSON`, `not a TLS report`, `bad session count`, `report too large` (over 256 KB unzipped), `mail too large` (over 256 KB). Real reports are a few KB, and the limits keep one mail inside the free plan's 10 ms of CPU |
| `alerted_at`, `alert_error` | when that day's alert went out; why the send failed (retried with the next failing report) |
| `capped` | 100 mails arrived that day; later ones were dropped unread |

Lists keep at most 20 names, and the rest are counted as `other`. The report
itself is never stored or forwarded. Sender and receiver IPs, contact
addresses and policy strings are dropped as the report is read. The free-text
`failure-reason-code` appears only in the alert mail. A mail that is not a
readable report is counted and then accepted and dropped, never rejected or
thrown back: a temporary failure would make the sender retry for days.

**Alert:** at most one mail per UTC day, from `alerts@cleanway.ai` to
`ALERT_TO`, sent with the first report that counts failed sessions. Subject:
`Cleanway: сбои TLS при доставке почты на cleanway.ai (<n>)`. It names the
reporter, the policy counts and each failure type with our MX host, says
whether the mode is `testing` (mail still arrives) or `enforce` (that mail is
not delivered), and links the summary page. Later reports that day only go to
the summary.

**Forged reports.** Anyone can mail `tls-reports@cleanway.ai`. A forged
report can skew a day's counts and send at most one alert that day. After 100
mails in a day the Worker stops writing. The free plan allows 1,000 KV writes
a day for the whole account, shared with the uptime monitor, so this Worker
uses at most 101 of them. It also uses one KV read per mail and 30 per view of
the summary page.

## Deploy (Cloudflare API, by hand)

Nothing in CI deploys this. The requests below use a token with *Edit* on
Workers Scripts and Workers KV Storage (account) and on Workers Routes, DNS and
Email Routing Rules (zone `cleanway.ai`):

```sh
CF=https://api.cloudflare.com/client/v4
CF_API_TOKEN=...      # never commit it
CF_ACCOUNT_ID=...     # Cloudflare → Workers & Pages → Account ID
CF_ZONE_ID=...        # Cloudflare → cleanway.ai → Overview → Zone ID
auth=(-H "Authorization: Bearer $CF_API_TOKEN")
```

The same paths work from a logged-in `dash.cloudflare.com` tab as
`fetch('/api/v4/<path>', { method, headers: { 'content-type': 'application/json' }, body })`.
For the upload in step 2, send a `FormData` with `metadata`
(`application/json` Blob) and `worker.js`
(`application/javascript+module` Blob, filename `worker.js`).

**1. KV namespace.** Keep the returned `result.id`:

```sh
curl -sS -X POST "$CF/accounts/$CF_ACCOUNT_ID/storage/kv/namespaces" "${auth[@]}" \
  -H "Content-Type: application/json" --data '{"title":"cleanway-mail-security"}'
KV_ID=...   # result.id from the answer
```

**2. Upload the Worker** as an ES module with its four bindings. `ALERT` is a
`send_email` binding: its destination must be a verified Email Routing
address. `amoskotin@gmail.com` already is, because the uptime monitor mails it.

```sh
cat > /tmp/mail-security-metadata.json <<EOF
{
  "main_module": "worker.js",
  "compatibility_date": "2026-10-01",
  "bindings": [
    { "type": "kv_namespace", "name": "STATE", "namespace_id": "$KV_ID" },
    { "type": "send_email", "name": "ALERT", "destination_address": "amoskotin@gmail.com" },
    { "type": "plain_text", "name": "ALERT_TO", "text": "amoskotin@gmail.com" },
    { "type": "plain_text", "name": "MTA_STS_MODE", "text": "testing" }
  ]
}
EOF
curl -sS -X PUT "$CF/accounts/$CF_ACCOUNT_ID/workers/scripts/cleanway-mail-security" "${auth[@]}" \
  -F "metadata=@/tmp/mail-security-metadata.json;type=application/json" \
  -F "worker.js=@ops/mail-security-worker/worker.js;type=application/javascript+module"
```

A later upload (a code change, or the mode switch below) is the same `PUT`
with all four bindings, because the `PUT` replaces the binding list.

**3. The workers.dev address** for the summary page:

```sh
curl -sS -X POST "$CF/accounts/$CF_ACCOUNT_ID/workers/scripts/cleanway-mail-security/subdomain" "${auth[@]}" \
  -H "Content-Type: application/json" --data '{"enabled":true}'
```

**4. Custom domain `mta-sts.cleanway.ai`.** No DNS record may exist under that
name first (none did on 2026-10-23). Cloudflare creates the proxied record and
the edge certificate, which takes a few minutes. The zone's CAA records
already allow Cloudflare's CAs.

```sh
curl -sS -X PUT "$CF/accounts/$CF_ACCOUNT_ID/workers/domains" "${auth[@]}" \
  -H "Content-Type: application/json" \
  --data '{"hostname":"mta-sts.cleanway.ai","service":"cleanway-mail-security","zone_id":"'"$CF_ZONE_ID"'","environment":"production"}'
```

**5. Email Routing rule** `tls-reports@cleanway.ai` → this Worker:

```sh
curl -sS -X POST "$CF/zones/$CF_ZONE_ID/email/routing/rules" "${auth[@]}" \
  -H "Content-Type: application/json" --data '{
    "name": "TLS-RPT reports to cleanway-mail-security",
    "enabled": true,
    "matchers": [{ "type": "literal", "field": "to", "value": "tls-reports@cleanway.ai" }],
    "actions": [{ "type": "worker", "value": ["cleanway-mail-security"] }]
  }'
```

**6. Check the policy before publishing DNS** (see Verify):
`curl -sS https://mta-sts.cleanway.ai/.well-known/mta-sts.txt`.

**7. The two TXT records** (DNS only, TTL 300). The `id` is the date you
publish it plus a two-digit counter, `yyyymmddNN`, e.g. `2026102401`:

```sh
curl -sS -X POST "$CF/zones/$CF_ZONE_ID/dns_records" "${auth[@]}" -H "Content-Type: application/json" \
  --data '{"type":"TXT","name":"_mta-sts.cleanway.ai","content":"\"v=STSv1; id=2026102401\"","ttl":300}'
curl -sS -X POST "$CF/zones/$CF_ZONE_ID/dns_records" "${auth[@]}" -H "Content-Type: application/json" \
  --data '{"type":"TXT","name":"_smtp._tls.cleanway.ai","content":"\"v=TLSRPTv1; rua=mailto:tls-reports@cleanway.ai\"","ttl":300}'
```

## Rollout

1. **Testing, about two weeks.** Senders fetch the policy and report on it,
   and nothing is enforced. A sender reports only for days it delivered mail
   to cleanway.ai. The domain receives little mail, so send a message from a
   Gmail and an Outlook account to `hello@cleanway.ai` a few times during the
   two weeks. Reports usually arrive the day after.
2. **Read the summaries** at `https://cleanway-mail-security.amoskotin.workers.dev/`.
   Go ahead when `policies` shows `sts cleanway.ai` from Google (and ideally
   Microsoft), so senders see the policy, and `failed` stayed `0`.
3. **Enforce.** Upload again with `"MTA_STS_MODE"` → `"enforce"` (step 2), or
   use Workers & Pages → `cleanway-mail-security` → Settings → Variables →
   `MTA_STS_MODE` → Deploy. Check that `curl` shows `mode: enforce` and
   `max_age: 604800`. **Only then** bump the id. A sender re-fetches the
   policy when it sees a new id, so bumping first would let it cache the old
   policy under the new id.

   ```sh
   RID=$(curl -sS "$CF/zones/$CF_ZONE_ID/dns_records?type=TXT&name=_mta-sts.cleanway.ai" "${auth[@]}" | jq -r '.result[0].id')
   curl -sS -X PATCH "$CF/zones/$CF_ZONE_ID/dns_records/$RID" "${auth[@]}" -H "Content-Type: application/json" \
     --data '{"content":"\"v=STSv1; id=2026110701\""}'
   ```
4. **Rollback** (enforce is blocking real mail): set `MTA_STS_MODE=testing`,
   check with `curl`, then bump the id. Senders that cached `enforce` look for
   a new id on their next delivery. **Retire MTA-STS entirely:** serve
   `MTA_STS_MODE=none` under a new id for at least one old `max_age` (one
   week). Then delete `_mta-sts`, the custom domain and the Worker.
5. **If the MX records change** (Cloudflare → Email → Email Routing shows
   them): update `MX_HOSTS` in `worker.js`, upload it, then bump the id. In
   `enforce`, senders defer mail to MX hosts the policy does not list, and they
   retry for days, so a fix the same day loses nothing.

## Verify

```sh
curl -sS -D - https://mta-sts.cleanway.ai/.well-known/mta-sts.txt
#   200, content-type: text/plain; charset=utf-8, cache-control: no-store, the policy above
curl -sS https://mta-sts.cleanway.ai/.well-known/mta-sts.txt | od -c | head -2    # lines end in \r \n
curl -sS -o /dev/null -w '%{http_code}\n' https://mta-sts.cleanway.ai/            # 404
dig +short TXT _mta-sts.cleanway.ai      # "v=STSv1; id=..."
dig +short TXT _smtp._tls.cleanway.ai    # "v=TLSRPTv1; rua=mailto:tls-reports@cleanway.ai"
curl -sS https://cleanway-mail-security.amoskotin.workers.dev/ | jq .policy
```

- **Routing to the Worker:** mail anything from Gmail to
  `tls-reports@cleanway.ai`. Today's summary then shows `"errors": 1`,
  `"error_kinds": {"no report in the mail": 1}`. It was not a report, so it
  is dropped.
- **Online checkers:** https://aykevl.nl/apps/mta-sts/ checks the TXT record,
  the policy and the MX certificates. Hardenize (https://www.hardenize.com/)
  has MTA-STS and TLS-RPT sections.

## When the alert arrives

The mail's `result-type` says what failed. The first step for each:

| `result-type` | Meaning | First step |
|---|---|---|
| `certificate-host-mismatch`, `certificate-expired`, `certificate-not-trusted`, `starttls-not-supported` | the TLS of a Cloudflare MX host (named in the mail) as that sender saw it | https://www.cloudflarestatus.com/ (Email Routing). Repeated, or from several senders, in `enforce`: roll back to `testing` (Rollout 4) |
| `validation-failure` | the sender's generic failure, often an MX host the policy does not list | compare the zone's MX records with `MX_HOSTS` (Rollout 5) |
| `sts-policy-fetch-error` | the sender could not fetch the policy | the `curl` above; Workers & Pages → `cleanway-mail-security` → the custom domain is still attached |
| `sts-webpki-invalid` | the certificate of `mta-sts.cleanway.ai` was not valid | the custom domain's certificate in Cloudflare |
| `sts-policy-invalid` | the policy text did not parse | should not happen (the tests pin it): compare `curl` with the policy above |

A few failures from one sender on one day in `testing` are usually that
sender's own TLS stack. Watch whether they come back. A forged report shows up
as a reporter that is not a mail provider you know.

Tests: `node --test ops/mail-security-worker/worker.test.mjs` (CI runs it
through `tests/test_mail_security_worker.py`).
