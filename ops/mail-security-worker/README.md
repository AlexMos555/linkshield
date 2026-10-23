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
| `https://cleanway-mail-security.amoskotin.workers.dev/` | `GET /`: the policy in force and the summaries of the last 30 days (counts only), one KV read |

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

One KV key, `summary`: the summaries of the last 30 UTC days the reports
arrived on, newest first. The key expires 31 days after its last write. Each
day has:

| Field | Meaning |
|---|---|
| `reports`, `successful`, `failed` | reports read and their summed `total-successful-session-count` / `total-failure-session-count` |
| `policies` | the same sums per policy, e.g. `"sts cleanway.ai"` (the sender used our MTA-STS policy) or `"no-policy-found cleanway.ai"` (it did not see one). A `policy-type` outside RFC 8460 is `other`, and a `policy-domain` other than `cleanway.ai` is `other-domain` |
| `failures` | failed sessions per `result-type` and our MX host, e.g. `"certificate-host-mismatch route2.mx.cloudflare.net": 3`. A `result-type` outside RFC 8460 is `other`, a host not in `MX_HOSTS` is `other-host`, no host is `?` |
| `reporters` | reports per domain of the mail's `From` header (`google.com`, `microsoft.com`, ...). `unknown` when the header is not exactly one plain address |
| `covers` | the days the reports describe (usually yesterday) |
| `errors`, `error_kinds` | mails that were not a readable report: `no report in the mail`, `bad base64`, `bad gzip`, `bad JSON`, `not a TLS report`, `bad session count`, `report too large` (over 256 KB unzipped), `mail too large` (over 256 KB). Real reports are a few KB, and the limits keep one mail inside the free plan's 10 ms of CPU |
| `errors_capped` | 20 such mails arrived that day; later ones were not counted |
| `capped` | 100 reports were counted that day; later ones were not counted, but can still send an alert |
| `alerts` | when each of that day's alerts was sent: `google.com`, `microsoft.com`, `other` (see Alert) |
| `alert_tries`, `alert_error` | sends attempted that day (at most 5); the last send that failed and why (that alert is retried with the next failing report) |

Lists keep at most 20 names, and the rest are counted as `other`. The report
itself is never stored or forwarded. Sender and receiver IPs, contact
addresses, policy strings and `failure-reason-code` are dropped as the report
is read (a reason that looks like a code, e.g. `X509_V_ERR_HOSTNAME_MISMATCH`,
goes into the alert mail only). A redelivered report counts once: today's
entry keeps a hash of each report's JSON. A mail that is not a readable
report is counted and then accepted and dropped, never rejected or thrown
back: a temporary failure would make the sender retry for days.

**Alert:** a mail from `alerts@cleanway.ai` to `ALERT_TO`, sent with the first
report of the UTC day that counts failed sessions, at most once a day for
each known reporter (`KNOWN_REPORTERS` in `worker.js`: `google.com`,
`microsoft.com`) and once a day for all other reporters together, so at most
three a day. Subject: `Cleanway: сбои TLS при доставке почты на cleanway.ai
(<n>)`. It gives the policy counts and up to 5 policies × 5 failure types
with our MX host, says whether the mode is `testing` (mail still arrives) or
`enforce` (that mail is not delivered), and links the summary page. Later
reports from that reporter that day only go to the summary. The alert is
recorded in KV before it is sent. If that write fails, nothing is sent and
the next failing report tries again. If the send fails, the record is undone
and the next failing report retries, at most 5 sends a day.

**Forged reports.** Anyone can mail `tls-reports@cleanway.ai`: the address is
public in the `_smtp._tls` record. What a forger can and cannot do:

- **Shadow a real report: no.** Reports are deduplicated by a hash of their
  JSON, not by `organization-name` and `report-id`, which anyone can copy
  (Google's id is predictable).
- **Silence Google's or Microsoft's alert: no.** A reporter is the domain of
  the mail's `From` header. `google.com` and `microsoft.com` publish DMARC
  `p=reject`, and Email Routing rejects mail that fails the sender's DMARC
  policy, so mail `From` them is theirs. Every other reporter, forged or not,
  shares the third daily alert. An alert from such a reporter says it may be
  forged and shows nothing the sender wrote. Its address is in the summary
  under `reporters`.
- **Put words into the alert: no.** It repeats only values from closed sets
  (RFC 8460 `result-type` and `policy-type`, our MX hosts, `cleanway.ai`, ISO
  dates, numbers), a `failure-reason-code` only when it looks like a code (no
  spaces, no dots), and, for a known reporter, its plain company name.
  Invisible and bidi control characters are stripped.
- **Skew a day's counts: yes.** Forged reports add to that day's summary.
  20 junk mails or 100 reports end the counting for the day. Junk cannot use
  up the reports' budget, and a capped day still sends alerts.

KV on the free plan allows 1,000 writes and 100,000 reads a day for the whole
account, shared with the uptime monitor (about 150 writes a day and a read
every minute). This Worker writes at most once per mail, twice when an alert
fails to send: at most 20 + 1 for junk, 100 + 1 for reports and 10 for
alerts, so about 130 a day. It reads
once per mail and once per view of the summary page. KV has no atomic update,
and a read can be up to 60 s stale at another location. Under concurrent
delivery these daily limits (and the counts) are best effort.

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
   Go ahead when `reporters` has `google.com` (and ideally `microsoft.com`),
   `policies` shows `sts cleanway.ai` (senders see the policy), and `failed`
   stayed `0`.
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
sender's own TLS stack. Watch whether they come back. An alert from a reporter
outside `KNOWN_REPORTERS` may be forged: look at `reporters` in the summary.
If it is a real mail provider that reports every day, add its `From` domain to
`KNOWN_REPORTERS`, but only if that domain publishes DMARC `p=reject`
(`dig +short TXT _dmarc.<domain>`).

Tests: `node --test ops/mail-security-worker/worker.test.mjs
ops/mail-security-worker/forged.test.mjs` (CI runs both through
`tests/test_mail_security_worker.py`).
