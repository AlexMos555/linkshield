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
| `https://cleanway-mail-security.amoskotin.workers.dev/` | `GET /`: the policy in force and the summaries of the last 30 days (counts only), Google's and Microsoft's apart from everyone else's |

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

Reports are kept apart by trust, in three **groups**: `google.com`,
`microsoft.com` (the known reporters, whose mail is vouched for by DMARC: see
Forged reports) and `unverified` (every other reporter, real or forged). Each
group has its own KV key (`summary:google.com`, `summary:microsoft.com`,
`summary:unverified`) with its summaries of the last 30 UTC days the reports
arrived on. A key expires 31 days after its last write. The summary page
shows each day like this:

```
{ "day": "2026-10-23",
  "verified":   { "google.com": { "reports": 1, "successful": 1200, "failed": 0,
                                  "policies": { "sts cleanway.ai": { "successful": 1200, "failed": 0 } }, ... } },
  "unverified": { "reports": 0, "successful": 0, "failed": 0, ..., "reporters": {} } }
```

`verified` lists the known reporters that mailed that day, and `unverified`
is always there. The groups are never added together. Each group's entry
has:

| Field | Meaning |
|---|---|
| `reports`, `successful`, `failed` | reports read and their summed `total-successful-session-count` / `total-failure-session-count` |
| `policies` | the same sums per policy, e.g. `"sts cleanway.ai"` (the sender used our MTA-STS policy) or `"no-policy-found cleanway.ai"` (it did not see one). A `policy-type` outside RFC 8460 is `other`, and a `policy-domain` other than `cleanway.ai` is `other-domain` |
| `failures` | failed sessions per `result-type` and our MX host, e.g. `"certificate-host-mismatch route2.mx.cloudflare.net": 3`. A `result-type` outside RFC 8460 is `other`, a host not in `MX_HOSTS` is `other-host`, no host is `?` |
| `reporters` | `unverified` only: reports per domain of the mail's `From` header (`yahoo.com`, `sub.google.com`, ...). `unknown` when the header is not exactly one plain address |
| `covers` | the days the reports describe (usually yesterday) |
| `errors`, `error_kinds` | mails that were not a readable report: `no report in the mail`, `bad base64`, `bad gzip`, `bad JSON`, `not a TLS report`, `bad session count`, `report too large` (over 256 KB unzipped), `mail too large` (over 256 KB) |
| `errors_capped` | the group's junk budget for the day is spent (20 mails for `unverified`, 5 for each known reporter); later ones were not counted |
| `capped` | the group's report budget for the day is spent (100 reports for `unverified`, 20 for each known reporter); later ones were not counted, but can still send an alert |
| `alert` | when the group's alert was sent that day, or `null` (see Alert) |
| `alert_tries`, `alert_error` | sends the group's alert may use that day, at most 5 (an attempt reserves up to two: the send and one retry); when the last attempt sent nothing and why (the next failing report tries again) |

Lists keep at most 20 names, and the rest are counted as `other`. The report
itself is never stored or forwarded. Sender and receiver IPs, contact
addresses, policy strings and `failure-reason-code` are dropped as the report
is read (a reason that looks like a code, e.g. `X509_V_ERR_HOSTNAME_MISMATCH`,
goes into the alert mail only). A redelivered report counts once: today's
entry keeps a hash of each report's JSON. A mail that is not a readable
report is counted and then accepted and dropped, never rejected or thrown
back: a temporary failure would make the sender retry for days.

Reading one mail is bounded so it stays well inside the free plan's 10 ms of
CPU: at most 256 KB of mail, 30 MIME parts looked at (empty multipart ones
included), 10 candidate parts, and 256 KB unzipped for all of a mail's gzip
parts together (the first gzip bomb ends the reading). Base64 and
quoted-printable are decoded in one pass. Measured in Node 22 with warm code,
the worst crafted 256 KB mails cost about 4 ms and a real report under 1 ms;
the first mail after the Worker starts is slower. A mail that ran out of CPU
anyway would fail alone, before any KV write.

**Alert:** a mail from `alerts@cleanway.ai` to `ALERT_TO`, sent with the first
report of the UTC day that counts failed sessions, at most once a day per
group (`google.com`, `microsoft.com`, and all unverified reporters together),
so at most three a day. Subject: `Cleanway: сбои TLS при доставке почты на
cleanway.ai (<n>)`, or `(<n>, отправитель не проверен)` for an unverified
reporter. It gives the policy counts and up to 5 policies × 5 failure types
with our MX host, says whether the mode is `testing` (mail still arrives) or
`enforce` (that mail is not delivered), and links the summary page. Later
reports from that group that day only go to the summary.

Google mails one report a day, so a failure has to be retried within the
same delivery. The alert is recorded in KV before it is sent. KV allows one
write a second to a key, so a write that is refused is redone once 1.1 s
later on a fresh read (it keeps what another mail wrote in between). If that
fails too, nothing is sent and the error is logged. A send that fails is
retried once, 1.1 s later. If both fail, the record is undone and
`alert_error` says why, and the group's next failing report tries again, at
most 5 sends a day per group.

**Forged reports.** Anyone can mail `tls-reports@cleanway.ai`: the address is
public in the `_smtp._tls` record. What a forger can and cannot do:

- **Change Google's or Microsoft's counts: no.** A report is theirs only when
  the mail's `From` header is exactly `@google.com` or `@microsoft.com` (their
  reports come from `noreply-smtp-tls-reporting@google.com` and
  `tlsrpt-noreply@microsoft.com`). Both publish DMARC `p=reject`, and Email
  Routing rejects mail that fails the sender's DMARC policy, so mail `From`
  them is theirs. Their subdomains are not trusted: a subdomain can publish a
  weaker `_dmarc` record of its own. Each known reporter has its own KV key,
  report and junk budgets, dedup list and failure list. Forged mail never
  writes to that key, so it can neither fill those lists nor overwrite a
  report that arrives at the same moment.
- **Shadow a real report: no.** Reports are deduplicated by a hash of their
  JSON, not by `organization-name` and `report-id`, which anyone can copy
  (Google's id is predictable), and each group has its own list: a forged
  byte-for-byte copy sent first only lands in `unverified`.
- **Silence Google's or Microsoft's alert: no.** Each has its own daily alert
  and its own sends. Every other reporter, forged or not, shares the third
  one. Such an alert says in its subject and text that it may be forged and
  shows nothing the sender wrote. The sender's domain is in the summary under
  `unverified` → `reporters`.
- **Put words into the alert: no.** It repeats only values from closed sets
  (RFC 8460 `result-type` and `policy-type`, our MX hosts, `cleanway.ai`, ISO
  dates, numbers), a `failure-reason-code` only when it looks like a code (no
  spaces, no dots), and, for a known reporter, its plain company name.
  Invisible and bidi control characters are stripped.
- **Skew the unverified counts: yes.** Forged reports add to `unverified`,
  including failures. 20 junk mails or 100 reports end its counting for the
  day. Junk cannot use up the reports' budget, and a capped day still sends
  alerts. This is why the rollout and the rollback below look only at
  `verified`.

KV on the free plan allows 1,000 writes and 100,000 reads a day for the whole
account, shared with the uptime monitor (about 150 writes a day and a read
every minute). This Worker writes once per mail that changes something, plus
one write when an alert sent nothing and its record is undone. A day's limit
for `unverified` is 20 + 1 for junk, 100 + 1 for reports and 3 undone alerts;
for each known reporter 5 + 1, 20 + 1 and 3. That is at most about 190 writes
a day. It reads once per mail (twice when a write is redone) and three times
per view of the summary page. KV has no atomic update, and a read can be up
to 60 s stale at another location. Under concurrent delivery within one
group these daily limits (and the counts) are best effort. Mail of one group
never writes another group's key.

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

**State:** deployed 2026-10-23 in `testing` (KV namespace `cleanway-mail-security`,
custom domain `mta-sts.cleanway.ai`, Email Routing rule `tls-reports@` → this
Worker, `_mta-sts` id `2026102301`, `_smtp._tls` published). Review the
summaries and decide on `enforce` around 2026-11-06.

1. **Testing, about two weeks.** Senders fetch the policy and report on it,
   and nothing is enforced. A sender reports only for days it delivered mail
   to cleanway.ai. The domain receives little mail, so send a message from a
   Gmail and an Outlook account to `hello@cleanway.ai` a few times during the
   two weeks. Reports usually arrive the day after.
2. **Read the summaries** at `https://cleanway-mail-security.amoskotin.workers.dev/`,
   and only `verified`. Go ahead when `verified` has `google.com` on some
   days (and ideally `microsoft.com`), their `policies` show
   `sts cleanway.ai` (senders see the policy), and their `failed` stayed `0`.
   Ignore `unverified` for this decision: anyone can put numbers there.
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
4. **Rollback** (enforce is blocking real mail, as `verified` shows: see
   When the alert arrives): set `MTA_STS_MODE=testing`,
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
  `tls-reports@cleanway.ai`. Today's `unverified` then shows `"errors": 1`,
  `"error_kinds": {"no report in the mail": 1}` (`gmail.com` is not a known
  reporter). It was not a report, so it is dropped.
- **Online checkers:** https://aykevl.nl/apps/mta-sts/ checks the TXT record,
  the policy and the MX certificates. Hardenize (https://www.hardenize.com/)
  has MTA-STS and TLS-RPT sections.

## When the alert arrives

The mail's `result-type` says what failed. The first step for each:

| `result-type` | Meaning | First step |
|---|---|---|
| `certificate-host-mismatch`, `certificate-expired`, `certificate-not-trusted`, `starttls-not-supported` | the TLS of a Cloudflare MX host (named in the mail) as that sender saw it | https://www.cloudflarestatus.com/ (Email Routing). Repeated in `verified` (Google's or Microsoft's own reports) in `enforce`: roll back to `testing` (Rollout 4) |
| `validation-failure` | the sender's generic failure, often an MX host the policy does not list | compare the zone's MX records with `MX_HOSTS` (Rollout 5) |
| `sts-policy-fetch-error` | the sender could not fetch the policy | the `curl` above; Workers & Pages → `cleanway-mail-security` → the custom domain is still attached |
| `sts-webpki-invalid` | the certificate of `mta-sts.cleanway.ai` was not valid | the custom domain's certificate in Cloudflare |
| `sts-policy-invalid` | the policy text did not parse | should not happen (the tests pin it): compare `curl` with the policy above |

A few failures from one sender on one day in `testing` are usually that
sender's own TLS stack. Watch whether they come back. An alert from an
unverified reporter (the subject ends `отправитель не проверен`) may be
forged, and failures only in `unverified` never justify a rollback on their
own, however many senders they seem to come from. Look at `unverified` →
`reporters` in the summary. If it is a real mail provider that reports every
day, add the exact domain of its `From` to `KNOWN_REPORTERS`, but only if
`dig +short TXT _dmarc.<domain>` shows `p=reject` (and no `pct=` below 100),
and upload the Worker. Its next reports then count as verified.

Tests: `node --test ops/mail-security-worker/worker.test.mjs
ops/mail-security-worker/forged.test.mjs` (CI runs both through
`tests/test_mail_security_worker.py`).
