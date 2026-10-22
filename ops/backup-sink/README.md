# Backup sink (Cloudflare Worker)

`worker.js` runs as the Worker `cleanway-backup-sink` in the founder's
Cloudflare account with one binding: `BACKUPS` → R2 bucket `cleanway-db-backups`
(location WEUR, lifecycle: delete after 35 days).

It accepts only `PUT /upload/db/<UTC timestamp>.dump.age` carrying a GitHub
Actions OIDC token whose `aud` is `cleanway-backup`, `repository` is
`AlexMos555/linkshield`, `ref` is `refs/heads/main` and `workflow_ref` is the
`db-backup.yml` workflow. Everything else gets 401/403/404. Objects are never
overwritten (409). Nothing here can read or list backups — downloading is done
in the Cloudflare dashboard (see docs/runbooks/restore.md). The uptime Worker
(`ops/uptime-worker`) may hold a binding to the same bucket to alert when the
newest backup is older than 30 h; it only lists names and upload times, and the
objects are age-encrypted anyway.

Redeploy: upload `worker.js` as an ES module with the binding above (created via
the Cloudflare API, no wrangler project).
