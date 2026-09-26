#!/usr/bin/env bash
# Put the published DNS blocklist into the APK as its starter ("seed") list.
#
# A fresh install used to block nothing until its first 2.6 MB download from
# our US server finished — the path most likely to be slow or cut from Russia.
# With a seed in the APK the phone blocks known scam sites from minute one
# (SeedBlocklist.kt); the first list it syncs replaces the seed.
#
# Run at RELEASE build time, in the build mirror, AFTER sync.sh (whose
# `rsync --delete` removes the file, since it is not in git):
#
#   bash ~/Library/Caches/cleanway-dev/cwmobile/scripts/fetch-seed-blocklist.sh
#   bash mobile/scripts/fetch-seed-blocklist.sh <assets-dir>     # explicit target
#
# The default target is this checkout's module assets, next to the script.
# The file is gitignored. A debug build without it works; a release build
# refuses to start (plugins/withSeedGuard.js) unless given -PcleanwayNoSeed.
#
# Nothing is installed unless the download verifies: HTTP 200, sha256 equal
# to the ETag, the v2 magic and header, count × 6 bytes, strictly ascending
# hashes, a plausible size and a recent publish. Env overrides:
#   CLEANWAY_BLOCKLIST_URL     default https://api.cleanway.ai/api/v1/blocklist/dns
#   CLEANWAY_SEED_MIN_COUNT    default 100000  (a list this small is a broken publish)
#   CLEANWAY_SEED_MAX_AGE_H    default 72      (do not ship a stale starter list)
set -euo pipefail

URL="${CLEANWAY_BLOCKLIST_URL:-https://api.cleanway.ai/api/v1/blocklist/dns}"
MIN_COUNT="${CLEANWAY_SEED_MIN_COUNT:-100000}"
MAX_AGE_H="${CLEANWAY_SEED_MAX_AGE_H:-72}"
NAME="dns-blocklist-v2.seed.bin"

here="$(cd "$(dirname "$0")" && pwd)"
dest_dir="${1:-$here/../modules/cleanway-vpn/android/src/main/assets}"
[ -d "$dest_dir" ] || { echo "no such assets dir: $dest_dir" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsS --compressed --max-time 180 \
  -H "Accept: application/octet-stream" -A "Cleanway-SeedBuild" \
  -D "$tmp/headers" -o "$tmp/body" "$URL"

python3 - "$tmp/body" "$tmp/headers" "$MIN_COUNT" "$MAX_AGE_H" <<'PY'
import hashlib, re, sys, time

body = open(sys.argv[1], "rb").read()
headers = open(sys.argv[2], "rb").read().decode("latin-1")
min_count, max_age_h = int(sys.argv[3]), int(sys.argv[4])

def fail(why):
    sys.exit(f"seed rejected: {why}")

status = re.findall(r"^HTTP/\S+ (\d{3})", headers, re.M)
if not status or status[-1] != "200":
    fail(f"HTTP status {status[-1] if status else '?'}")

magic = b"CWBL2\n"
if not body.startswith(magic):
    fail("bad magic (not a v2 artifact, or a delta)")
nl = body.find(b"\n", len(magic))
if nl < 0:
    fail("no header line")
m = re.fullmatch(rb"# cleanway-dns-blocklist v2 generated=(\d+) count=(\d+) status=(ok|revoked)", body[len(magic):nl])
if not m:
    fail("bad header")
generated, count, state = int(m.group(1)), int(m.group(2)), m.group(3).decode()
if state != "ok":
    fail("the published list is revoked")
entries = body[nl + 1:]
if len(entries) != count * 6:
    fail(f"body is {len(entries)} bytes, header says {count} × 6")
if count < min_count:
    fail(f"only {count} entries (< {min_count})")
prev = -1
for i in range(0, len(entries), 6):
    v = int.from_bytes(entries[i:i + 6], "big")
    if v <= prev:
        fail(f"hashes not strictly ascending at entry {i // 6}")
    prev = v
age_h = (time.time() - generated) / 3600
if age_h > max_age_h:
    fail(f"published {age_h:.0f} h ago (> {max_age_h} h)")

# The ETag is the published sha256 — the one check that ties these bytes to
# what the server published. No ETag, or one of another shape (an edge that
# rewrites it), means the download cannot be verified: fail closed.
etag = re.findall(r"^etag:\s*(.+?)\s*$", headers, re.M | re.I)
sha = hashlib.sha256(body).hexdigest()
if not etag:
    fail("no ETag header, so the sha256 cannot be checked")
want = etag[-1].removeprefix("W/").strip('"').lower()
if not re.fullmatch(r"[0-9a-f]{64}", want):
    fail(f"the ETag is not a sha256 ({etag[-1][:40]}), so the download cannot be checked")
if want != sha:
    fail("sha256 does not match the ETag")
print(f"ok: count={count} generated={generated} ({age_h:.1f} h ago) sha256={sha[:16]}…")
PY

install -m 0644 "$tmp/body" "$dest_dir/$NAME"
echo "seed installed: $dest_dir/$NAME ($(wc -c < "$dest_dir/$NAME" | tr -d ' ') bytes)"
