"""Local load test for the DoH gateway (api/routers/doh.py).

Three pieces, each a subcommand, so the gateway under test is the real
`uvicorn api.main:app` process and nothing is mocked inside it:

  upstream  a fake RFC 8484 upstream (echoes the question, one A/AAAA answer
            with TTL 300, OPT echoed when the query had one), with an optional
            artificial delay standing in for the round trip to Cloudflare.
  seed      fills a local Redis the way scripts/refresh_dangerous_domains.py
            does: the `dangerous_domains` set AND the v2 hash artifact + meta.
  run       N worker processes x C concurrent keep-alive clients replay a
            realistic query mix for D seconds and print p50/p95/p99 + req/s.

Query mix (roughly what one phone's resolver sends): popular names drawn
Zipf-like from data/top_10k.json (so most names repeat — browsers and apps ask
for the same few hundred names all day), A/AAAA/HTTPS in the 45/45/10 split
iOS produces, 2% names that are on the blocklist, 3% never-seen random names,
20% GET / 80% POST, half the queries carrying EDNS0 with RFC 8467 padding.

Typical session (see docs/runbooks/doh-gateway.md "Load testing"):

  redis-server --port 6390 --save '' &
  python scripts/doh_loadtest.py upstream --port 8053 --delay-ms 15 &
  REDIS_URL=redis://127.0.0.1:6390 python scripts/doh_loadtest.py seed
  REDIS_URL=redis://127.0.0.1:6390 DOH_UPSTREAMS=http://127.0.0.1:8053/dns-query \\
      python -m uvicorn api.main:app --port 8000 --no-access-log &
  python scripts/doh_loadtest.py run --url http://127.0.0.1:8000/dns-query \\
      --procs 3 --concurrency 16 --seconds 20
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import multiprocessing as mp
import os
import random
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEED_BLOCKED = 430_000  # ~ the size of the live dangerous_domains set


def blocked_name(i: int) -> str:
    return f"login-{i}.phish{i % 997}.top"


# ── wire helpers ────────────────────────────────────────────────────

def build_query(name: str, qtype: int, edns: bool, txid: int) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 1 if edns else 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    q += struct.pack("!HH", qtype, 1)
    msg = header + q
    if edns:
        # OPT RR with an RFC 7830 padding option to a 128-byte block (RFC 8467).
        base = len(msg) + 11 + 4
        pad = (-base) % 128
        opt_rdata = struct.pack("!HH", 12, pad) + b"\x00" * pad
        msg += b"\x00" + struct.pack("!HHIH", 41, 1232, 0, len(opt_rdata)) + opt_rdata
    return msg


def _question_end(wire: bytes) -> int:
    pos = 12
    while pos < len(wire) and wire[pos]:
        pos += wire[pos] + 1
    return pos + 5


def fake_answer(wire: bytes) -> bytes:
    qend = _question_end(wire)
    qtype = struct.unpack("!H", wire[qend - 4:qend - 2])[0]
    edns = struct.unpack("!H", wire[10:12])[0] > 0
    if qtype == 28:
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 300, 16) + bytes(15) + b"\x01"
    elif qtype == 1:
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([192, 0, 2, 1])
    else:
        rr = b""
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0) if edns else b""
    header = wire[:2] + b"\x81\x80" + struct.pack("!HHHH", 1, 1 if rr else 0, 0, 1 if edns else 0)
    return header + wire[12:qend] + rr + opt


# ── upstream ────────────────────────────────────────────────────────

def make_upstream_app(delay_ms: float):
    async def app(scope, receive, send):
        if scope["type"] != "http":
            return
        body = b""
        if scope["method"] == "POST":
            while True:
                msg = await receive()
                body += msg.get("body", b"")
                if not msg.get("more_body"):
                    break
        else:
            qs = dict(p.split("=", 1) for p in scope["query_string"].decode().split("&") if "=" in p)
            raw = qs.get("dns", "")
            body = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        if delay_ms:
            await asyncio.sleep(delay_ms / 1000)
        out = fake_answer(body)
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/dns-message"),
                                (b"content-length", str(len(out)).encode())]})
        await send({"type": "http.response.body", "body": out})
    return app


def cmd_upstream(args) -> None:
    import uvicorn
    uvicorn.run(make_upstream_app(args.delay_ms), host="127.0.0.1", port=args.port,
                log_level="warning", access_log=False)


# ── seed ────────────────────────────────────────────────────────────

async def _seed(n: int) -> None:
    import redis.asyncio as redis
    sys.path.insert(0, str(ROOT))
    from api.services.blocklist_artifact import (LIST_CANARY, REDIS_META_KEY, REDIS_TEXT_KEY,
                                                 meta_for_v2, render_artifact_v2)
    r = redis.from_url(os.environ.get("REDIS_URL", "redis://127.0.0.1:6390"), decode_responses=True)
    names = [blocked_name(i) for i in range(n)]
    await r.delete("dangerous_domains")
    for i in range(0, n, 20_000):
        await r.sadd("dangerous_domains", *names[i:i + 20_000])
    await r.sadd("dangerous_domains", LIST_CANARY)
    blob = render_artifact_v2(names)
    meta = meta_for_v2(blob)
    pipe = r.pipeline(transaction=True)
    pipe.set(REDIS_TEXT_KEY, base64.b64encode(blob).decode("ascii"))
    pipe.delete(REDIS_META_KEY)
    pipe.hset(REDIS_META_KEY, mapping=meta)
    await pipe.execute()
    print(f"seeded {await r.scard('dangerous_domains')} names, artifact {len(blob)} bytes, "
          f"version {meta['version']}")
    await r.aclose()


def cmd_seed(args) -> None:
    asyncio.run(_seed(args.count))


# ── run ─────────────────────────────────────────────────────────────

def _popular() -> list[str]:
    ranks = json.loads((ROOT / "data" / "top_10k.json").read_text())
    return [d for d, _ in sorted(ranks.items(), key=lambda kv: kv[1])][:5000]


def _pick(rng: random.Random, popular: list[str], cum: list[float]) -> tuple[str, int]:
    roll = rng.random()
    if roll < 0.02:
        name = blocked_name(rng.randrange(SEED_BLOCKED))
    elif roll < 0.05:
        name = f"r{rng.getrandbits(40):x}.example.net"
    else:
        name = rng.choices(popular, cum_weights=cum)[0]
        if rng.random() < 0.3:
            name = "www." + name
    t = rng.random()
    qtype = 1 if t < 0.45 else 28 if t < 0.90 else 65
    return name, qtype


async def _client_loop(url: str, deadline: float, seed: int, out: list, errors: list) -> None:
    import httpx
    rng = random.Random(seed)
    popular = _popular()
    weights = [1 / (i + 1) for i in range(len(popular))]
    cum, acc = [], 0.0
    for w in weights:
        acc += w
        cum.append(acc)
    async with httpx.AsyncClient(timeout=10, limits=httpx.Limits(max_connections=1)) as c:
        while time.perf_counter() < deadline:
            name, qtype = _pick(rng, popular, cum)
            wire = build_query(name, qtype, rng.random() < 0.5, rng.getrandbits(16))
            t0 = time.perf_counter()
            try:
                if rng.random() < 0.2:
                    enc = base64.urlsafe_b64encode(wire).decode().rstrip("=")
                    resp = await c.get(url, params={"dns": enc},
                                       headers={"accept": "application/dns-message"})
                else:
                    resp = await c.post(url, content=wire,
                                        headers={"content-type": "application/dns-message",
                                                 "accept": "application/dns-message"})
                ok = resp.status_code == 200 and resp.content[:2] == wire[:2]
            except Exception:  # noqa: BLE001 — counted, not raised
                ok = False
            dt = time.perf_counter() - t0
            if ok:
                out.append(dt)
            else:
                errors.append(dt)


def _proc(url: str, concurrency: int, seconds: float, seed: int, q) -> None:
    async def main():
        out: list = []
        errors: list = []
        deadline = time.perf_counter() + seconds
        await asyncio.gather(*(_client_loop(url, deadline, seed * 1000 + i, out, errors)
                               for i in range(concurrency)))
        return out, errors
    out, errors = asyncio.run(main())
    q.put((out, len(errors)))


def _pct(sorted_vals: list[float], p: float) -> float:
    return sorted_vals[min(len(sorted_vals) - 1, int(p / 100 * len(sorted_vals)))] * 1000


def cmd_run(args) -> None:
    q: mp.Queue = mp.Queue()
    ps = [mp.Process(target=_proc, args=(args.url, args.concurrency, args.seconds, i + 1, q))
          for i in range(args.procs)]
    for p in ps:
        p.start()
    lat: list[float] = []
    errs = 0
    for _ in ps:
        out, e = q.get()
        lat.extend(out)
        errs += e
    for p in ps:
        p.join()
    lat.sort()
    if not lat:
        print("no successful requests")
        return
    print(json.dumps({
        "clients": args.procs * args.concurrency,
        "seconds": args.seconds,
        "ok": len(lat),
        "errors": errs,
        "rps": round(len(lat) / args.seconds, 1),
        "p50_ms": round(_pct(lat, 50), 2),
        "p95_ms": round(_pct(lat, 95), 2),
        "p99_ms": round(_pct(lat, 99), 2),
    }))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    up = sub.add_parser("upstream")
    up.add_argument("--port", type=int, default=8053)
    up.add_argument("--delay-ms", type=float, default=15.0)
    sd = sub.add_parser("seed")
    sd.add_argument("--count", type=int, default=SEED_BLOCKED)
    rn = sub.add_parser("run")
    rn.add_argument("--url", default="http://127.0.0.1:8000/dns-query")
    rn.add_argument("--procs", type=int, default=3)
    rn.add_argument("--concurrency", type=int, default=16)
    rn.add_argument("--seconds", type=float, default=20)
    args = ap.parse_args()
    {"upstream": cmd_upstream, "seed": cmd_seed, "run": cmd_run}[args.cmd](args)


if __name__ == "__main__":
    main()
