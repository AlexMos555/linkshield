"""Capacity test only (docs/runbooks/capacity.md) — an open-loop load
generator for when Docker / k6 is not at hand. Never point it at production.

The same request mixes as k6_doh.js and k6_public.js, at a constant arrival
rate: a request is sent on schedule whether or not the earlier ones have been
answered (k6's constant-arrival-rate), each on a keep-alive connection of its
own, so an overloaded server shows up as latency and errors instead of
slowing the generator down. Latency counts from the SCHEDULED send time.
With no free connection left (--max-conns per process) a request is dropped,
like k6's dropped_iterations. --preconnect opens connections before the
clock starts: a burst of new ones overflows the server's accept queue (128 on
macOS) and the SYN retries would be measured as server latency — run the
server with a keep-alive longer than the test (uvicorn --timeout-keep-alive).

  python scripts/capacity/loadgen.py --url http://127.0.0.1:8080 --mode doh \\
      --rate 3000 --duration 30 --procs 2 --rss-pid <uvicorn master pid>

MODE: doh (k6_doh.js mix, GET) | doh-cached (the top 50 names only: once warm,
the gateway answers them from its cache, no upstream in the way) | hit | miss |
allow | health (k6_public.js).
Prints one JSON line: sent, dropped, status counts, p50/p95/p99 of the 200s
and of every answered request, peak RSS of --rss-pid and its children.
Standard library only.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import itertools
import json
import multiprocessing as mp
import random
import resource
import subprocess
import sys
import threading
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from doh_loadtest import build_query  # noqa: E402

TICK_S = 0.002


def _popular() -> list[str]:
    ranks = json.loads((ROOT / "data" / "top_10k.json").read_text())
    return sorted(ranks, key=ranks.get)[:5000]


def make_paths(mode: str, rng: random.Random):
    popular = _popular()
    if mode in ("doh", "doh-cached"):
        cum = list(itertools.accumulate(1 / (i + 1) for i in range(len(popular))))

        def name() -> str:
            if mode == "doh-cached":  # names the gateway's cache already holds
                return rng.choice(popular[:50])
            roll = rng.random()
            if roll < 0.02:
                i = rng.randrange(650_000)
                return f"login-{i}.phish{i % 997}.top"
            if roll < 0.12:
                return f"r{rng.getrandbits(48):x}.example.net"
            n = rng.choices(popular, cum_weights=cum)[0]
            return "www." + n if rng.random() < 0.3 else n

        def doh() -> str:
            t = rng.random()
            qtype = 1 if t < 0.45 else 28 if t < 0.9 else 65
            wire = build_query(name(), qtype, rng.random() < 0.5, rng.getrandbits(16))
            return "/dns-query?dns=" + base64.urlsafe_b64encode(wire).decode().rstrip("=")
        return doh
    if mode == "health":
        return lambda: "/health"
    if mode == "allow":
        return lambda: f"/api/v1/public/check/{rng.choice(popular[:500])}"
    if mode == "hit":
        return lambda: f"/api/v1/public/check/shop{rng.randrange(500)}.capstore.com"
    if mode == "miss":
        return lambda: f"/api/v1/public/check/m{rng.getrandbits(48):x}.capstore.com"
    raise SystemExit(f"unknown mode {mode}")


async def _one(host: str, port: int, path: str, idle: list, timeout: float) -> int:
    """One GET; the status, 0 on a timeout, -1 on a connection error."""
    conn = idle.pop() if idle else None
    writer = None
    try:
        async def go() -> int:
            nonlocal writer, conn
            while True:
                if conn is None:
                    reader, writer = await asyncio.open_connection(host, port)
                else:
                    reader, writer = conn
                writer.write(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\n\r\n".encode())
                try:
                    head = await reader.readuntil(b"\r\n\r\n")
                    break
                except (asyncio.IncompleteReadError, ConnectionError):
                    if conn is None:
                        raise
                    writer.close()  # an idle keep-alive connection the server closed: once more
                    conn = None
            status, length, close = int(head[9:12]), 0, False
            for line in head.split(b"\r\n")[1:]:
                key, _, value = line.partition(b":")
                key = key.strip().lower()
                if key == b"content-length":
                    length = int(value)
                elif key == b"connection" and value.strip().lower() == b"close":
                    close = True
            if length:
                await reader.readexactly(length)
            if close:
                writer.close()
            else:
                idle.append((reader, writer))
            return status
        return await asyncio.wait_for(go(), timeout)
    except asyncio.TimeoutError:
        if writer is not None:
            writer.close()
        return 0
    except Exception:  # noqa: BLE001 — counted, never raised
        if writer is not None:
            writer.close()
        return -1


async def _run(url: str, mode: str, rate: float, duration: float, timeout: float,
               max_conns: int, seed: int, preconnect: int = 0) -> dict:
    parts = urlsplit(url)
    host, port = parts.hostname or "127.0.0.1", parts.port or 80
    next_path = make_paths(mode, random.Random(seed))
    idle: list = []
    busy = 0
    statuses: Counter = Counter()
    ok_ms: list[float] = []
    all_ms: list[float] = []
    dropped = 0
    tasks: set = set()
    loop = asyncio.get_running_loop()
    # Connections opened before the clock starts: a burst of new connections
    # overflows the server's accept queue (128 on macOS), and the SYN retries
    # (1 s, 3 s …) would be measured as server latency.
    for i in range(0, preconnect, 100):
        opened = await asyncio.gather(*(asyncio.open_connection(host, port)
                                        for _ in range(min(100, preconnect - i))), return_exceptions=True)
        idle.extend(c for c in opened if not isinstance(c, BaseException))

    async def fire(scheduled: float, path: str) -> None:
        nonlocal busy
        busy += 1
        try:
            status = await _one(host, port, path, idle, timeout)
        finally:
            busy -= 1
        statuses[status] += 1
        if status > 0:
            ms = (loop.time() - scheduled) * 1000
            all_ms.append(ms)
            if status == 200:
                ok_ms.append(ms)

    start = loop.time()
    sent = 0
    total = int(rate * duration)
    while sent < total:
        now = loop.time()
        due = min(total, int((now - start) * rate) + 1)
        while sent < due:
            scheduled = start + sent / rate
            sent += 1
            if busy >= max_conns:
                dropped += 1
                continue
            task = asyncio.ensure_future(fire(scheduled, next_path()))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
        await asyncio.sleep(TICK_S)
    if tasks:
        await asyncio.wait(tasks, timeout=timeout + 1)
    for _, writer in idle:
        writer.close()
    return {"sent": sent, "dropped": dropped, "statuses": dict(statuses), "ok_ms": ok_ms, "all_ms": all_ms}


def _proc(args, index: int, queue) -> None:
    try:
        import uvloop  # optional: ~2x the requests per generator process
        uvloop.install()
    except ImportError:
        pass
    queue.put(asyncio.run(_run(args.url, args.mode, args.rate / args.procs, args.duration,
                               args.timeout, args.max_conns, args.seed + index, args.preconnect // args.procs)))


def _pct(values: list[float], p: float):
    if not values:
        return None
    values = sorted(values)
    return round(values[min(len(values) - 1, int(p / 100 * len(values)))], 1)


class RssSampler(threading.Thread):
    """Peak resident memory of a process and its children, via ps."""

    def __init__(self, pid: int) -> None:
        super().__init__(daemon=True)
        self.pid, self.peak_kb, self.peak_one_kb, self.stop = pid, 0, 0, threading.Event()

    def run(self) -> None:
        while not self.stop.is_set():
            kids = subprocess.run(["pgrep", "-P", str(self.pid)], capture_output=True, text=True).stdout.split()
            out = subprocess.run(["ps", "-o", "rss=", "-p", ",".join([str(self.pid), *kids])],
                                 capture_output=True, text=True).stdout.split()
            sizes = [int(x) for x in out if x.isdigit()]
            if sizes:
                self.peak_kb = max(self.peak_kb, sum(sizes))
                self.peak_one_kb = max(self.peak_one_kb, max(sizes))
            self.stop.wait(0.5)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--mode", default="doh", choices=["doh", "doh-cached", "hit", "miss", "allow", "health"])
    ap.add_argument("--rate", type=float, default=500, help="requests per second, all processes together")
    ap.add_argument("--duration", type=float, default=30)
    ap.add_argument("--procs", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=10)
    ap.add_argument("--max-conns", type=int, default=3000, help="per process")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--preconnect", type=int, default=0,
                    help="keep-alive connections to open before the clock starts (all processes)")
    ap.add_argument("--rss-pid", type=int, default=0, help="sample this process + its children")
    args = ap.parse_args()
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = args.max_conns + 256
    if soft < want:
        resource.setrlimit(resource.RLIMIT_NOFILE, (want if hard == resource.RLIM_INFINITY else min(want, hard), hard))

    sampler = RssSampler(args.rss_pid) if args.rss_pid else None
    if sampler:
        sampler.start()
    queue: mp.Queue = mp.Queue()
    procs = [mp.Process(target=_proc, args=(args, i, queue)) for i in range(args.procs)]
    for p in procs:
        p.start()
    parts = [queue.get() for _ in procs]
    for p in procs:
        p.join()
    if sampler:
        sampler.stop.set()
        sampler.join()
    ok = [x for part in parts for x in part["ok_ms"]]
    answered = [x for part in parts for x in part["all_ms"]]
    statuses: Counter = Counter()
    for part in parts:
        statuses.update(part["statuses"])
    print(json.dumps({
        "mode": args.mode, "rate": args.rate, "duration": args.duration,
        "sent": sum(p["sent"] for p in parts), "dropped": sum(p["dropped"] for p in parts),
        "statuses": {str(k): v for k, v in sorted(statuses.items())},
        "ok_rps": round(len(ok) / args.duration, 1),
        "ok_p50_ms": _pct(ok, 50), "ok_p95_ms": _pct(ok, 95), "ok_p99_ms": _pct(ok, 99),
        "all_p50_ms": _pct(answered, 50), "all_p95_ms": _pct(answered, 95),
        "rss_peak_mb": round(sampler.peak_kb / 1024) if sampler else None,
        "rss_peak_worker_mb": round(sampler.peak_one_kb / 1024) if sampler else None,
    }))


if __name__ == "__main__":
    main()
