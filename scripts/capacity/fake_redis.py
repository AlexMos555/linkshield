"""Capacity test only (docs/runbooks/capacity.md) — a Redis stand-in for a
machine with neither redis-server nor Docker: fakeredis over TCP, seeded
in-process like `scripts/doh_loadtest.py seed --count N` (the blocklist set
and the v2 artifact the DoH gateway loads).

Needs `pip install "fakeredis[lua]==2.40.0"` in a throwaway environment — it
is not a project dependency. Much slower than Redis: fine for comparing a
change before/after on the same machine, not for absolute numbers.

  python scripts/capacity/fake_redis.py --port 16391 --count 650000

fakeredis' TCP handler writes replies to a non-blocking socket with one
plain write(), which truncates large replies (the ~5 MB artifact); here a
send loop waits for the socket to drain instead.
"""
from __future__ import annotations

import argparse
import base64
import select
import sys
from pathlib import Path

import fakeredis
from fakeredis import TcpFakeServer
from fakeredis._clients import _tcp_server

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from api.services.blocklist_artifact import (  # noqa: E402
    LIST_CANARY, REDIS_META_KEY, REDIS_TEXT_KEY, meta_for_v2, render_artifact_v2,
)
from doh_loadtest import blocked_name  # noqa: E402


def _write(self, value: bytes) -> None:
    sock = self.request_handler.connection
    view = memoryview(value)
    while view:
        try:
            view = view[sock.send(view):]
        except BlockingIOError:
            select.select([], [sock], [], 1.0)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=16391)
    ap.add_argument("--count", type=int, default=650_000)
    args = ap.parse_args()
    _tcp_server.Writer.write = _write
    server = TcpFakeServer(("127.0.0.1", args.port), server_type="redis")
    server.daemon_threads = True
    r = fakeredis.FakeRedis(server=server.fake_server, decode_responses=True)
    names = [blocked_name(i) for i in range(args.count)]
    for i in range(0, len(names), 20_000):
        r.sadd("dangerous_domains", *names[i:i + 20_000])
    r.sadd("dangerous_domains", LIST_CANARY)
    blob = render_artifact_v2(names)
    r.set(REDIS_TEXT_KEY, base64.b64encode(blob).decode("ascii"))
    r.hset(REDIS_META_KEY, mapping=meta_for_v2(blob))
    print(f"fake redis on 127.0.0.1:{args.port}: {r.scard('dangerous_domains')} names, "
          f"artifact {len(blob)} bytes", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
