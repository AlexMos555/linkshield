"""A programmable stand-in for ``httpx.AsyncClient`` talking to Supabase.

Routes are matched by HTTP method + a substring of the URL (the most
recently added route wins), and answer with a REAL ``httpx.Response`` (some
handlers check ``isinstance(resp, httpx.Response)``) or raise an exception
(timeouts, connection errors). Every request is recorded so tests can
assert what was read or written — and that nothing was written at all.

    sb = FakeSupabase()
    monkeypatch.setattr(httpx, "AsyncClient", sb.client())
    sb.on("PATCH", "/rest/v1/users", status=409)
    sb.on("GET", "/rest/v1/devices", exc=httpx.ReadTimeout("slow"))
"""
from __future__ import annotations

from typing import Any, Optional

import httpx

_DEFAULT_STATUS = {"GET": 200, "POST": 201, "PATCH": 204, "DELETE": 204}


class FakeSupabase:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self._routes: list[tuple[str, str, int, Any, dict, Optional[BaseException]]] = []

    def on(
        self,
        method: str,
        needle: str,
        *,
        status: int = 200,
        body: Any = None,
        headers: Optional[dict] = None,
        exc: Optional[BaseException] = None,
    ) -> "FakeSupabase":
        self._routes.insert(0, (method.upper(), needle, status, body, headers or {}, exc))
        return self

    def to(self, method: str, needle: str) -> list[dict[str, Any]]:
        """Recorded calls with this method whose URL contains `needle`."""
        return [c for c in self.calls if c["method"] == method.upper() and needle in c["url"]]

    def writes(self) -> list[dict[str, Any]]:
        return [c for c in self.calls if c["method"] != "GET"]

    def _handle(self, method: str, url: str, params=None, json=None, headers=None) -> httpx.Response:
        method = method.upper()
        self.calls.append(
            {
                "method": method,
                "url": str(url),
                "params": dict(params or {}),
                "json": json,
                "headers": dict(headers or {}),
            }
        )
        for m, needle, status, body, hdrs, exc in self._routes:
            if m == method and needle in str(url):
                if exc is not None:
                    raise exc
                if body is None and status in (204, 304):
                    return httpx.Response(status, headers=hdrs)
                if isinstance(body, bytes):  # raw payload, e.g. a proxy's HTML error page
                    return httpx.Response(status, content=body, headers=hdrs)
                return httpx.Response(status, json=[] if body is None else body, headers=hdrs)
        status = _DEFAULT_STATUS.get(method, 200)
        return httpx.Response(status) if status == 204 else httpx.Response(status, json=[])

    def client(self):
        stub = self

        class _Client:
            def __init__(self, *_a, **_k) -> None:
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_a):
                return None

            async def request(self, method, url, *, params=None, json=None, headers=None, **_kw):
                return stub._handle(method, url, params, json, headers)

            async def get(self, url, **kw):
                return await self.request("GET", url, **kw)

            async def post(self, url, **kw):
                return await self.request("POST", url, **kw)

            async def patch(self, url, **kw):
                return await self.request("PATCH", url, **kw)

            async def delete(self, url, **kw):
                return await self.request("DELETE", url, **kw)

        return _Client
