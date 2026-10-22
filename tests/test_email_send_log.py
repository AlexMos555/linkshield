"""A failed Resend send says why in the production log (docs/runbooks/email.md).

Until 2026-10-22 Resend's answer was logged under `body`, a key the JSON
formatter never prints (DENIED_EXTRAS: `body` is message content elsewhere),
so `email.send.resend.error` showed a status code and nothing else. The
answer is Resend's own error object, not the mail: it goes under `error`,
scrubbed of addresses and credentials like every printed value.
"""
from __future__ import annotations

import asyncio
import json
import logging

from api.services import email as email_service
from api.services.logger import JsonFormatter

REJECTION = (
    '{"statusCode":422,"name":"validation_error",'
    '"message":"Invalid `to` field: someone@example.com is not a valid address"}'
)


class _Response:
    status_code = 422
    text = REJECTION


class _Client:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, *args, **kwargs):
        return _Response()


def _send() -> email_service.SendResult:
    provider = email_service.ResendProvider("re_test_key")
    return asyncio.run(provider.send(
        to="someone@example.com", from_addr="no-reply@cleanway.ai", from_name="Cleanway",
        subject="Your code", html="<p>hi</p>", text="hi", headers={},
    ))


def test_a_rejected_send_prints_resends_reason(monkeypatch, caplog):
    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    with caplog.at_level(logging.ERROR, logger="cleanway.email"):
        result = _send()
    assert not result.ok and result.error == "Resend 422"
    (record,) = [r for r in caplog.records if r.getMessage() == "email.send.resend.error"]
    line = json.loads(JsonFormatter().format(record))
    assert line["status"] == 422
    assert line["send_id"] == result.send_id
    assert "validation_error" in line["error"] and "Invalid `to` field" in line["error"]
    assert "someone@example.com" not in json.dumps(line)
    assert "body" not in line
