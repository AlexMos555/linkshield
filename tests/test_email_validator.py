"""Tests for the disposable-email blocklist + the /api/v1/auth/check-email
endpoint that gates signup.

We deliberately don't snapshot the entire vendored 5400-domain list —
that file is sourced from
github.com/disposable-email-domains/disposable-email-domains and may
get updated. Tests pin a curated handful of well-known disposables
that have been on the list for years (mailinator, 10minutemail,
guerrilla, tempmail) plus normal domains (gmail, outlook, our own
cleanway.ai) that must never end up there.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.services.email_validator import (
    disposable_blocklist_size,
    is_disposable_email,
)


@pytest.fixture
def client():
    from api.main import app
    return TestClient(app)


# ─── Helper unit tests ────────────────────────────────────────────


@pytest.mark.parametrize(
    "addr",
    [
        # All five confirmed in the vendored list at commit time.
        "user@mailinator.com",
        "test@10minutemail.com",
        "throwaway@guerrillamail.com",
        "x@tempmail.de",
        "abuse@easytrashmail.com",
        # case insensitivity
        "USER@MAILINATOR.COM",
        "Mixed@Mailinator.Com",
    ],
)
def test_known_disposable_blocked(addr: str):
    assert is_disposable_email(addr) is True


@pytest.mark.parametrize(
    "addr",
    [
        "alice@gmail.com",
        "bob@outlook.com",
        "x@protonmail.com",
        "support@cleanway.ai",
        # Case where the local part contains "mailinator" but the
        # domain is fine — we lookup ONLY by domain.
        "i-love-mailinator@gmail.com",
    ],
)
def test_legit_domains_pass(addr: str):
    assert is_disposable_email(addr) is False


@pytest.mark.parametrize(
    "bad",
    [
        "",
        None,
        "no-at-sign",
        "@nodomain",
        "double@@at",
    ],
)
def test_malformed_input_returns_false(bad):
    """Validation of email shape isn't this helper's job — empty /
    malformed inputs return False so callers (e.g. FastAPI EmailStr
    validation upstream) can decide."""
    assert is_disposable_email(bad) is False  # type: ignore[arg-type]


def test_blocklist_loaded_with_thousands_of_entries():
    """Smoke test: if the data file is missing or empty, the protection
    is silently inactive — that's a regression we want to catch."""
    n = disposable_blocklist_size()
    # Upstream list has ~5400 entries. If we ever drop below 1000 the
    # vendoring/refresh process is probably broken.
    assert n > 1000, f"blocklist suspiciously small: {n} entries"


# ─── Endpoint integration tests ──────────────────────────────────


def test_check_email_endpoint_flags_disposable(client):
    resp = client.post(
        "/api/v1/auth/check-email",
        json={"email": "user@mailinator.com"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["disposable"] is True
    assert body["domain"] == "mailinator.com"


def test_check_email_endpoint_passes_real_email(client):
    resp = client.post(
        "/api/v1/auth/check-email",
        json={"email": "alice@gmail.com"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["disposable"] is False
    assert body["domain"] == "gmail.com"


def test_check_email_endpoint_rejects_invalid_format(client):
    """Pydantic's EmailStr should refuse before our handler runs."""
    resp = client.post(
        "/api/v1/auth/check-email",
        json={"email": "not-an-email"},
    )
    assert resp.status_code == 422


def test_check_email_endpoint_normalises_case(client):
    """Lookup is case-insensitive — uppercase domain still flagged."""
    resp = client.post(
        "/api/v1/auth/check-email",
        json={"email": "X@MAILINATOR.COM"},
    )
    assert resp.status_code == 200
    assert resp.json()["disposable"] is True
