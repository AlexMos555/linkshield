"""
HMAC keys no longer have to be the legacy Supabase JWT secret.

The unsubscribe-link signature and the audit-log IP hash used
SUPABASE_JWT_SECRET as their HMAC key. That secret is the project's legacy
HS256 JWT key, which is to be revoked in Supabase once nothing depends on it,
so each use reads a dedicated key first and falls back to the old one:

- UNSUBSCRIBE_HMAC_KEY signs new unsubscribe links; links minted earlier with
  the legacy secret keep verifying for their 90-day life;
- AUDIT_IP_HASH_KEY keys the audit-log IP hash.
"""
from __future__ import annotations

import base64
import hashlib
import hmac

from api.routers import email_unsubscribe as eu

LEGACY = "test-secret-for-development-only-not-for-production-use"
DEDICATED = "dedicated-unsubscribe-key-0123456789-abcdefghijklmnop"


def _signature(token: str) -> bytes:
    sig_b64 = token.split(".", 1)[1]
    return base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))


def _payload(token: str) -> bytes:
    p = token.split(".", 1)[0]
    return base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))


def test_unsubscribe_links_fall_back_to_the_legacy_secret(monkeypatch):
    monkeypatch.delenv("UNSUBSCRIBE_HMAC_KEY", raising=False)
    monkeypatch.setenv("SUPABASE_JWT_SECRET", LEGACY)
    token = eu.mint_token("user-1", "welcome")
    expected = hmac.new(LEGACY.encode(), _payload(token), hashlib.sha256).digest()
    assert _signature(token) == expected
    assert eu.verify_token(token) is not None


def test_unsubscribe_links_are_signed_with_the_dedicated_key(monkeypatch):
    monkeypatch.setenv("SUPABASE_JWT_SECRET", LEGACY)
    monkeypatch.setenv("UNSUBSCRIBE_HMAC_KEY", DEDICATED)
    token = eu.mint_token("user-1", "welcome")
    expected = hmac.new(DEDICATED.encode(), _payload(token), hashlib.sha256).digest()
    assert _signature(token) == expected
    assert eu.verify_token(token)["uid"] == "user-1"


def test_links_minted_before_the_switch_still_verify(monkeypatch):
    monkeypatch.setenv("SUPABASE_JWT_SECRET", LEGACY)
    monkeypatch.delenv("UNSUBSCRIBE_HMAC_KEY", raising=False)
    old_link = eu.mint_token("user-1", "weekly_report")

    monkeypatch.setenv("UNSUBSCRIBE_HMAC_KEY", DEDICATED)
    assert eu.verify_token(old_link)["template"] == "weekly_report"


def test_dedicated_key_alone_is_enough(monkeypatch):
    """After the legacy secret is gone from the env, links still work."""
    monkeypatch.setenv("SUPABASE_JWT_SECRET", "")
    monkeypatch.setenv("UNSUBSCRIBE_HMAC_KEY", DEDICATED)
    assert eu.verify_token(eu.mint_token("user-1", "welcome")) is not None


def test_a_link_signed_with_another_key_is_refused(monkeypatch):
    monkeypatch.setenv("SUPABASE_JWT_SECRET", LEGACY)
    monkeypatch.setenv("UNSUBSCRIBE_HMAC_KEY", "someone-elses-key-xxxxxxxxxxxxxxxxxxxxxxxx")
    forged = eu.mint_token("user-1", "welcome")
    monkeypatch.setenv("UNSUBSCRIBE_HMAC_KEY", DEDICATED)
    assert eu.verify_token(forged) is None


def test_audit_ip_hash_prefers_the_dedicated_key(monkeypatch):
    from api.config import get_settings
    from api.services.audit_log import _hash_ip

    settings = get_settings()
    monkeypatch.setattr(settings, "audit_ip_hash_key", "")
    legacy = hmac.new(settings.supabase_jwt_secret.encode(), b"203.0.113.7", hashlib.sha256).hexdigest()[:16]
    assert _hash_ip("203.0.113.7") == legacy

    monkeypatch.setattr(settings, "audit_ip_hash_key", "audit-ip-key-xyz")
    dedicated = hmac.new(b"audit-ip-key-xyz", b"203.0.113.7", hashlib.sha256).hexdigest()[:16]
    assert _hash_ip("203.0.113.7") == dedicated
