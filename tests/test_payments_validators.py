"""Tests for CheckoutRequest URL validation (H-1: open redirect via Stripe)."""

import pytest
from pydantic import ValidationError

from api.routers.payments import CheckoutRequest


class TestCheckoutRequestRedirectValidation:
    def test_defaults_accepted(self):
        req = CheckoutRequest(plan="personal_monthly")
        assert req.success_url.startswith("https://cleanway.ai/")
        assert req.cancel_url.startswith("https://cleanway.ai/")

    def test_cleanway_apex_accepted(self):
        req = CheckoutRequest(
            plan="personal_monthly",
            success_url="https://cleanway.ai/thanks",
            cancel_url="https://cleanway.ai/cancel",
        )
        assert req.success_url == "https://cleanway.ai/thanks"

    def test_cleanway_www_accepted(self):
        req = CheckoutRequest(
            plan="personal_monthly",
            success_url="https://www.cleanway.ai/ok",
            cancel_url="https://www.cleanway.ai/no",
        )
        assert req.cancel_url == "https://www.cleanway.ai/no"

    @pytest.mark.parametrize(
        "bad_url",
        [
            "https://evil.com/phish",
            "http://cleanway.ai/x",  # no https
            "https://cleanway.ai.evil.com/",  # subdomain trick
            "https://evil.com/?redir=cleanway.ai",
            "javascript:alert(1)",
            "//cleanway.ai/",
            # ── Regression cases below (open-redirect attacker payloads). ─
            # If any of these ever start passing validation, a Stripe
            # checkout would forward the user to attacker-controlled JS /
            # domain after payment, with all the nasty implications: session
            # token leak via Referer, phishing prompt to "re-enter card",
            # XSS into our own domain via JS-scheme.
            #
            # Userinfo spoof — RFC 3986 lets `user@host` syntax inside URL,
            # so this navigates to evil.com with `cleanway.ai` as the
            # ignored userinfo segment. Coversprefix-match attack.
            "https://cleanway.ai@evil.com/",
            "https://cleanway.ai:password@evil.com/path",
            # Backslash-as-separator — older URL parsers (some browser
            # legacy modes) treat `\\` like `/`, so the effective host
            # flips. We must reject before letting Stripe forward it.
            "https://cleanway.ai\\@evil.com/",
            "https://cleanway.ai\\.evil.com/",
            # Uppercase scheme — startswith() is case-sensitive today,
            # but somebody might "fix" the validator with .lower() and
            # accidentally widen it. Pin the current behavior.
            "HTTPS://cleanway.ai/x",
            "Https://cleanway.ai/x",
            # Bare host with no path slash — must require trailing /.
            "https://cleanway.ai",
            # Leading whitespace — paste from Slack frequently has these.
            " https://cleanway.ai/x",
            "\thttps://cleanway.ai/x",
            # Punycode / homograph — diacritic 'á' ≠ ASCII 'a' on the wire.
            "https://cleanwáy.ai/x",
            "https://xn--cleanwy-2va.ai/x",  # punycode-like host
            # Embedded CR/LF for header injection downstream.
            "https://cleanway.ai/\r\nLocation: evil.com/",
            # Protocol-less or wrong-scheme.
            "cleanway.ai/x",
            "ftp://cleanway.ai/x",
            "data:text/html,<script>alert(1)</script>",
        ],
    )
    def test_off_domain_rejected(self, bad_url: str):
        with pytest.raises(ValidationError):
            CheckoutRequest(plan="personal_monthly", success_url=bad_url)

        with pytest.raises(ValidationError):
            CheckoutRequest(plan="personal_monthly", cancel_url=bad_url)

    def test_long_path_query_accepted(self):
        """Real-world success URLs carry session_id + utm query params."""
        url = "https://cleanway.ai/success/deep/path?session_id={CHECKOUT_SESSION_ID}&utm=stripe"
        req = CheckoutRequest(plan="personal_monthly", success_url=url)
        assert req.success_url == url

    def test_max_length_enforced(self):
        """Defense against mega-URL DoS through Stripe — 2KB cap."""
        too_long = "https://cleanway.ai/" + ("x" * 2050)
        with pytest.raises(ValidationError):
            CheckoutRequest(plan="personal_monthly", success_url=too_long)
        # Just under the cap is fine.
        ok = "https://cleanway.ai/" + ("x" * 2000)
        req = CheckoutRequest(plan="personal_monthly", success_url=ok)
        assert req.success_url == ok

    def test_both_urls_validated_independently(self):
        """A request with one bad URL must reject even if the other is valid."""
        # success OK, cancel evil
        with pytest.raises(ValidationError):
            CheckoutRequest(
                plan="personal_monthly",
                success_url="https://cleanway.ai/ok",
                cancel_url="https://evil.com/bad",
            )
        # cancel OK, success evil
        with pytest.raises(ValidationError):
            CheckoutRequest(
                plan="personal_monthly",
                success_url="https://evil.com/bad",
                cancel_url="https://cleanway.ai/ok",
            )
