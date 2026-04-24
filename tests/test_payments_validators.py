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
        ],
    )
    def test_off_domain_rejected(self, bad_url: str):
        with pytest.raises(ValidationError):
            CheckoutRequest(plan="personal_monthly", success_url=bad_url)

        with pytest.raises(ValidationError):
            CheckoutRequest(plan="personal_monthly", cancel_url=bad_url)
