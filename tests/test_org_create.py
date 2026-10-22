"""POST /api/v1/org/create — Business plan only.

The handler's docstring said "Requires business tier" but nothing checked
it: any signed-in account could create an org and become its admin. (An
org admin also blocked the GDPR purge of their account until migration 026
— see tests/test_migration_026_orgs_admin_cascade.py.)
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier


@pytest.fixture
def as_user():
    from api.main import app
    from api.services.auth import get_current_user, get_current_user_including_deleted

    def _as(tier: UserTier) -> TestClient:
        user = AuthUser(id="11111111-1111-4111-8111-111111111111", email="a@example.com", tier=tier)
        # The rate limiter resolves the caller through the "including
        # deleted" variant; the route itself through get_current_user.
        app.dependency_overrides[get_current_user] = lambda: user
        app.dependency_overrides[get_current_user_including_deleted] = lambda: user
        return TestClient(app)

    yield _as
    app.dependency_overrides.clear()


@pytest.fixture
def sb(monkeypatch):
    import httpx

    from api import config
    from tests.supabase_rest_stub import FakeSupabase

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "fake-key", raising=False)
    stub = FakeSupabase()
    stub.on("POST", "/rest/v1/orgs", status=201, body=[{"id": "org-1", "name": "Acme"}])
    monkeypatch.setattr(httpx, "AsyncClient", stub.client())
    return stub


@pytest.mark.parametrize("tier", [UserTier.free, UserTier.personal, UserTier.family])
def test_org_create_needs_the_business_plan(as_user, sb, tier):
    resp = as_user(tier).post("/api/v1/org/create", json={"name": "Acme"})
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["code"] == "business_plan_required"
    assert sb.to("POST", "/rest/v1/orgs") == []


def test_business_account_creates_the_org(as_user, sb):
    resp = as_user(UserTier.business).post("/api/v1/org/create", json={"name": "Acme"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["org_id"] == "org-1"
    (insert,) = sb.to("POST", "/rest/v1/orgs")
    assert insert["json"] == {"name": "Acme", "admin_user_id": "11111111-1111-4111-8111-111111111111"}
