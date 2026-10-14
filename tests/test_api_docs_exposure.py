"""Interactive API docs and the raw OpenAPI schema are off in production.

/docs, /redoc and /openapi.json hand an attacker a complete, current map of
every route and parameter. They stay on in development and staging (and CI's
openapi-drift job reads the schema from app.openapi(), never over HTTP).
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.main import api_docs_settings


def test_production_turns_every_docs_route_off():
    assert api_docs_settings("production") == {
        "docs_url": None,
        "redoc_url": None,
        "openapi_url": None,
    }


def test_development_and_staging_keep_fastapi_defaults():
    assert api_docs_settings("development") == {}
    assert api_docs_settings("staging") == {}


def test_a_production_app_serves_no_docs_but_still_builds_its_schema():
    app = FastAPI(**api_docs_settings("production"))

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    c = TestClient(app)
    for path in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"):
        assert c.get(path).status_code == 404, path
    # scripts/dump-openapi.py (CI openapi-drift) calls app.openapi() directly.
    assert "/ping" in app.openapi()["paths"]


def test_the_dev_app_still_serves_its_schema():
    from api.main import app

    c = TestClient(app)
    assert c.get("/openapi.json").status_code == 200
    assert c.get("/").json()["docs"] == "/docs"
