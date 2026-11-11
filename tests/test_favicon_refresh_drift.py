"""Guard: the favicon-refresh ops script must hash exactly like the runtime.

scripts/refresh_brand_favicons.py hardcodes HASH_HEX_LEN (rather than importing it
from api.services.favicon_hash) so the httpx-only CI cron stays dependency-free — the
import path drags in the redis/pydantic api chain and crashed the job for 4 weeks.
This test ensures the hardcoded literal never silently diverges from the runtime
constant (which would make the cron populate hashes the runtime can't recognise).
"""
import ast
import importlib.util
import pathlib
import re

import httpx
import pytest

from api.services import favicon_hash
from api.services.favicon_hash import HASH_HEX_LEN
from tests.test_favicon_hash import AKAMAI_DENIED, ICON_SAMPLES, NOT_ICONS

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "refresh_brand_favicons.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("refresh_brand_favicons", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_favicon_refresh_hash_len_matches_runtime():
    script = (
        pathlib.Path(__file__).resolve().parent.parent
        / "scripts"
        / "refresh_brand_favicons.py"
    )
    m = re.search(r"^HASH_HEX_LEN\s*=\s*(\d+)", script.read_text(), re.M)
    assert m, "HASH_HEX_LEN literal not found in scripts/refresh_brand_favicons.py"
    assert int(m.group(1)) == HASH_HEX_LEN, (
        f"scripts/refresh_brand_favicons.py HASH_HEX_LEN={m.group(1)} "
        f"!= runtime api.services.favicon_hash.HASH_HEX_LEN={HASH_HEX_LEN}"
    )


def test_favicon_refresh_image_check_matches_runtime():
    """The cron must skip exactly what the runtime refuses to hash, or it files
    hashes the runtime never produces (and vice versa)."""
    script = _load_script()
    assert script._RASTER_MAGIC == favicon_hash._RASTER_MAGIC
    for kind, body in {**ICON_SAMPLES, **NOT_ICONS}.items():
        assert script.looks_like_favicon(body) == favicon_hash.looks_like_favicon(body), kind


def _function_body(path: pathlib.Path, name: str) -> str:
    fn = next(n for n in ast.parse(path.read_text()).body
              if isinstance(n, ast.FunctionDef) and n.name == name)
    body = fn.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]  # the docstring may differ
    return ast.dump(ast.Module(body=body, type_ignores=[]))


def test_favicon_refresh_image_check_is_the_runtime_code():
    """Samples miss edits they do not exercise (2026-10-27: dropping the <html
    guard or shrinking the 1 KB window in the script alone kept the test above
    green), so the two definitions must also be the same code."""
    assert _function_body(SCRIPT, "looks_like_favicon") == _function_body(
        pathlib.Path(favicon_hash.__file__), "looks_like_favicon"
    )


@pytest.mark.asyncio
async def test_favicon_refresh_skips_bot_wall_page():
    """2026-10-25: GitHub's runners got Akamai's "Access Denied" page with 200 OK
    and the cron filed it as the UPS favicon."""
    script = _load_script()
    bodies = {"blocked.example": AKAMAI_DENIED, "ok.example": ICON_SAMPLES["png"]}

    def _handler(request):
        return httpx.Response(200, content=bodies[request.url.host])

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
        assert await script._fetch(client, "blocked.example") is None
        assert await script._fetch(client, "ok.example") == ICON_SAMPLES["png"]
