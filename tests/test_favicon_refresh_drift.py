"""Guard: the favicon-refresh ops script must hash exactly like the runtime.

scripts/refresh_brand_favicons.py hardcodes HASH_HEX_LEN (rather than importing it
from api.services.favicon_hash) so the httpx-only CI cron stays dependency-free — the
import path drags in the redis/pydantic api chain and crashed the job for 4 weeks.
This test ensures the hardcoded literal never silently diverges from the runtime
constant (which would make the cron populate hashes the runtime can't recognise).
"""
import pathlib
import re

from api.services.favicon_hash import HASH_HEX_LEN


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
