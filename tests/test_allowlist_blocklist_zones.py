"""The allowlist refuses every tenant zone the blocklist lists tenants under.

/public/check answers from the allowlist (step 2) before it looks the host up
in our own blocklist (step 3). build_blockset lists a tenant of a shared
suffix exactly, even when the zone's own name is a top-100k entry: its
tenant branch runs before the popular-registrable skip. So that order loses
no blocklist hit only while is_trusted_top_domain() refuses every tenant of
every scripts/blocklist_shared_zones.default_shared_suffixes() zone. The two
lists are kept by hand in different places (blocklist_shared_zones.
UNRANKED_SHARED_DOMAINS, scoring._ALLOWLIST_TENANT_ZONES …), and since
2026-10-27 the allowlist reaches compound-suffix entries, so a zone such as
<host>.co.kr added on the blocklist side alone would be answered 'safe'
first (final review of #353).
"""
from __future__ import annotations

import importlib.util
import pathlib

import pytest

from api.services.scoring import is_trusted_top_domain

_SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "blocklist_shared_zones.py"
_spec = importlib.util.spec_from_file_location("blocklist_shared_zones", _SCRIPT)
bsz = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bsz)  # type: ignore[union-attr]

_ZONES = sorted(bsz.default_shared_suffixes())


def test_the_zone_list_is_the_real_one():
    # 2,303 on 2026-10-27; a broken load would make the check below vacuous.
    assert len(_ZONES) > 2000


def test_no_tenant_of_a_blocklist_zone_is_trusted():
    trusted = [z for z in _ZONES if is_trusted_top_domain(f"zq7tenant.{z}")]
    assert trusted == []


@pytest.mark.parametrize("host", ["000webhost.com", "www.000webhost.com"])
def test_000webhost_itself_stays_trusted(host):
    assert is_trusted_top_domain(host) is True
