"""Names of the popularity lists that stopped existing: data/top_domains_dead.json.

On 2026-10-31, 1,129 of the 100,000 names of data/top_100k.json (and 26 of
data/top_domains_reported.json) no longer existed — NXDOMAIN at Cloudflare,
Google and the parent zone's own servers — and about 215 were registered to
nobody (RDAP 404): rank 105 (w2rt6byl5nf1opmc-a.com), postimg.org, ht.ly,
strana.ua, casino names and a ca33*/ca61*.shop/.top/.xyz/.de series.
Whoever registers one inherits what the lists give a name: the instant
'safe' allowlist, the popularity bonus, the DNS blocklist's never-block
guard, the phone's veto, OTX's waiver. A name is
NXDOMAIN for weeks between its expiry and the day anyone may buy it (the
registry's hold, redemption and pending-delete), so a weekly sweep
(scripts/refresh_dead_top_names.py, .github/workflows/refresh-dead-top-names.yml)
tombstones it before it can change hands.

Tombstones are sticky: a dead name that resolves again stays here, because
the one who brought it back may be anyone. The sweep lists such names for a
person to check; only a person removes one.

Applied where the lists are READ (scoring.top_domain_key, the OTX gate and the
ML safe override, tranco.get_tranco_rank, the publisher's guards, the phone's
veto), never by editing data/top_100k.json: the served model reads that file's
bytes as its in_top_domains feature (ml_features.resolve_feature_data).

Standard library only: the publisher and the asset builders import it on
runners without the API's dependencies.
"""

from __future__ import annotations

import json
import logging
import os

logger = logging.getLogger("cleanway.dead_top_names")

DEAD_FILE = "top_domains_dead.json"
# The rest of the top-1M ranking (ranks 100k-1M, scripts/refresh_tranco.py):
# a file of its own, swept with a cap of its own (refresh_dead_top_names.py
# --ranking). 2.46% of a 20,000-name sample of the band was dead on
# 2026-10-31 — about 22,000 names that kept a rank.
BAND_FILE = "top_1m_dead.json"
_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")


def load(path: str = os.path.join(_DATA_DIR, DEAD_FILE)) -> frozenset[str]:
    """The tombstoned names. Unreadable: none — every listed name keeps its
    trust, as before the file existed — and an error in the log."""
    try:
        with open(path, encoding="utf-8") as f:
            names = json.load(f)["names"]
        return frozenset(n.lower() for n in names)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        logger.error("%s not loaded (%s): dead popular names keep their trust", DEAD_FILE, exc)
        return frozenset()


DEAD_TOP_NAMES = load() | load(os.path.join(_DATA_DIR, BAND_FILE))
