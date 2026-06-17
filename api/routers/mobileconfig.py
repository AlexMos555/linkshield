"""iOS Configuration Profile download — Strategy doc Top-20 #6.

  GET /api/v1/mobileconfig?locale=ru
    Response: application/x-apple-aspen-config attachment

iOS recognises the response mime-type and shows the standard
"Install Profile?" sheet. The user taps Allow, then has to
confirm in Settings → General → VPN & Device Management.

Privacy: no user identity in the request, no tracking parameter
in the generated profile. UUIDs are fresh per-download so two
users can both install without collision in iOS's profile list.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query, Response

from api.services.mobileconfig import build_profile, _PROFILE_STRINGS
from api.services.rate_limiter import rate_limit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["mobileconfig"])


@router.get(
    "/mobileconfig",
    dependencies=[Depends(rate_limit(mode="ip", category="mobileconfig"))],
)
async def download_mobileconfig(
    locale: str = Query("en", min_length=2, max_length=5),
) -> Response:
    locale_key = (locale or "en").lower()
    if locale_key not in _PROFILE_STRINGS:
        locale_key = "en"

    xml = build_profile(locale=locale_key)
    return Response(
        content=xml,
        media_type="application/x-apple-aspen-config",
        headers={
            # `attachment` triggers the iOS install sheet rather than
            # rendering the XML inline in Safari.
            "Content-Disposition": "attachment; filename=cleanway-dns.mobileconfig",
            "Cache-Control": "no-store",
        },
    )
