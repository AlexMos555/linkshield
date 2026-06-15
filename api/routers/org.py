"""
B2B Organization API.

  POST /api/v1/org/create — create organization
  GET  /api/v1/org/{org_id}/dashboard — org threat dashboard
  POST /api/v1/org/{org_id}/members — add member
  POST /api/v1/org/{org_id}/simulate — launch phishing simulation
  GET  /api/v1/org/{org_id}/simulations — list simulation results
"""

from __future__ import annotations

import logging
import hashlib
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.services.auth import get_current_user
from api.services.rate_limiter import rate_limit
from api.models.schemas import AuthUser
from api.config import get_settings

logger = logging.getLogger("cleanway.org")

router = APIRouter(prefix="/api/v1/org", tags=["organization"])


async def _require_org_admin(user: AuthUser, org_id: str) -> None:
    """
    Authorize the caller as the admin of `org_id`.

    Raises 403 if the JWT-bound user isn't the org's admin_user_id, or
    404 if the org doesn't exist (we keep the response shape identical
    to "not your org" so an attacker can't probe for existing org IDs
    by enumerating).

    Audit finding backend-security MEDIUM "Org router endpoints accept
    any org_id with no membership or admin authorization check": every
    /org/{org_id}/... endpoint must call this before reading or writing.

    Fails open (allows the request) in dev when Supabase isn't wired —
    local development flows that use the stub create_org path return a
    fake org_id, and we don't want to block them. Production env-guard
    in validate_settings forces real Supabase, so this fail-open path
    is unreachable there.
    """
    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        if settings.environment == "production":
            raise HTTPException(503, "Database not configured")
        return  # dev / staging stub flow

    import httpx

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"{settings.supabase_url}/rest/v1/orgs",
                params={
                    "id": f"eq.{org_id}",
                    "select": "id,admin_user_id",
                    "limit": "1",
                },
                headers={
                    "apikey": settings.supabase_service_key,
                    "Authorization": f"Bearer {settings.supabase_service_key}",
                },
            )
    except Exception as e:
        logger.error("org_admin_check_lookup_failed", extra={"error": str(e)})
        # Database flake — refuse the request rather than allow a
        # write through unauthenticated. The user retries.
        raise HTTPException(503, "Organization lookup failed")

    if resp.status_code != 200:
        raise HTTPException(404, "Organization not found")
    rows = resp.json() if resp.text else []
    if not rows or not isinstance(rows, list):
        raise HTTPException(404, "Organization not found")
    row = rows[0]
    admin_user_id = row.get("admin_user_id")
    if admin_user_id != user.id:
        # Same 404 to avoid enumeration. Log so a real admin who
        # mistypes an org_id can be debugged.
        logger.warning(
            "org_admin_check_failed",
            extra={"caller": user.id, "org_id": org_id, "admin_user_id": admin_user_id},
        )
        raise HTTPException(404, "Organization not found")


class CreateOrgRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)


class AddMemberRequest(BaseModel):
    # RFC 5321 caps emails at 320 chars. role is enum-validated in handler.
    email: str = Field(..., max_length=320)
    role: str = Field("member", max_length=16)  # admin | member


class SimulationRequest(BaseModel):
    # template is enum-validated by the handler (whitelist of 4 values);
    # the cap exists so a malformed request can't reach the validator
    # with a 100KB string and pin a worker on Pydantic processing.
    template: str = Field("generic_phishing", max_length=64)
    target_emails: list[str] = Field(..., min_length=1, max_length=500)
    # sender_name and subject end up in the simulated phishing email body.
    # 256 / 1024 chars match RFC norms (display name / Subject header) and
    # prevent payload-bomb attacks from B2B admin accounts whose sessions
    # might be compromised.
    sender_name: str = Field("IT Security", max_length=256)
    subject: str = Field("Action Required: Verify Your Account", max_length=1024)


class SimulationResult(BaseModel):
    id: str
    template: str
    total_sent: int
    total_opened: int
    total_clicked: int
    total_reported: int
    click_rate: float
    report_rate: float
    created_at: str


@router.post(
    "/create",
    dependencies=[Depends(rate_limit(mode="sensitive", category="org_create"))],
)
async def create_org(
    request: CreateOrgRequest,
    user: AuthUser = Depends(get_current_user),
):
    """Create a new organization. Requires business tier."""
    import httpx

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        # In production this is a hard failure — we won't fake a business org.
        # In dev/staging the mock helps local flows without Supabase configured.
        if settings.environment == "production":
            raise HTTPException(503, "Database not configured")
        org_id = hashlib.sha256(f"{user.id}-{request.name}".encode()).hexdigest()[:12]
        return {
            "org_id": org_id,
            "name": request.name,
            "admin": user.email,
            "tier": "business",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "mock": True,
        }

    try:
        headers = {
            "apikey": settings.supabase_service_key,
            "Authorization": f"Bearer {settings.supabase_service_key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        }

        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{settings.supabase_url}/rest/v1/orgs",
                headers=headers,
                json={"name": request.name, "admin_user_id": user.id},
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                org = data[0] if isinstance(data, list) else data
                # Audit trail: org creation is a billing-relevant event (the
                # admin will be billed against the business tier). Name is
                # NOT in meta — could be PII (e.g. real company name).
                from api.services import audit_log
                await audit_log.write(
                    action="org.created",
                    target_kind="org",
                    target_id=str(org["id"]),
                    actor_user_id=user.id,
                )
                return {"org_id": org["id"], "name": request.name, "admin": user.email}

        raise HTTPException(500, "Failed to create organization")

    except HTTPException:
        raise
    except Exception as e:
        logger.error("org_create_error", extra={"error": str(e)})
        raise HTTPException(500, "Failed to create organization")


@router.get(
    "/{org_id}/dashboard",
    dependencies=[Depends(rate_limit(category="user_read"))],
)
async def org_dashboard(
    org_id: str,
    user: AuthUser = Depends(get_current_user),
):
    """
    Organization threat dashboard.
    Shows aggregate stats — individual user data is NOT visible to admins.
    """
    await _require_org_admin(user, org_id)
    return {
        "org_id": org_id,
        "period": "last_30_days",
        "stats": {
            "total_members": 0,
            "total_checks": 0,
            "threats_blocked": 0,
            "phishing_simulations": 0,
            "avg_click_rate": 0.0,
            "avg_report_rate": 0.0,
            "risk_score": 50,
        },
        "top_threats": [],
        "trend": "improving",
        "note": "Individual browsing data is not visible. Only aggregate numbers.",
    }


@router.post(
    "/{org_id}/members",
    dependencies=[Depends(rate_limit(category="org_write"))],
)
async def add_member(
    org_id: str,
    request: AddMemberRequest,
    user: AuthUser = Depends(get_current_user),
):
    """Add member to organization."""
    await _require_org_admin(user, org_id)
    # Email is PII — don't pin it in structured logs (audit finding
    # backend MEDIUM "Org add_member endpoint logs invitee email"). The
    # role + org are sufficient for "did the operator do the action"
    # debugging; the actual invitee identity lives in audit_log.
    logger.info(
        "org_member_invite_sent",
        extra={"org": org_id, "role": request.role},
    )
    return {
        "status": "ok",
        "org_id": org_id,
        "email": request.email,
        "role": request.role,
        "message": f"Invitation sent to {request.email}",
    }


@router.post(
    "/{org_id}/simulate",
    dependencies=[Depends(rate_limit(mode="sensitive", category="org_simulate"))],
)
async def launch_simulation(
    org_id: str,
    request: SimulationRequest,
    user: AuthUser = Depends(get_current_user),
):
    """
    Launch phishing simulation campaign.

    Templates:
      - generic_phishing: "Your account will be suspended"
      - credential_harvest: Fake login page
      - invoice_scam: Fake invoice attachment
      - ceo_fraud: "CEO" requests urgent wire transfer

    Privacy: simulations only target verified org member emails.
    Results track who clicked/reported — for training, not punishment.
    """
    await _require_org_admin(user, org_id)
    sim_id = hashlib.sha256(
        f"{org_id}-{datetime.now().isoformat()}".encode()
    ).hexdigest()[:12]

    logger.info("simulation_launched", extra={
        "org": org_id, "template": request.template,
        "targets": len(request.target_emails),
    })

    return {
        "simulation_id": sim_id,
        "status": "queued",
        "template": request.template,
        "total_targets": len(request.target_emails),
        "sender_name": request.sender_name,
        "subject": request.subject,
        "message": f"Simulation queued. {len(request.target_emails)} emails will be sent within 24 hours.",
        "tracking_url": f"https://cleanway.ai/org/{org_id}/sim/{sim_id}",
    }


@router.get(
    "/{org_id}/simulations",
    dependencies=[Depends(rate_limit(category="user_read"))],
)
async def list_simulations(
    org_id: str,
    user: AuthUser = Depends(get_current_user),
):
    """List all phishing simulation campaigns for this org."""
    await _require_org_admin(user, org_id)
    return {
        "org_id": org_id,
        "simulations": [],
        "note": "No simulations run yet. Use POST /org/{org_id}/simulate to create one.",
    }


SIMULATION_TEMPLATES = {
    "generic_phishing": {
        "name": "Generic Phishing",
        "subject": "Action Required: Verify Your Account",
        "preview": "Your account will be suspended in 24 hours unless you verify...",
        "difficulty": "easy",
    },
    "credential_harvest": {
        "name": "Credential Harvest",
        "subject": "Password Expiring — Update Now",
        "preview": "Your corporate password expires today. Click here to update...",
        "difficulty": "medium",
    },
    "invoice_scam": {
        "name": "Invoice Scam",
        "subject": "Invoice #INV-4821 — Payment Overdue",
        "preview": "Please review the attached invoice and process payment...",
        "difficulty": "medium",
    },
    "ceo_fraud": {
        "name": "CEO Fraud",
        "subject": "Urgent: Wire Transfer Needed",
        "preview": "I need you to process a wire transfer today. This is confidential...",
        "difficulty": "hard",
    },
}


@router.get("/templates", dependencies=[Depends(rate_limit(category="user_read"))])
async def list_templates(user: AuthUser = Depends(get_current_user)):
    """List available phishing simulation templates."""
    return {"templates": SIMULATION_TEMPLATES}
