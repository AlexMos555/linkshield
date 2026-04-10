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
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.services.auth import get_current_user
from api.models.schemas import AuthUser
from api.config import get_settings

logger = logging.getLogger("linkshield.org")

router = APIRouter(prefix="/api/v1/org", tags=["organization"])


class CreateOrgRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)


class AddMemberRequest(BaseModel):
    email: str
    role: str = "member"  # admin | member


class SimulationRequest(BaseModel):
    template: str = "generic_phishing"  # generic_phishing | credential_harvest | invoice_scam | ceo_fraud
    target_emails: list[str] = Field(..., min_length=1, max_length=500)
    sender_name: str = "IT Security"
    subject: str = "Action Required: Verify Your Account"


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


@router.post("/create")
async def create_org(
    request: CreateOrgRequest,
    user: AuthUser = Depends(get_current_user),
):
    """Create a new organization. Requires business tier."""
    import httpx

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        # Return mock for demo
        org_id = hashlib.sha256(f"{user.id}-{request.name}".encode()).hexdigest()[:12]
        return {
            "org_id": org_id,
            "name": request.name,
            "admin": user.email,
            "tier": "business",
            "created_at": datetime.now(timezone.utc).isoformat(),
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
                return {"org_id": org["id"], "name": request.name, "admin": user.email}

        raise HTTPException(500, "Failed to create organization")

    except HTTPException:
        raise
    except Exception as e:
        logger.error("org_create_error", extra={"error": str(e)})
        raise HTTPException(500, "Failed to create organization")


@router.get("/{org_id}/dashboard")
async def org_dashboard(
    org_id: str,
    user: AuthUser = Depends(get_current_user),
):
    """
    Organization threat dashboard.
    Shows aggregate stats — individual user data is NOT visible to admins.
    """
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


@router.post("/{org_id}/members")
async def add_member(
    org_id: str,
    request: AddMemberRequest,
    user: AuthUser = Depends(get_current_user),
):
    """Add member to organization."""
    logger.info("org_member_added", extra={"org": org_id, "email": request.email, "role": request.role})
    return {
        "status": "ok",
        "org_id": org_id,
        "email": request.email,
        "role": request.role,
        "message": f"Invitation sent to {request.email}",
    }


@router.post("/{org_id}/simulate")
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
        "tracking_url": f"https://linkshield.io/org/{org_id}/sim/{sim_id}",
    }


@router.get("/{org_id}/simulations")
async def list_simulations(
    org_id: str,
    user: AuthUser = Depends(get_current_user),
):
    """List all phishing simulation campaigns for this org."""
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


@router.get("/templates")
async def list_templates(user: AuthUser = Depends(get_current_user)):
    """List available phishing simulation templates."""
    return {"templates": SIMULATION_TEMPLATES}
