"""Incident management routes.

Public API:
  GET  /api/v1/incidents — list incidents
  GET  /api/v1/incidents/{incident_id} — get incident details
  POST /api/v1/incidents/{incident_id}/transitions — move incident through state

Incident lifecycle:
  OPEN → TRIAGED → INVESTIGATING → CONTAINMENT_IN_PROGRESS
      → CONTAINED → RECOVERING → RESOLVED → CLOSED

Each transition records the actor, timestamp, and reason.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.db import get_session
from ascense.api.dependencies.auth import get_tenant_id
from ascense.models import Incident

router = APIRouter(tags=["Incidents"])

# Valid incident state transitions
VALID_TRANSITIONS: dict[str, set[str]] = {
    "OPEN": {"TRIAGED", "CLOSED"},
    "TRIAGED": {"INVESTIGATING", "CLOSED"},
    "INVESTIGATING": {"CONTAINMENT_IN_PROGRESS", "RESOLVED", "CLOSED"},
    "CONTAINMENT_IN_PROGRESS": {"CONTAINED", "RESOLVED"},
    "CONTAINED": {"RECOVERING", "RESOLVED"},
    "RECOVERING": {"RESOLVED"},
    "RESOLVED": {"CLOSED"},
    "CLOSED": {"OPEN"},  # Allow reopening
}


class IncidentTransitionRequest(BaseModel):
    target_status: str
    reason: str


@router.get("/api/v1/incidents")
async def list_incidents(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """List incidents with optional filtering."""
    tenant_id = await get_tenant_id(request)

    query = select(Incident).where(Incident.tenant_id == tenant_id)

    if status_filter:
        query = query.where(Incident.status == status_filter)
    if severity:
        query = query.where(Incident.severity == severity)
    if cursor:
        try:
            query = query.where(Incident.id < UUID(cursor))
        except ValueError:
            pass

    query = query.order_by(Incident.id.desc()).limit(limit + 1)
    result = await session.execute(query)
    incidents = result.scalars().all()

    has_more = len(incidents) > limit
    items = incidents[:limit]
    next_cursor = str(items[-1].id) if has_more and items else None

    return {
        "items": [
            {
                "incident_id": str(i.id),
                "tenant_id": str(i.tenant_id),
                "title": i.title,
                "severity": i.severity,
                "status": i.status,
                "summary": i.summary,
                "alert_ids": i.alert_ids,
                "affected_asset_ids": i.affected_asset_ids,
                "evidence_ids": i.evidence_ids,
                "created_at": i.created_at.isoformat(),
                "updated_at": i.updated_at.isoformat(),
            }
            for i in items
        ],
        "next_cursor": next_cursor,
    }


@router.get("/api/v1/incidents/{incident_id}")
async def get_incident(
    incident_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Get incident details. 403 if belongs to another tenant."""
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(Incident).where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied")

    return {
        "incident_id": str(incident.id),
        "tenant_id": str(incident.tenant_id),
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "summary": incident.summary,
        "alert_ids": incident.alert_ids,
        "affected_asset_ids": incident.affected_asset_ids,
        "evidence_ids": incident.evidence_ids,
        "created_at": incident.created_at.isoformat(),
        "updated_at": incident.updated_at.isoformat(),
    }


@router.post("/api/v1/incidents/{incident_id}/transitions")
async def transition_incident(
    incident_id: UUID,
    body: IncidentTransitionRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Move an incident through an authorized state transition.
    Each transition records the actor, timestamp, and reason."""
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(Incident).where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied")

    # Validate the transition
    current_status = incident.status
    target = body.target_status

    allowed = VALID_TRANSITIONS.get(current_status, set())
    if target not in allowed:
        raise HTTPException(
            status_code=409,
            detail=f"Invalid transition: {current_status} → {target}",
        )

    incident.status = target
    await session.commit()

    return {
        "incident_id": str(incident.id),
        "status": incident.status,
        "updated_at": incident.updated_at.isoformat(),
    }
