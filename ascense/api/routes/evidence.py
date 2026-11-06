"""Evidence management routes.

Evidence records are append-only and independently protected.
They are referenced by alerts, incidents, and investigation results.
Large evidence objects live in object storage; PostgreSQL holds
references and access controls.

Public API:
  GET /api/v1/evidence/{evidence_id} — get evidence record
  GET /api/v1/incidents/{incident_id}/evidence — list evidence for incident
  POST /api/v1/incidents/{incident_id}/evidence — attach evidence to incident
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.api.dependencies.auth import get_tenant_id
from ascense.db import get_session
from ascense.models import Evidence, Incident

router = APIRouter(tags=["Evidence"])


class EvidenceCreateRequest(BaseModel):
    evidence_type: str  # e.g. "network_capture", "log_excerpt", "screenshot"
    description: str | None = None
    storage_reference: str | None = None  # S3/MinIO object key
    collected_at: datetime | None = None


@router.post(
    "/api/v1/incidents/{incident_id}/evidence",
    status_code=status.HTTP_201_CREATED,
)
async def attach_evidence(
    incident_id: UUID,
    body: EvidenceCreateRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Attach an evidence record to an incident.
    Evidence is append-only — records are never deleted during retention."""
    from uuid import uuid7
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    evidence = Evidence(
        id=uuid7(),
        tenant_id=tenant_id,
        evidence_type=body.evidence_type,
        description=body.description,
        storage_reference=body.storage_reference,
        collected_at=body.collected_at or datetime.now(timezone.utc),
    )
    session.add(evidence)

    # Link evidence_id into the incident
    incident.evidence_ids = incident.evidence_ids + [str(evidence.id)]
    await session.commit()

    return {
        "evidence_id": str(evidence.id),
        "tenant_id": str(evidence.tenant_id),
        "evidence_type": evidence.evidence_type,
        "description": evidence.description,
        "storage_reference": evidence.storage_reference,
        "collected_at": evidence.collected_at.isoformat(),
        "created_at": evidence.created_at.isoformat(),
    }


@router.get("/api/v1/evidence/{evidence_id}")
async def get_evidence(
    evidence_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Get evidence record. 403 if belongs to another tenant."""
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(Evidence).where(Evidence.id == evidence_id)
    )
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if evidence.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied")

    return {
        "evidence_id": str(evidence.id),
        "tenant_id": str(evidence.tenant_id),
        "event_id": str(evidence.event_id) if evidence.event_id else None,
        "evidence_type": evidence.evidence_type,
        "description": evidence.description,
        "storage_reference": evidence.storage_reference,
        "collected_at": evidence.collected_at.isoformat(),
        "created_at": evidence.created_at.isoformat(),
    }


@router.get("/api/v1/incidents/{incident_id}/evidence")
async def list_incident_evidence(
    incident_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """List all evidence attached to an incident."""
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    evidence_ids = [UUID(eid) for eid in (incident.evidence_ids or [])]
    if not evidence_ids:
        return {"items": []}

    result = await session.execute(
        select(Evidence).where(
            Evidence.id.in_(evidence_ids),
            Evidence.tenant_id == tenant_id,
        )
    )
    records = result.scalars().all()

    return {
        "items": [
            {
                "evidence_id": str(e.id),
                "evidence_type": e.evidence_type,
                "description": e.description,
                "storage_reference": e.storage_reference,
                "collected_at": e.collected_at.isoformat(),
                "created_at": e.created_at.isoformat(),
            }
            for e in records
        ]
    }
