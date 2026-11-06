"""Alert management routes.

Public API:
  GET  /api/v1/alerts — list alerts (with filters)
  GET  /api/v1/alerts/{alert_id} — get alert and evidence references
  POST /api/v1/alerts/{alert_id}/acknowledgements — acknowledge an alert

Alert lifecycle: NEW → ACKNOWLEDGED → UNDER_INVESTIGATION → RESOLVED / FALSE_POSITIVE
"""

from __future__ import annotations

import contextlib
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.api.dependencies.auth import get_tenant_id
from ascense.db import get_session
from ascense.models import Alert

router = APIRouter(tags=["Alerts"])


class AlertAcknowledgementRequest(BaseModel):
    reason: str


@router.get("/api/v1/alerts")
async def list_alerts(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = None,
    incident_id: UUID | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """List alerts with optional filtering by status, severity, or incident."""
    tenant_id = await get_tenant_id(request)

    query = select(Alert).where(Alert.tenant_id == tenant_id)

    if status_filter:
        query = query.where(Alert.status == status_filter)
    if severity:
        query = query.where(Alert.severity == severity)
    if incident_id:
        query = query.where(Alert.incident_id == incident_id)
    if cursor:
        with contextlib.suppress(ValueError):
            query = query.where(Alert.id < UUID(cursor))

    query = query.order_by(Alert.id.desc()).limit(limit + 1)
    result = await session.execute(query)
    alerts = result.scalars().all()

    has_more = len(alerts) > limit
    items = alerts[:limit]
    next_cursor = str(items[-1].id) if has_more and items else None

    return {
        "items": [
            {
                "alert_id": str(a.id),
                "tenant_id": str(a.tenant_id),
                "incident_id": str(a.incident_id) if a.incident_id else None,
                "alert_type": a.alert_type,
                "severity": a.severity,
                "risk_score": a.risk_score,
                "status": a.status,
                "detection_finding_ids": a.detection_finding_ids,
                "event_ids": a.event_ids,
                "evidence_ids": a.evidence_ids,
                "affected_asset_ids": a.affected_asset_ids,
                "summary": a.summary,
                "observed_at": a.observed_at.isoformat(),
                "created_at": a.created_at.isoformat(),
            }
            for a in items
        ],
        "next_cursor": next_cursor,
    }


@router.get("/api/v1/alerts/{alert_id}")
async def get_alert(
    alert_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Get alert and evidence references. 403 if belongs to another tenant."""
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(Alert).where(Alert.id == alert_id)
    )
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied")

    return {
        "alert_id": str(alert.id),
        "tenant_id": str(alert.tenant_id),
        "incident_id": str(alert.incident_id) if alert.incident_id else None,
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "risk_score": alert.risk_score,
        "status": alert.status,
        "detection_finding_ids": alert.detection_finding_ids,
        "event_ids": alert.event_ids,
        "evidence_ids": alert.evidence_ids,
        "affected_asset_ids": alert.affected_asset_ids,
        "summary": alert.summary,
        "observed_at": alert.observed_at.isoformat(),
        "created_at": alert.created_at.isoformat(),
    }


@router.post("/api/v1/alerts/{alert_id}/acknowledgements")
async def acknowledge_alert(
    alert_id: UUID,
    body: AlertAcknowledgementRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Acknowledge an alert. Transitions from NEW to ACKNOWLEDGED."""
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(Alert).where(Alert.id == alert_id)
    )
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied")
    if alert.status != "NEW":
        raise HTTPException(
            status_code=409,
            detail=f"Alert is in status {alert.status}, cannot acknowledge",
        )

    alert.status = "ACKNOWLEDGED"
    await session.commit()

    return {
        "alert_id": str(alert.id),
        "status": alert.status,
        "acknowledged_at": alert.updated_at.isoformat(),
    }
