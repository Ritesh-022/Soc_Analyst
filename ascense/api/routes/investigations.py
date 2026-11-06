"""Investigation routes — Stage 5.

Public API:
  POST /api/v1/incidents/{incident_id}/investigations — start investigation
  GET  /api/v1/investigations/{investigation_id} — get result
  POST /api/v1/investigations/{investigation_id}/cancellations — cancel

Investigation results are read-only summaries. Proposals are generated
separately from investigation results and go through the full policy →
approval → command pipeline before any action is taken.

Every investigation is:
  - Tenant-scoped — agent cannot access other tenants' data
  - Bounded — max tool calls, timeout per step
  - Evidence-referenced — every claim needs a real evidence_id
  - Auditable — all tool calls and results are logged
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.api.dependencies.auth import get_tenant_id
from ascense.db import get_session
from ascense.models import Incident

router = APIRouter(tags=["Investigations"])

# In-memory store for investigation results (Stage 5 will use a DB table)
_investigations: dict[str, dict] = {}


class InvestigationRequest(BaseModel):
    """Request to start an investigation on an incident."""
    priority: str = "normal"  # normal | urgent


@router.post(
    "/api/v1/incidents/{incident_id}/investigations",
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_investigation(
    incident_id: UUID,
    body: InvestigationRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Enqueue an AI investigation for an incident.

    The investigation runs asynchronously. Poll
    GET /api/v1/investigations/{investigation_id} for results.

    Constraints:
      - Read-only tools only (enforced by tool registry)
      - Tenant-scoped evidence access
      - Bounded: timeout and max tool-call budget
      - No direct command execution
    """
    from uuid import uuid7
    from ascense.workers.investigation.worker import (
        build_incident_context,
        run_investigation,
    )

    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(Incident).where(
            Incident.id == incident_id,
            Incident.tenant_id == tenant_id,
        )
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if incident.status in ("RESOLVED", "CLOSED"):
        raise HTTPException(
            status_code=409,
            detail=f"Incident is {incident.status} — cannot investigate terminal incidents",
        )

    investigation_id = uuid7()
    inv_id_str = str(investigation_id)

    # Record investigation as pending
    _investigations[inv_id_str] = {
        "investigation_id": inv_id_str,
        "incident_id": str(incident_id),
        "tenant_id": str(tenant_id),
        "status": "PENDING",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "result": None,
    }

    # Run investigation in a background task
    async def _run():
        try:
            _investigations[inv_id_str]["status"] = "RUNNING"
            inv_result = await run_investigation(incident, investigation_id, session)
            _investigations[inv_id_str].update({
                "status": inv_result.get("status", "COMPLETED"),
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "result": inv_result,
            })
        except asyncio.CancelledError:
            _investigations[inv_id_str]["status"] = "CANCELLED"
        except Exception:
            _investigations[inv_id_str]["status"] = "FAILED"

    asyncio.create_task(_run())

    return {
        "investigation_id": inv_id_str,
        "incident_id": str(incident_id),
        "status": "PENDING",
        "created_at": _investigations[inv_id_str]["created_at"],
    }


@router.get("/api/v1/investigations/{investigation_id}")
async def get_investigation(
    investigation_id: UUID,
    request: Request,
) -> dict:
    """Get investigation status and results.

    Returns PENDING/RUNNING while in progress.
    Results include evidence references for every claim.
    """
    tenant_id = await get_tenant_id(request)
    inv_id_str = str(investigation_id)

    inv = _investigations.get(inv_id_str)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    # Cross-tenant isolation
    if inv["tenant_id"] != str(tenant_id):
        raise HTTPException(status_code=403, detail="Tenant access denied")

    return inv


@router.post("/api/v1/investigations/{investigation_id}/cancellations")
async def cancel_investigation(
    investigation_id: UUID,
    request: Request,
) -> dict:
    """Cancel a running investigation."""
    tenant_id = await get_tenant_id(request)
    inv_id_str = str(investigation_id)

    inv = _investigations.get(inv_id_str)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if inv["tenant_id"] != str(tenant_id):
        raise HTTPException(status_code=403, detail="Tenant access denied")

    if inv["status"] in ("COMPLETED", "CANCELLED", "FAILED"):
        raise HTTPException(
            status_code=409,
            detail=f"Investigation is {inv['status']} and cannot be cancelled",
        )

    inv["status"] = "CANCELLED"
    inv["completed_at"] = datetime.now(timezone.utc).isoformat()

    return {"investigation_id": inv_id_str, "status": "CANCELLED"}
