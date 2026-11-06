"""Response workflow routes: proposals, approvals, commands.

POST /api/v1/incidents/{incident_id}/action-proposals
GET  /api/v1/incidents/{incident_id}/action-proposals
POST /api/v1/action-proposals/{proposal_id}/approvals
GET  /api/v1/action-proposals/{proposal_id}/approvals
GET  /api/v1/action-proposals/{proposal_id}
GET  /api/v1/commands/{command_id}
GET  /api/v1/audit-events
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid7

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.api.dependencies.auth import get_current_user_id, get_tenant_id, require_role
from ascense.broker import publish
from ascense.db import get_session
from ascense.models import ActionProposal, Approval, AuditEvent, Command, Incident

router = APIRouter(tags=["Response"])

PROPOSAL_EXPIRY_SECONDS = 3600  # 1 hour


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ProposalRequest(BaseModel):
    action_type: str
    target: dict
    parameters: dict = {}
    reason: str | None = None
    evidence_ids: list[str] = []
    affected_asset_ids: list[str] = []


class ApprovalRequest(BaseModel):
    decision: str  # APPROVED | REJECTED
    reason: str | None = None


# ---------------------------------------------------------------------------
# Proposal state machine
# ---------------------------------------------------------------------------

VALID_PROPOSAL_TRANSITIONS: dict[str, list[str]] = {
    "DRAFT": ["PENDING_APPROVAL", "CANCELLED"],
    "PENDING_APPROVAL": ["APPROVED", "REJECTED", "CANCELLED"],
    "APPROVED": ["EXECUTING", "CANCELLED"],
    "REJECTED": [],
    "EXECUTING": ["SUCCEEDED", "FAILED", "PARTIALLY_SUCCEEDED"],
    "SUCCEEDED": [],
    "FAILED": [],
    "PARTIALLY_SUCCEEDED": [],
    "CANCELLED": [],
}


def _assert_proposal_transition(current: str, next_: str) -> None:
    if next_ not in VALID_PROPOSAL_TRANSITIONS.get(current, []):
        raise HTTPException(
            status_code=422,
            detail=f"Invalid proposal transition: {current} → {next_}",
        )


# ---------------------------------------------------------------------------
# Action proposals
# ---------------------------------------------------------------------------


@router.post(
    "/api/v1/incidents/{incident_id}/action-proposals",
    status_code=status.HTTP_201_CREATED,
)
async def create_proposal(
    incident_id: UUID,
    body: ProposalRequest,
    request: Request,
    user_id: UUID = Depends(get_current_user_id),
    _role_check: None = Depends(require_role("admin", "analyst")),
    session: AsyncSession = Depends(get_session),
) -> dict:
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id)
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Incident not found")

    proposal = ActionProposal(
        id=uuid7(),
        tenant_id=tenant_id,
        incident_id=incident_id,
        action_type=body.action_type,
        target=body.target,
        parameters=body.parameters,
        reason=body.reason,
        evidence_ids=body.evidence_ids,
        affected_asset_ids=body.affected_asset_ids,
        created_by="user",
        created_by_user_id=user_id,
        status="PENDING_APPROVAL",
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=PROPOSAL_EXPIRY_SECONDS),
    )
    session.add(proposal)
    await session.commit()

    await publish(
        "response.proposal.created.v1",
        {"proposal_id": str(proposal.id), "tenant_id": str(tenant_id)},
    )

    return {"proposal_id": str(proposal.id), "status": proposal.status}


@router.get("/api/v1/incidents/{incident_id}/action-proposals")
async def list_proposals(
    incident_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(ActionProposal).where(
            ActionProposal.incident_id == incident_id,
            ActionProposal.tenant_id == tenant_id,
        )
    )
    proposals = result.scalars().all()
    return {
        "items": [
            {
                "proposal_id": str(p.id),
                "action_type": p.action_type,
                "status": p.status,
                "created_at": p.created_at.isoformat(),
                "expires_at": p.expires_at.isoformat() if p.expires_at else None,
            }
            for p in proposals
        ]
    }


@router.get("/api/v1/action-proposals/{proposal_id}")
async def get_proposal(
    proposal_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(ActionProposal).where(ActionProposal.id == proposal_id)
    )
    proposal = result.scalar_one_or_none()
    if not proposal:
        raise HTTPException(status_code=404, detail="Proposal not found")
    if proposal.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied")

    return {
        "proposal_id": str(proposal.id),
        "incident_id": str(proposal.incident_id),
        "action_type": proposal.action_type,
        "target": proposal.target,
        "parameters": proposal.parameters,
        "reason": proposal.reason,
        "status": proposal.status,
        "created_by": proposal.created_by,
        "created_by_user_id": str(proposal.created_by_user_id) if proposal.created_by_user_id else None,
        "evidence_ids": proposal.evidence_ids,
        "affected_asset_ids": proposal.affected_asset_ids,
        "expires_at": proposal.expires_at.isoformat() if proposal.expires_at else None,
        "created_at": proposal.created_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------------


@router.post(
    "/api/v1/action-proposals/{proposal_id}/approvals",
    status_code=status.HTTP_201_CREATED,
)
async def record_approval(
    proposal_id: UUID,
    body: ApprovalRequest,
    request: Request,
    user_id: UUID = Depends(get_current_user_id),
    _role_check: None = Depends(require_role("admin", "approver")),
    session: AsyncSession = Depends(get_session),
) -> dict:
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(ActionProposal).where(ActionProposal.id == proposal_id)
    )
    proposal = result.scalar_one_or_none()
    if not proposal:
        raise HTTPException(status_code=404, detail="Proposal not found")
    if proposal.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied")

    # A user cannot approve their own proposal
    if body.decision == "APPROVED" and proposal.created_by_user_id == user_id:
        raise HTTPException(status_code=403, detail="Cannot approve your own proposal")

    # Proposal must not be expired
    if proposal.expires_at and proposal.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=422, detail="Proposal has expired")

    if body.decision not in ("APPROVED", "REJECTED"):
        raise HTTPException(status_code=422, detail="decision must be APPROVED or REJECTED")

    approval = Approval(
        id=uuid7(),
        tenant_id=tenant_id,
        proposal_id=proposal_id,
        decision=body.decision,
        reason=body.reason,
        approver_id=user_id,
        status="RECORDED",
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=PROPOSAL_EXPIRY_SECONDS),
    )
    session.add(approval)

    proposal.status = "APPROVED" if body.decision == "APPROVED" else "REJECTED"
    proposal.updated_at = datetime.now(timezone.utc)
    await session.commit()

    if body.decision == "APPROVED":
        await publish(
            "response.approval.recorded.v1",
            {
                "approval_id": str(approval.id),
                "proposal_id": str(proposal_id),
                "tenant_id": str(tenant_id),
            },
        )

    return {"approval_id": str(approval.id), "decision": body.decision}


@router.get("/api/v1/action-proposals/{proposal_id}/approvals")
async def list_approvals(
    proposal_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(ActionProposal).where(ActionProposal.id == proposal_id)
    )
    proposal = result.scalar_one_or_none()
    if not proposal:
        raise HTTPException(status_code=404, detail="Proposal not found")
    if proposal.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied")

    result = await session.execute(
        select(Approval).where(Approval.proposal_id == proposal_id)
    )
    approvals = result.scalars().all()
    return {
        "items": [
            {
                "approval_id": str(a.id),
                "decision": a.decision,
                "reason": a.reason,
                "approver_id": str(a.approver_id),
                "status": a.status,
                "created_at": a.created_at.isoformat(),
            }
            for a in approvals
        ]
    }


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@router.get("/api/v1/commands/{command_id}")
async def get_command(
    command_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    tenant_id = await get_tenant_id(request)

    result = await session.execute(select(Command).where(Command.id == command_id))
    command = result.scalar_one_or_none()
    if not command:
        raise HTTPException(status_code=404, detail="Command not found")
    if command.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied")

    return {
        "command_id": str(command.id),
        "gateway_id": str(command.gateway_id),
        "action_type": command.action_type,
        "target": command.target,
        "status": command.status,
        "proposal_id": str(command.proposal_id),
        "approval_id": str(command.approval_id),
        "expires_at": command.expires_at.isoformat(),
        "created_at": command.created_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


@router.get("/api/v1/audit-events")
async def list_audit_events(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict:
    tenant_id = await get_tenant_id(request)

    query = select(AuditEvent).where(AuditEvent.tenant_id == tenant_id)
    if cursor:
        try:
            query = query.where(AuditEvent.id < UUID(cursor))
        except ValueError:
            pass
    query = query.order_by(AuditEvent.occurred_at.desc()).limit(limit + 1)

    result = await session.execute(query)
    events = result.scalars().all()

    has_more = len(events) > limit
    items = events[:limit]

    return {
        "items": [
            {
                "audit_event_id": str(e.id),
                "action": e.action,
                "actor_id": str(e.actor_id),
                "actor_type": e.actor_type,
                "target_type": e.target_type,
                "target_id": str(e.target_id) if e.target_id else None,
                "outcome": e.outcome,
                "occurred_at": e.occurred_at.isoformat(),
            }
            for e in items
        ],
        "next_cursor": str(items[-1].id) if has_more and items else None,
    }


# ---------------------------------------------------------------------------
# Approval revocation
# ---------------------------------------------------------------------------


class RevocationRequest(BaseModel):
    reason: str


@router.post("/api/v1/action-proposals/{proposal_id}/approvals/{approval_id}/revocations")
async def revoke_approval(
    proposal_id: UUID,
    approval_id: UUID,
    body: RevocationRequest,
    request: Request,
    user_id: UUID = Depends(get_current_user_id),
    _role_check: None = Depends(require_role("admin", "approver")),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Revoke an existing approval. Only admins and approvers can revoke.

    Revoking an approval cancels any QUEUED commands that depend on it.
    This is a safety mechanism — if an approval was granted in error,
    the action can still be stopped before the gateway executes it.
    """
    from ascense.models import Command
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(Approval).where(Approval.id == approval_id)
    )
    approval = result.scalar_one_or_none()
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")
    if approval.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied")
    if approval.status not in ("PENDING", "APPROVED"):
        raise HTTPException(
            status_code=409,
            detail=f"Approval is {approval.status} and cannot be revoked",
        )

    # Revoke the approval
    approval.status = "REVOKED"

    # Cancel any QUEUED commands that reference this approval
    result = await session.execute(
        select(Command).where(
            Command.approval_id == approval_id,
            Command.status.in_(["QUEUED", "LEASED"]),
        )
    )
    commands = result.scalars().all()
    for cmd in commands:
        cmd.status = "CANCELLED"

    await session.commit()

    return {
        "approval_id": str(approval.id),
        "status": approval.status,
        "commands_cancelled": len(commands),
    }


# ---------------------------------------------------------------------------
# Proposal cancellation
# ---------------------------------------------------------------------------

@router.post("/api/v1/action-proposals/{proposal_id}/cancellations")
async def cancel_proposal(
    proposal_id: UUID,
    body: RevocationRequest,
    request: Request,
    user_id: UUID = Depends(get_current_user_id),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Cancel an action proposal that has not yet been approved."""
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(ActionProposal).where(ActionProposal.id == proposal_id)
    )
    proposal = result.scalar_one_or_none()
    if not proposal:
        raise HTTPException(status_code=404, detail="Proposal not found")
    if proposal.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied")

    cancellable = {"DRAFT", "PENDING_APPROVAL", "SUBMITTED", "POLICY_EVALUATION"}
    if proposal.status not in cancellable:
        raise HTTPException(
            status_code=409,
            detail=f"Proposal is {proposal.status} and cannot be cancelled",
        )

    proposal.status = "CANCELLED"
    proposal.updated_at = datetime.now(timezone.utc)
    await session.commit()

    return {"proposal_id": str(proposal.id), "status": proposal.status}
