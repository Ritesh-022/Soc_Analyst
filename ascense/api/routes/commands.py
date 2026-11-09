"""Internal command management routes.

These routes are INTERNAL only — they must not be reachable from the
public internet or the dashboard. The API gateway / reverse proxy must
block all /internal/v1/ paths from external ingress.

Internal API:
  POST /internal/v1/commands — create a signed command from an approved proposal
  POST /internal/v1/commands/{command_id}/verify — trigger enforcement verification

Edge API:
  POST /edge/v1/gateways/{gateway_id}/commands:claim — atomic lease claim
  POST /edge/v1/gateways/{gateway_id}/commands/{command_id}/acknowledgements — confirm receipt
  POST /edge/v1/gateways/{gateway_id}/commands/{command_id}/results — report execution result

Public API:
  GET  /api/v1/commands/{command_id} — view command status (already in proposals.py)
  GET  /api/v1/action-proposals/{proposal_id}/executions — view execution attempts
"""

from __future__ import annotations

import hmac
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.api.dependencies.auth import get_tenant_id
from ascense.api.dependencies.gateway import GatewayAuthContext, get_gateway_context
from ascense.config import get_settings
from ascense.db import get_session
from ascense.models import (
    ActionProposal,
    Approval,
    Command,
    ExecutionAttempt,
    Gateway,
    PolicyVersion,
)
from ascense.workers.response.worker import create_signed_command


def _verify_gateway_identity(request: Request, url_gateway_id: UUID) -> None:
    """Verify that the authenticated mTLS identity matches the gateway_id in the URL.

    In production, the mTLS middleware sets request.state.gateway_id from
    the verified certificate. This function ensures the URL parameter
    matches that authenticated identity.
    """
    _is_dev = get_settings().is_dev

    if _is_dev:
        # Dev mode: accept X-Gateway-ID header or state
        state_gateway_id = getattr(request.state, "gateway_id", None)
        header_gateway_id = request.headers.get("X-Gateway-ID")
        if state_gateway_id and state_gateway_id == str(url_gateway_id):
            return
        if header_gateway_id and header_gateway_id == str(url_gateway_id):
            return
        return  # permissive in dev

    # Production: mTLS middleware must have set gateway_id
    state_gateway_id = getattr(request.state, "gateway_id", None)
    if not state_gateway_id:
        raise HTTPException(
            status_code=401,
            detail="Authenticated gateway identity required.",
        )

    try:
        auth_gateway_id = UUID(str(state_gateway_id))
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid authenticated gateway identity.",
        ) from exc

    if auth_gateway_id != url_gateway_id:
        raise HTTPException(
            status_code=403,
            detail="Gateway ID in URL does not match the authenticated certificate identity.",
        )

router = APIRouter(tags=["Commands"])


def _auth_token_from_request(request: Request) -> str | None:
    """Read the internal service credential from request headers."""
    token = request.headers.get("X-Service-Token")
    if token:
        return token
    auth_header = request.headers.get("Authorization", "")
    scheme, separator, value = auth_header.partition(" ")
    if separator and scheme.casefold() == "bearer":
        return value
    return None


async def require_internal_service_auth(
    request: Request,
    authorization: str | None = Header(None, alias="Authorization"),
) -> None:
    """Require a trusted internal service credential on /internal/v1/* routes."""
    del authorization
    token = _auth_token_from_request(request)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Internal service authentication required",
        )

    expected = get_settings().INTERNAL_SERVICE_TOKEN
    if not token or not hmac.compare_digest(token, expected):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid internal service credential",
        )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CreateCommandRequest(BaseModel):
    proposal_id: UUID
    approval_id: UUID


class CommandClaimResponse(BaseModel):
    command_id: str
    action_type: str
    target: dict
    parameters: dict
    signature: str
    nonce: str
    idempotency_key: str
    expires_at: str


class ExecutionResultRequest(BaseModel):
    """Execution result submitted by the gateway."""
    execution_status: str
    observed_enforcement_state: dict | None = None
    result_reference: str | None = None


# ---------------------------------------------------------------------------
# Internal API
# ---------------------------------------------------------------------------


@router.post("/internal/v1/commands", status_code=status.HTTP_201_CREATED)
async def create_command(
    body: CreateCommandRequest,
    _auth: None = Depends(require_internal_service_auth),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Create a signed command from an approved proposal.

    Called by the response automation service after an approval is
    recorded. Validates:
      - Proposal exists and is APPROVED
      - Approval is valid and not expired
      - Gateway belongs to the same tenant as the proposal

    Returns the command_id for dispatch.
    """
    result = await session.execute(
        select(ActionProposal).where(ActionProposal.id == body.proposal_id)
    )
    proposal = result.scalar_one_or_none()
    if not proposal:
        raise HTTPException(status_code=404, detail="Proposal not found")

    result = await session.execute(
        select(Approval).where(Approval.id == body.approval_id)
    )
    approval = result.scalar_one_or_none()
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")

    # Validate approval is for this proposal
    if approval.proposal_id != proposal.id:
        raise HTTPException(status_code=422, detail="Approval does not match proposal")

    # Get active policy version for the tenant
    result = await session.execute(
        select(PolicyVersion).where(
            PolicyVersion.tenant_id == proposal.tenant_id,
            PolicyVersion.is_active == True,  # noqa: E712
        ).limit(1)
    )
    policy = result.scalar_one_or_none()
    policy_version_id = policy.id if policy else None
    if not policy_version_id:
        raise HTTPException(status_code=422, detail="No active policy version for tenant")

    try:
        command = await create_signed_command(
            proposal, approval, policy_version_id, session
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {
        "command_id": str(command.id),
        "gateway_id": str(command.gateway_id),
        "action_type": command.action_type,
        "status": command.status,
        "proposal_id": str(command.proposal_id),
        "approval_id": str(command.approval_id),
        "expires_at": command.expires_at.isoformat(),
        "created_at": command.created_at.isoformat(),
    }


@router.post("/internal/v1/commands/{command_id}/verify")
async def trigger_verification(
    command_id: UUID,
    _auth: None = Depends(require_internal_service_auth),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Trigger independent enforcement verification for a command.

    The verification service does an independent read-back from the
    firewall to confirm the enforcement state is in effect.
    Only this service may set verification_status — not the gateway.
    """
    result = await session.execute(
        select(ExecutionAttempt).where(ExecutionAttempt.command_id == command_id)
    )
    attempt = result.scalar_one_or_none()
    if not attempt:
        raise HTTPException(status_code=404, detail="No execution attempt found for command")

    # In production, this calls the firewall's management API to verify the rule is active.
    # UNKNOWN verification_status must escalate — never treated as success.
    # For now, return UNKNOWN to trigger escalation handling.
    attempt.verification_status = "UNVERIFIABLE"
    await session.commit()

    return {
        "command_id": str(command_id),
        "execution_attempt_id": str(attempt.id),
        "verification_status": attempt.verification_status,
    }


# ---------------------------------------------------------------------------
# Edge API: Command claim and acknowledgement
# ---------------------------------------------------------------------------


@router.post("/edge/v1/gateways/{gateway_id}/commands:claim")
async def claim_command(
    gateway_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    gateway_context: GatewayAuthContext = Depends(get_gateway_context),
) -> dict:
    """Atomic lease claim: gateway claims the next available queued command.

    Only one gateway process can lease a given command — the claim is
    atomic (SELECT ... FOR UPDATE SKIP LOCKED). The lease has a defined
    expiry window; if not acknowledged within that window, the command
    returns to QUEUED.
    """
    _verify_gateway_identity(request, gateway_id)

    from datetime import timedelta

    result = await session.execute(
        select(Gateway).where(Gateway.id == gateway_id)
    )
    gateway = result.scalar_one_or_none()
    if not gateway:
        raise HTTPException(status_code=404, detail="Gateway not found")

    # Atomically claim the next available command for this gateway
    result = await session.execute(
        select(Command)
        .where(
            Command.gateway_id == gateway_id,
            Command.status == "QUEUED",
        )
        .order_by(Command.created_at)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    command = result.scalar_one_or_none()

    if not command:
        return {"command": None}

    # Check command has not expired
    if command.expires_at < datetime.now(UTC):
        command.status = "EXPIRED"
        await session.commit()
        return {"command": None}

    # Issue the lease
    command.status = "LEASED"
    command.lease_expires_at = datetime.now(UTC) + timedelta(seconds=300)
    await session.commit()

    return {
        "command": {
            "command_id": str(command.id),
            "action_type": command.action_type,
            "target": command.target,
            "parameters": command.parameters,
            "signature": command.signature,
            "nonce": command.nonce,
            "idempotency_key": command.idempotency_key,
            "expires_at": command.expires_at.isoformat(),
            "lease_expires_at": command.lease_expires_at.isoformat(),
        }
    }


@router.post(
    "/edge/v1/gateways/{gateway_id}/commands/{command_id}/acknowledgements",
    status_code=status.HTTP_200_OK,
)
async def acknowledge_command(
    gateway_id: UUID,
    command_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
    gateway_context: GatewayAuthContext = Depends(get_gateway_context),
) -> dict:
    """Gateway confirms it has received and accepted the command.

    Transitions command from LEASED → ACKNOWLEDGED.
    After this point, the gateway will execute the command.
    """
    _verify_gateway_identity(request, gateway_id)

    result = await session.execute(
        select(Command).where(
            Command.id == command_id,
            Command.gateway_id == gateway_id,
        )
    )
    command = result.scalar_one_or_none()
    if not command:
        raise HTTPException(status_code=404, detail="Command not found for this gateway")

    if command.status != "LEASED":
        raise HTTPException(
            status_code=409,
            detail=f"Command is in status {command.status}, cannot acknowledge",
        )

    if command.lease_expires_at and command.lease_expires_at < datetime.now(UTC):
        command.status = "EXPIRED"
        await session.commit()
        raise HTTPException(status_code=409, detail="Command lease has expired")

    command.status = "ACKNOWLEDGED"
    await session.commit()

    return {"command_id": str(command.id), "status": command.status}


@router.post(
    "/edge/v1/gateways/{gateway_id}/commands/{command_id}/results",
    status_code=status.HTTP_200_OK,
)
async def report_execution_result(
    gateway_id: UUID,
    command_id: UUID,
    body: ExecutionResultRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    gateway_context: GatewayAuthContext = Depends(get_gateway_context),
) -> dict:
    """Gateway reports the execution result for a command.

    The gateway MUST persist the execution journal record BEFORE
    performing any action. This endpoint records the result.

    execution_status is set by the gateway.
    verification_status is set by the verification service only.
    UNKNOWN execution_status must trigger escalation.
    """
    _verify_gateway_identity(request, gateway_id)

    from uuid import uuid7

    result = await session.execute(
        select(Command).where(
            Command.id == command_id,
            Command.gateway_id == gateway_id,
        )
    )
    command = result.scalar_one_or_none()
    if not command:
        raise HTTPException(status_code=404, detail="Command not found for this gateway")

    valid_statuses = {
        "SUCCEEDED", "FAILED", "PARTIALLY_SUCCEEDED", "UNKNOWN",
        "ROLLBACK_PENDING", "ROLLED_BACK", "ROLLBACK_FAILED",
    }
    if body.execution_status not in valid_statuses:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid execution_status: {body.execution_status}",
        )

    # Create or update the execution attempt
    result = await session.execute(
        select(ExecutionAttempt).where(ExecutionAttempt.command_id == command_id)
    )
    attempt = result.scalar_one_or_none()

    if not attempt:
        import hashlib
        cmd_hash = hashlib.sha256(command.signature.encode()).hexdigest()[:32]
        attempt = ExecutionAttempt(
            id=uuid7(),
            tenant_id=command.tenant_id,
            command_id=command.id,
            gateway_id=gateway_id,
            command_hash=cmd_hash,
            received_at=datetime.now(UTC),
            execution_started_at=datetime.now(UTC),
        )
        session.add(attempt)

    attempt.execution_completed_at = datetime.now(UTC)
    attempt.execution_status = body.execution_status
    attempt.observed_enforcement_state = body.observed_enforcement_state
    attempt.result_reference = body.result_reference
    # verification_status stays PENDING — set only by verification service

    # UNKNOWN execution must trigger an escalation (logged here)
    if body.execution_status == "UNKNOWN":
        import structlog
        log = structlog.get_logger(__name__)
        log.warning(
            "command.execution_unknown",
            command_id=str(command_id),
            gateway_id=str(gateway_id),
            note="Escalation required: verification_status will not auto-resolve",
        )

    await session.commit()

    return {
        "execution_attempt_id": str(attempt.id),
        "command_id": str(command_id),
        "execution_status": attempt.execution_status,
        "verification_status": attempt.verification_status,
    }


# ---------------------------------------------------------------------------
# Public API: Execution attempts
# ---------------------------------------------------------------------------


@router.get("/api/v1/action-proposals/{proposal_id}/executions")
async def list_executions(
    proposal_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """List execution attempts for all commands under a proposal."""
    tenant_id = await get_tenant_id(request)

    # Verify proposal belongs to this tenant
    result = await session.execute(
        select(ActionProposal).where(
            ActionProposal.id == proposal_id,
            ActionProposal.tenant_id == tenant_id,
        )
    )
    proposal = result.scalar_one_or_none()
    if not proposal:
        raise HTTPException(status_code=404, detail="Proposal not found")

    # Get all commands for this proposal
    result = await session.execute(
        select(Command).where(
            Command.proposal_id == proposal_id,
            Command.tenant_id == tenant_id,
        )
    )
    commands = result.scalars().all()
    command_ids = [c.id for c in commands]

    if not command_ids:
        return {"items": []}

    # Get all execution attempts
    result = await session.execute(
        select(ExecutionAttempt).where(ExecutionAttempt.command_id.in_(command_ids))
    )
    attempts = result.scalars().all()

    return {
        "items": [
            {
                "execution_attempt_id": str(a.id),
                "command_id": str(a.command_id),
                "execution_status": a.execution_status,
                "verification_status": a.verification_status,
                "received_at": a.received_at.isoformat(),
                "execution_started_at": (
                    a.execution_started_at.isoformat()
                    if a.execution_started_at else None
                ),
                "execution_completed_at": (
                    a.execution_completed_at.isoformat()
                    if a.execution_completed_at else None
                ),
                "observed_enforcement_state": a.observed_enforcement_state,
                "result_reference": a.result_reference,
            }
            for a in attempts
        ]
    }
