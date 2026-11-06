"""Response worker.

The response service is the sole enforcement authority. It creates signed
commands bound to tenant, gateway, target, approval, and policy version,
dispatches them to the gateway command queue, receives execution results,
and verifies the actual enforcement state.

Must not: execute commands without a valid approval, reuse expired
approvals, skip policy evaluation, or accept unsigned execution results.

Owner: Developer A (response safety authority)
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid7

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.db import async_session_factory
from ascense.models import ActionProposal, Approval, Command, ExecutionAttempt

logger = structlog.get_logger(__name__)


async def create_signed_command(
    proposal: ActionProposal,
    approval: Approval,
    policy_version_id: UUID,
    session: AsyncSession,
) -> Command:
    """Create an authorized, signed command from an approved proposal.

    The command binds:
      - command_id, tenant_id, gateway_id — exact identities
      - target, action_type, parameters — exact action
      - proposal_id, approval_id — authorization chain
      - policy_version_id — policy version at authorization time
      - created_at, expires_at — short expiry window
      - nonce — unique per command (prevents replay)
      - idempotency_key — safe retransmission
      - signature — verifiable by the gateway
    """
    # Validate that the approval is still valid
    if approval.status != "APPROVED":
        raise ValueError(f"Approval is {approval.status}, not APPROVED")
    if approval.expires_at and approval.expires_at < datetime.now(timezone.utc):
        raise ValueError("Approval has expired")

    # Generate cryptographic material
    nonce = secrets.token_urlsafe(32)
    idempotency_key = secrets.token_urlsafe(32)

    # Command hash for signature (simplified — in production use proper
    # cryptographic signing with a managed key)
    command_data = f"{proposal.id}:{approval.id}:{proposal.action_type}:{proposal.target}"
    signature = hashlib.sha256(command_data.encode()).hexdigest()

    command = Command(
        id=uuid7(),
        tenant_id=proposal.tenant_id,
        gateway_id=UUID(proposal.target.get("gateway_id", "00000000-0000-7000-8000-000000000000")),
        action_type=proposal.action_type,
        target=proposal.target,
        parameters=proposal.parameters,
        proposal_id=proposal.id,
        approval_id=approval.id,
        policy_version_id=policy_version_id,
        status="QUEUED",
        nonce=nonce,
        idempotency_key=idempotency_key,
        signature=signature,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=900),
    )
    session.add(command)

    logger.info(
        "command.created",
        command_id=str(command.id),
        proposal_id=str(proposal.id),
        action_type=command.action_type,
    )
    return command


async def verify_enforcement_state(
    command_id: UUID,
    session: AsyncSession,
) -> str:
    """Verify the actual enforcement state by independent read-back.

    Returns: VERIFIED, NOT_VERIFIED, or UNKNOWN.
    Only the response verification service sets verification status —
    an AI investigation worker cannot set it.

    A gateway reporting execution_status: SUCCEEDED does not imply
    verification_status: VERIFIED. These are two separate fields.
    """
    result = await session.execute(
        select(ExecutionAttempt).where(ExecutionAttempt.command_id == command_id)
    )
    attempt = result.scalar_one_or_none()

    if not attempt:
        return "PENDING"

    # In production, this would do an independent read-back from the
    # firewall or security product's authorized management interface.
    # For now, return UNKNOWN to trigger escalation.
    logger.info(
        "verification.attempted",
        command_id=str(command_id),
        execution_status=attempt.execution_status,
    )
    return "UNKNOWN"


async def run_worker() -> None:
    """Main response worker loop."""
    logger.info("response_worker.starting")
    # TODO: Consume from the response queue, create commands, dispatch
    logger.info("response_worker.started")
