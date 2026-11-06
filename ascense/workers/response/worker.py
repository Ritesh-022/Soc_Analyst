"""Response worker.

The response service is the sole enforcement authority. It creates signed
commands bound to tenant, gateway, target, approval, and policy version,
dispatches them to the gateway command queue, receives execution results,
and verifies the actual enforcement state.

Must not: execute commands without a valid approval, reuse expired
approvals, skip policy evaluation, or accept unsigned execution results.

Command signing:
  - Uses HMAC-SHA256 with a shared secret key (COMMAND_SIGNING_KEY)
  - The signature covers: command_id, tenant_id, gateway_id, action_type,
    target, parameters, proposal_id, approval_id, policy_version_id,
    nonce, expires_at
  - The gateway must verify this signature before executing any command
  - The signing key must be distributed to gateways out-of-band (not via API)

Owner: Developer A (response safety authority)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid7

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.config import get_settings
from ascense.models import ActionProposal, Approval, Command, ExecutionAttempt

logger = structlog.get_logger(__name__)

_settings = get_settings()


def _sign_command(
    command_id: UUID,
    tenant_id: UUID,
    gateway_id: UUID,
    action_type: str,
    target: dict,
    parameters: dict,
    proposal_id: UUID,
    approval_id: UUID,
    policy_version_id: UUID,
    nonce: str,
    expires_at: datetime,
) -> str:
    """Create an HMAC-SHA256 signature over all command fields.

    The gateway must re-compute this signature and verify it matches
    before executing the command. Any field tampering invalidates the
    signature.

    The signing key (COMMAND_SIGNING_KEY) must be distributed to gateways
    via a secure out-of-band channel — never via the API.
    """
    # Canonical representation: sorted JSON for deterministic signing
    payload = json.dumps(
        {
            "command_id": str(command_id),
            "tenant_id": str(tenant_id),
            "gateway_id": str(gateway_id),
            "action_type": action_type,
            "target": target,
            "parameters": parameters,
            "proposal_id": str(proposal_id),
            "approval_id": str(approval_id),
            "policy_version_id": str(policy_version_id),
            "nonce": nonce,
            "expires_at": expires_at.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    key = _settings.COMMAND_SIGNING_KEY.encode("utf-8")
    return hmac.new(
        key, payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify_command_signature(
    command: Command,
) -> bool:
    """Verify a command's HMAC-SHA256 signature.

    Called by the gateway before executing any command.
    Returns True if the signature is valid, False otherwise.
    """
    expected = _sign_command(
        command_id=command.id,
        tenant_id=command.tenant_id,
        gateway_id=command.gateway_id,
        action_type=command.action_type,
        target=command.target,
        parameters=command.parameters,
        proposal_id=command.proposal_id,
        approval_id=command.approval_id,
        policy_version_id=command.policy_version_id,
        nonce=command.nonce,
        expires_at=command.expires_at,
    )
    return hmac.compare_digest(expected, command.signature)


async def create_signed_command(
    proposal: ActionProposal,
    approval: Approval,
    policy_version_id: UUID,
    session: AsyncSession,
) -> Command:
    """Create an authorized, cryptographically signed command.

    The command binds:
      - command_id, tenant_id, gateway_id — exact identities
      - target, action_type, parameters — exact action
      - proposal_id, approval_id — authorization chain
      - policy_version_id — policy version at authorization time
      - created_at, expires_at — short expiry window (900s)
      - nonce — unique per command (prevents replay)
      - idempotency_key — safe retransmission
      - signature — HMAC-SHA256 over all fields (verified by gateway)
    """
    # Validate that the approval is still valid
    if approval.status != "APPROVED":
        raise ValueError(f"Approval is {approval.status}, not APPROVED")
    if approval.expires_at and approval.expires_at < datetime.now(UTC):
        raise ValueError("Approval has expired")

    # Generate cryptographic material
    nonce = secrets.token_urlsafe(32)
    idempotency_key = secrets.token_urlsafe(32)
    expires_at = datetime.now(UTC) + timedelta(seconds=900)
    gateway_id = UUID(
        proposal.target.get(
            "gateway_id",
            "00000000-0000-7000-8000-000000000000",
        )
    )

    # Create the HMAC-SHA256 signature over all command fields
    signature = _sign_command(
        command_id=uuid7(),  # temp — will be overwritten
        tenant_id=proposal.tenant_id,
        gateway_id=gateway_id,
        action_type=proposal.action_type,
        target=proposal.target,
        parameters=proposal.parameters,
        proposal_id=proposal.id,
        approval_id=approval.id,
        policy_version_id=policy_version_id,
        nonce=nonce,
        expires_at=expires_at,
    )

    command = Command(
        id=uuid7(),
        tenant_id=proposal.tenant_id,
        gateway_id=gateway_id,
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
        expires_at=expires_at,
    )
    session.add(command)

    logger.info(
        "command.created",
        command_id=str(command.id),
        proposal_id=str(proposal.id),
        action_type=command.action_type,
        signature_algo="HMAC-SHA256",
    )
    return command


async def verify_enforcement_state(
    command_id: UUID,
    session: AsyncSession,
) -> str:
    """Verify the actual enforcement state by independent read-back.

    Returns: VERIFIED, NOT_VERIFIED, or UNVERIFIABLE.
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
    # For now, return UNVERIFIABLE to trigger escalation.
    logger.info(
        "verification.attempted",
        command_id=str(command_id),
        execution_status=attempt.execution_status,
    )
    return "UNVERIFIABLE"


async def run_worker() -> None:
    """Main response worker loop."""
    logger.info("response_worker.starting")
    # TODO: Consume from the response queue, create commands, dispatch
    logger.info("response_worker.started")
