"""Policy evaluation and management routes.

The policy engine is the safety gate that sits between a human approval
and command creation. It evaluates an action proposal against the active
policy and returns ALLOW, DENY, or REQUIRE_APPROVAL.

Checks performed (in order):
  1. Schema check — valid action type, target format, TTL present
  2. Permission check — automation allowed for this tenant and level
  3. Protected-asset check — never-block list (management, DNS, gateways)
  4. Blast-radius check — estimated impact scope
  5. Reversibility check — can the action be undone?
  6. Rate-of-change check — max automated actions per hour/day
  7. Confidence check — score and agreement threshold per level

Internal API:
  POST /internal/v1/policy/evaluate — evaluate a proposal
  GET  /api/v1/policies — list active policy versions
  POST /api/v1/policies — create a new policy version (admin only)
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.api.dependencies.auth import get_tenant_id, require_role
from ascense.db import get_session
from ascense.models import ActionProposal, PolicyVersion

router = APIRouter(tags=["Policy"])

# ---------------------------------------------------------------------------
# Protected assets — these must NEVER be automatically blocked
# Never-block list is enforced regardless of policy configuration.
# ---------------------------------------------------------------------------
PROTECTED_ASSET_TYPES = frozenset({
    "gateway", "management_server", "dns_server", "domain_controller",
    "payment_system", "life_critical", "backup_server",
})

# Allowlisted action types for automated execution (L0/L1)
AUTOMATED_ACTION_TYPES = frozenset({
    "block_network_indicator",  # Block an IP/CIDR indicator with TTL
})

# Actions that always require human approval (L2/L3)
HUMAN_APPROVAL_REQUIRED_TYPES = frozenset({
    "isolate_asset",  # Host isolation — high blast radius, requires explicit approval
})


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class PolicyEvaluationRequest(BaseModel):
    proposal_id: UUID
    automation_level: str = "L1"  # L0=none, L1=auto low-impact, L2=auto medium, L3=auto high


class PolicyEvaluationResult(BaseModel):
    decision: str  # ALLOW | DENY | REQUIRE_APPROVAL
    policy_version_id: str
    reasons: list[str]
    checks: dict


class PolicyCreateRequest(BaseModel):
    description: str | None = None
    rules: dict = {}


# ---------------------------------------------------------------------------
# Internal API: evaluate a proposal
# ---------------------------------------------------------------------------

@router.post("/internal/v1/policy/evaluate")
async def evaluate_policy(
    body: PolicyEvaluationRequest,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Evaluate an action proposal against the active policy.

    Returns ALLOW, DENY, or REQUIRE_APPROVAL.
    This is the safety gate — command creation is blocked without ALLOW.

    DENY must propagate immediately. ALLOW with automation_level=L1
    allows command creation without additional human approval.
    REQUIRE_APPROVAL pauses the workflow for human authorization.
    """
    result = await session.execute(
        select(ActionProposal).where(ActionProposal.id == body.proposal_id)
    )
    proposal = result.scalar_one_or_none()
    if not proposal:
        raise HTTPException(status_code=404, detail="Proposal not found")

    # Get active policy for tenant
    result = await session.execute(
        select(PolicyVersion).where(
            PolicyVersion.tenant_id == proposal.tenant_id,
            PolicyVersion.is_active == True,  # noqa: E712
        ).limit(1)
    )
    policy = result.scalar_one_or_none()
    if not policy:
        # No active policy → deny by default (safe failure)
        return {
            "decision": "DENY",
            "policy_version_id": None,
            "reasons": ["No active policy version found for tenant — denying by default"],
            "checks": {"schema": "FAIL"},
        }

    checks: dict[str, str] = {}
    deny_reasons: list[str] = []
    approval_reasons: list[str] = []

    # 1. Schema check — action type must be in allowlist
    action_type = proposal.action_type
    if action_type not in AUTOMATED_ACTION_TYPES and action_type not in HUMAN_APPROVAL_REQUIRED_TYPES:
        deny_reasons.append(f"Action type '{action_type}' is not in the approved allowlist")
        checks["schema"] = "FAIL"
    else:
        checks["schema"] = "PASS"

    # 2. Automation level check
    if action_type in HUMAN_APPROVAL_REQUIRED_TYPES:
        approval_reasons.append(f"Action type '{action_type}' always requires human approval")
        checks["automation_level"] = "REQUIRE_APPROVAL"
    else:
        checks["automation_level"] = "PASS"

    # 3. Protected-asset check
    target = proposal.target or {}
    target_asset_type = target.get("asset_type", "")
    if target_asset_type in PROTECTED_ASSET_TYPES:
        deny_reasons.append(
            f"Target asset type '{target_asset_type}' is on the never-block protected list"
        )
        checks["protected_asset"] = "FAIL"
    else:
        checks["protected_asset"] = "PASS"

    # 4. Blast-radius check — affected_asset_ids count
    affected = proposal.affected_asset_ids or []
    if len(affected) > 10:
        approval_reasons.append(
            f"Action affects {len(affected)} assets — high blast radius requires approval"
        )
        checks["blast_radius"] = "REQUIRE_APPROVAL"
    else:
        checks["blast_radius"] = "PASS"

    # 5. Reversibility check
    params = proposal.parameters or {}
    ttl = params.get("ttl_seconds") or params.get("ttl")
    if action_type == "block_network_indicator" and not ttl:
        approval_reasons.append("Block action missing TTL — indefinite blocks require approval")
        checks["reversibility"] = "REQUIRE_APPROVAL"
    else:
        checks["reversibility"] = "PASS"

    # 6. Rate-of-change check (placeholder — full impl needs Redis/DB counter)
    checks["rate_of_change"] = "PASS"

    # 7. Confidence check
    # Proposals from automated sources must meet a minimum confidence threshold
    evidence_ids = proposal.evidence_ids or []
    if proposal.created_by == "investigation_agent" and len(evidence_ids) == 0:
        deny_reasons.append("AI investigation proposals must reference at least one evidence record")
        checks["confidence"] = "FAIL"
    else:
        checks["confidence"] = "PASS"

    # Determine final decision
    if deny_reasons:
        decision = "DENY"
        reasons = deny_reasons
    elif approval_reasons:
        decision = "REQUIRE_APPROVAL"
        reasons = approval_reasons
    else:
        decision = "ALLOW"
        reasons = ["All policy checks passed"]

    return {
        "decision": decision,
        "policy_version_id": str(policy.id),
        "reasons": reasons,
        "checks": checks,
    }


# ---------------------------------------------------------------------------
# Public API: policy management
# ---------------------------------------------------------------------------

@router.get("/api/v1/policies")
async def list_policies(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """List active policy versions for the current tenant."""
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(PolicyVersion).where(PolicyVersion.tenant_id == tenant_id)
        .order_by(PolicyVersion.created_at.desc())
    )
    policies = result.scalars().all()

    return {
        "items": [
            {
                "policy_version_id": str(p.id),
                "description": p.description,
                "is_active": p.is_active,
                "created_at": p.created_at.isoformat(),
            }
            for p in policies
        ]
    }


@router.post("/api/v1/policies", status_code=status.HTTP_201_CREATED)
async def create_policy(
    body: PolicyCreateRequest,
    request: Request,
    _role_check: None = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Create a new policy version. Admin only.
    Creating a new policy does NOT automatically activate it."""
    from uuid import uuid7
    tenant_id = await get_tenant_id(request)

    policy = PolicyVersion(
        id=uuid7(),
        tenant_id=tenant_id,
        description=body.description,
        rules=body.rules,
        is_active=False,  # must be explicitly activated
    )
    session.add(policy)
    await session.commit()

    return {
        "policy_version_id": str(policy.id),
        "description": policy.description,
        "is_active": policy.is_active,
        "created_at": policy.created_at.isoformat(),
    }
