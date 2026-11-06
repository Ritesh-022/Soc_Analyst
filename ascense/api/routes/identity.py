"""Identity and tenant context routes.

Public API:
  GET /api/v1/me — return current authenticated user and memberships
  GET /api/v1/tenants/current — get active tenant context
  GET /api/v1/tenants/current/memberships — view tenant users and roles

The backend derives tenant context from the authenticated user identity.
The caller must not be able to change tenant ownership by changing
request JSON.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.api.dependencies.auth import get_current_user_id, get_tenant_id
from ascense.db import get_session
from ascense.models import Membership, Tenant, User

router = APIRouter(tags=["Identity"])


class CurrentUser(BaseModel):
    user_id: str
    display_name: str | None = None
    email: str | None = None
    issuer: str | None = None
    subject: str | None = None
    memberships: list[dict] = []


class TenantResponse(BaseModel):
    tenant_id: str
    name: str
    created_at: str


@router.get("/api/v1/me")
async def get_current_user(
    user_id: UUID = Depends(get_current_user_id),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Return current authenticated user and memberships."""
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Load memberships with tenant info
    result = await session.execute(
        select(Membership, Tenant)
        .join(Tenant, Membership.tenant_id == Tenant.id)
        .where(Membership.user_id == user_id)
    )
    rows = result.all()

    memberships = [
        {
            "tenant_id": str(membership.tenant_id),
            "tenant_name": tenant.name,
            "role": membership.role,
        }
        for membership, tenant in rows
    ]

    return {
        "user_id": str(user.id),
        "display_name": user.display_name,
        "email": user.email,
        "issuer": user.issuer,
        "subject": user.subject,
        "memberships": memberships,
    }


@router.get("/api/v1/tenants/current")
async def get_current_tenant(
    request: Request,
    user_id: UUID = Depends(get_current_user_id),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Get active tenant context. Tenant is derived from authenticated
    identity, not from request body."""
    tenant_id = await get_tenant_id(request)

    result = await session.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    # Verify membership
    result = await session.execute(
        select(Membership).where(
            Membership.user_id == user_id,
            Membership.tenant_id == tenant_id,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=403, detail="Not a member of this tenant")

    return {
        "tenant_id": str(tenant.id),
        "name": tenant.name,
        "created_at": tenant.created_at.isoformat(),
    }


@router.get("/api/v1/tenants/current/memberships")
async def list_tenant_memberships(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """View tenant users and their roles."""
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(Membership, User)
        .join(User, Membership.user_id == User.id)
        .where(Membership.tenant_id == tenant_id)
    )
    rows = result.all()

    return {
        "items": [
            {
                "membership_id": str(membership.id),
                "user_id": str(user.id),
                "display_name": user.display_name,
                "email": user.email,
                "role": membership.role,
            }
            for membership, user in rows
        ]
    }
