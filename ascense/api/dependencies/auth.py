"""Authentication and tenant context dependencies.

The backend derives tenant context from the authenticated user or gateway
identity. The caller must not be able to change tenant ownership by
changing request JSON.

Authentication flow:
  1. Dev mode (ASCENSE_ENV=development): X-User-ID header accepted
  2. Dev/production: Bearer JWT token (HS256 in dev, RS256 via OIDC in prod)
  3. Production only: OIDC RS256 token validated against JWKS endpoint

Use generate_dev_token() from ascense.api.middleware.auth to create
tokens for testing when running without a real OIDC provider.
"""

from __future__ import annotations

from uuid import UUID

import structlog
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.config import get_settings
from ascense.db import get_session
from ascense.models import Membership

logger = structlog.get_logger(__name__)
_settings = get_settings()
_IS_DEV = _settings.ENVIRONMENT == "development"


async def get_current_user_id(
    request: Request,
    x_user_id: str | None = Header(None, alias="X-User-ID"),
) -> UUID:
    """Extract the authenticated user ID from the request.

    Priority order:
      1. request.state.user_id — already resolved by auth middleware (JWT)
      2. X-User-ID header — dev bypass only
      3. 401 Unauthorized
    """
    # Already resolved by JWT middleware
    state_user_id = getattr(request.state, "user_id", None)
    if state_user_id:
        try:
            return UUID(state_user_id)
        except ValueError:
            pass  # fall through to other auth methods

    # Dev bypass: X-User-ID header
    if _IS_DEV and x_user_id:
        try:
            return UUID(x_user_id)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid user ID format in X-User-ID header",
            ) from exc

    # Try Bearer token via auth middleware
    try:
        from ascense.api.middleware.auth import resolve_user_from_token
        user_id = await resolve_user_from_token(request)
        if user_id:
            return user_id
    except Exception:  # noqa: BLE001 — auth middleware failure is non-fatal
        logger.debug("auth.bearer_token_resolution_failed")

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=(
            "Authentication required. "
            "Provide a Bearer token or X-User-ID header (dev only)."
        ),
    )


async def get_tenant_id(request: Request) -> UUID:
    """Extract the tenant context from the request.

    The tenant_id is derived from the authenticated identity, not from
    the request body. The caller must not be able to change tenant
    ownership by changing request JSON.
    """
    tenant_id = getattr(request.state, "tenant_id", None)
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Tenant context required. "
                "Provide X-Tenant-ID header (dev) or a tenant-scoped JWT."
            ),
        )
    try:
        return UUID(tenant_id)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid tenant context",
        ) from exc


async def verify_tenant_membership(
    user_id: UUID = Depends(get_current_user_id),
    tenant_id: UUID = Depends(get_tenant_id),
    session: AsyncSession = Depends(get_session),
) -> None:
    """Verify that the user belongs to the tenant."""
    result = await session.execute(
        select(Membership).where(
            Membership.user_id == user_id,
            Membership.tenant_id == tenant_id,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not a member of this tenant",
        )


def require_role(*roles: str):
    """Dependency factory: user must have one of the specified roles in the tenant."""

    async def check_role(
        user_id: UUID = Depends(get_current_user_id),
        tenant_id: UUID = Depends(get_tenant_id),
        session: AsyncSession = Depends(get_session),
    ) -> None:
        result = await session.execute(
            select(Membership).where(
                Membership.user_id == user_id,
                Membership.tenant_id == tenant_id,
            )
        )
        membership = result.scalar_one_or_none()
        if not membership:
            raise HTTPException(status_code=403, detail="Not a tenant member")
        if membership.role not in roles:
            raise HTTPException(
                status_code=403,
                detail=f"Requires one of roles: {', '.join(roles)}",
            )

    return check_role
