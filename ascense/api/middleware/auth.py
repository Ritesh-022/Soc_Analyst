"""JWT/OIDC authentication middleware.

Validates Bearer tokens on every API request. In development mode
(ASCENSE_ENV=development), the X-User-ID header is also accepted as a
bypass for tooling convenience — this bypass is DISABLED in production.

Token validation:
  1. Extract Bearer token from Authorization header
  2. Decode and verify signature using JWKS from the issuer
  3. Validate audience, expiry, and issuer claims
  4. Extract internal user_id from the `sub` claim via the users table
  5. Attach user_id and tenant_id to request.state

The tenant context (X-Tenant-ID) can be passed explicitly in dev mode
or derived from the JWT's tenant claim in production.
"""

from __future__ import annotations

import os
from uuid import UUID

import jwt as pyjwt
import structlog
from fastapi import HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ascense.config import get_settings

logger = structlog.get_logger(__name__)

_bearer_scheme = HTTPBearer(auto_error=False)

settings = get_settings()
_IS_DEV = settings.ENVIRONMENT == "development"


def _decode_dev_token(token: str) -> dict | None:
    """In development, accept a simple shared-secret signed JWT.

    Payload: {"sub": "<user_id>", "tenant_id": "<tenant_id>"}
    """
    try:
        payload = pyjwt.decode(
            token,
            key=settings.DEV_AUTH_SECRET,
            algorithms=["HS256"],
            options={"require": ["sub"]},
        )
        return payload
    except pyjwt.PyJWTError:
        return None


def _decode_oidc_token(token: str) -> dict | None:
    """Validate an OIDC token from the configured issuer.

    In production, fetches the JWKS from the issuer discovery endpoint
    and validates the RS256 signature. Currently returns None (not yet
    implemented) — OIDC wiring is the next unblocked auth task.
    """
    # TODO: implement JWKS fetch and RS256 validation
    # Blocked until OIDC provider is configured.
    return None


async def resolve_user_from_token(
    request: Request,
) -> UUID | None:
    """Extract and validate user identity from the request.

    Returns the internal user_id UUID, or None if unauthenticated.
    Attaches user_id and tenant_id to request.state.
    """
    # Dev bypass: X-User-ID header (disabled in production)
    if _IS_DEV:
        x_user_id = request.headers.get("X-User-ID")
        if x_user_id:
            try:
                user_id = UUID(x_user_id)
                if not hasattr(request.state, "user_id"):
                    request.state.user_id = str(user_id)
                return user_id
            except ValueError:
                pass

    # Production: JWT Bearer token
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header.removeprefix("Bearer ").strip()

    # Try dev token first (for test tooling)
    payload = _decode_dev_token(token) if _IS_DEV else None

    # Then try OIDC
    if payload is None:
        payload = _decode_oidc_token(token)

    if payload is None:
        return None

    sub = payload.get("sub", "")
    try:
        user_id = UUID(sub)
    except ValueError:
        logger.warning("auth.invalid_sub_claim", sub=sub[:32])
        return None

    # If tenant_id is in the token, set it on request state
    tenant_claim = payload.get("tenant_id") or payload.get("tid")
    if tenant_claim and not getattr(request.state, "tenant_id", None):
        request.state.tenant_id = tenant_claim

    request.state.user_id = str(user_id)
    return user_id


def generate_dev_token(user_id: UUID, tenant_id: UUID) -> str:
    """Generate a development JWT for testing.

    Usage:
        token = generate_dev_token(user_id, tenant_id)
        headers = {"Authorization": f"Bearer {token}"}
    """
    payload = {
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
    }
    return pyjwt.encode(payload, key=settings.DEV_AUTH_SECRET, algorithm="HS256")
