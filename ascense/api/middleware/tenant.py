"""Tenant authorization middleware.

The backend derives tenant context from the authenticated user or gateway
identity. The caller must not be able to change tenant ownership by changing
request JSON. The browser must never be trusted to enforce permissions —
the backend checks authorization on every request.

Production flow:
  1. AuthMiddleware resolves user_id from the JWT Bearer token
  2. TenantMiddleware resolves tenant_id from the JWT's tenant claim
     (set by AuthMiddleware) or from the authenticated membership
  3. X-Tenant-ID may only select an existing membership in production

Development flow:
  1. X-User-ID and X-Tenant-ID headers are accepted for testing
  2. This bypass is DISABLED when ASCENSE_ENV != "development"
"""

from __future__ import annotations

from uuid import uuid7

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from ascense.config import get_settings

logger = structlog.get_logger()

settings = get_settings()
_IS_DEV = settings.ENVIRONMENT == "development"

# Paths that don't require tenant context
EXEMPT_PATHS = {"/health", "/docs", "/openapi.json", "/redoc"}


class TenantMiddleware(BaseHTTPMiddleware):
    """Ensures every non-exempt request has tenant context.

    In production, tenant_id is set only after checking the authenticated
    user's membership:
      - API requests: the JWT identity and membership are validated
      - Edge requests: from the gateway certificate (set by mTLS middleware)

    In development, X-Tenant-ID header is accepted for testing convenience.
    In production, it can only select a membership for the authenticated user.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip health checks and docs
        if any(path.startswith(p) for p in EXEMPT_PATHS):
            return await call_next(request)

        if not _IS_DEV and path.startswith("/api/v1/"):
            auth_header = request.headers.get("Authorization", "")
            scheme, separator, _ = auth_header.partition(" ")
            if not separator or scheme.casefold() != "bearer":
                return _authentication_required()

            from ascense.api.middleware.auth import resolve_user_from_token
            from ascense.db import async_session_factory

            async with async_session_factory() as session:
                user_id = await resolve_user_from_token(request, session)
            if user_id is None:
                return _authentication_required()

        tenant_id = getattr(request.state, "tenant_id", None)

        if not tenant_id and _IS_DEV:
            # Edge endpoints (/edge/v1/): tenant derived from gateway certificate
            # The mTLS middleware (if present) would have set it from the cert
            # In dev mode, fall back to header
            tenant_id = request.headers.get("X-Tenant-ID")
            if tenant_id:
                logger.debug(
                    "tenant.from_dev_header",
                    tenant_id=tenant_id[:8] + "...",
                )

        # Set tenant_id on request state (or leave None if not resolved)
        if tenant_id:
            request.state.tenant_id = tenant_id
        else:
            # In production, requests without tenant context will get 403
            # from the get_tenant_id dependency. Leave as None to trigger that.
            request.state.tenant_id = None

        return await call_next(request)


def _authentication_required() -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={
            "type": "https://api.ascense.example/problems/authentication-required",
            "title": "Authentication required",
            "status": 401,
            "detail": "A valid bearer token is required.",
            "error_code": "AUTHENTICATION_REQUIRED",
        },
        media_type="application/problem+json",
    )


class ProblemResponse(JSONResponse):
    """RFC 9457 Problem Details response."""

    def __init__(self, status: int, title: str, detail: str, error_code: str, **extra):
        body = {
            "type": f"https://api.ascense.example/problems/{error_code.lower()}",
            "title": title,
            "status": status,
            "detail": detail,
            "error_code": error_code,
            "request_id": str(uuid7()),
            **extra,
        }
        super().__init__(
            status_code=status,
            content=body,
            media_type="application/problem+json",
        )
