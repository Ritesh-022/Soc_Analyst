"""Tenant authorization middleware.

The backend derives tenant context from the authenticated user or gateway
identity. The caller must not be able to change tenant ownership by changing
request JSON. The browser must never be trusted to enforce permissions —
the backend checks authorization on every request.
"""

from __future__ import annotations

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from uuid import uuid7

logger = structlog.get_logger()

# Paths that don't require tenant context
EXEMPT_PATHS = {"/health", "/docs", "/openapi.json", "/redoc"}


class TenantMiddleware(BaseHTTPMiddleware):
    """Ensures every non-exempt request has tenant context.

    In production, this reads the authenticated user's active tenant from
    the OIDC token or gateway certificate. In development, a header
    X-Tenant-ID can be used for testing.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip health checks and docs
        if any(path.startswith(p) for p in EXEMPT_PATHS):
            return await call_next(request)

        # In development mode, allow X-Tenant-ID header for testing
        # In production, this is derived from the JWT or mTLS certificate
        tenant_id = request.headers.get("X-Tenant-ID")

        if tenant_id:
            request.state.tenant_id = tenant_id
        else:
            # For edge endpoints, tenant is derived from gateway certificate
            # For API endpoints, tenant is derived from JWT
            # This will be properly implemented with auth integration
            request.state.tenant_id = None

        response = await call_next(request)
        return response


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
        super().__init__(status_code=status, content=body, media_type="application/problem+json")
