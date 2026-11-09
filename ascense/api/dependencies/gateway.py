"""Authenticated gateway identity resolution.

Transport middleware validates the forwarded certificate. This dependency
performs database-backed authorization on the route's existing session so
certificate, gateway, tenant, and tenant-owned writes share one transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import NoReturn
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.api.middleware.mtls import _compute_fingerprint
from ascense.config import get_settings
from ascense.db import get_session, set_tenant_context


@dataclass(frozen=True, slots=True)
class GatewayAuthContext:
    gateway_id: UUID | None
    tenant_id: UUID | None
    certificate_id: UUID | None
    certificate_fingerprint: str | None
    certificate_serial: int | None
    certificate_expires_at: datetime | None


def _reject(detail: str, code: int = status.HTTP_403_FORBIDDEN) -> NoReturn:
    raise HTTPException(status_code=code, detail=detail)


async def get_gateway_context(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> GatewayAuthContext:
    """Resolve and authorize the gateway identity for an edge request."""
    settings = get_settings()
    if settings.is_dev:
        gateway_id = request.headers.get("X-Gateway-ID")
        tenant_id = request.headers.get("X-Tenant-ID")
        if not tenant_id:
            _reject("Gateway and tenant context required.", status.HTTP_401_UNAUTHORIZED)
        try:
            context = GatewayAuthContext(
                gateway_id=UUID(gateway_id) if gateway_id else None,
                tenant_id=UUID(tenant_id),
                certificate_id=None,
                certificate_fingerprint=None,
                certificate_serial=None,
                certificate_expires_at=None,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid development gateway identity.",
            ) from exc
        request.state.gateway_context = context
        request.state.gateway_id = str(context.gateway_id)
        request.state.tenant_id = str(context.tenant_id)
        await set_tenant_context(session, context.tenant_id)
        return context

    cert_der = getattr(request.state, "gateway_certificate_der", None)
    if not isinstance(cert_der, bytes):
        _reject("Authenticated gateway certificate required.", status.HTTP_401_UNAUTHORIZED)

    fingerprint = _compute_fingerprint(cert_der)
    result = await session.execute(
        text(
            """
            SELECT certificate_id, gateway_id, tenant_id,
                   certificate_fingerprint, certificate_expires_at
            FROM authenticate_gateway_certificate(:fingerprint)
            """
        ),
        {"fingerprint": fingerprint},
    )
    row = result.mappings().one_or_none()
    if row is None:
        _reject("Gateway certificate is not authorized.", status.HTTP_401_UNAUTHORIZED)
    certificate_gateway_id = getattr(request.state, "gateway_id", None)
    if certificate_gateway_id != str(row["gateway_id"]):
        _reject("Gateway certificate identity is inconsistent.", status.HTTP_401_UNAUTHORIZED)

    context = GatewayAuthContext(
        gateway_id=row["gateway_id"],
        tenant_id=row["tenant_id"],
        certificate_id=row["certificate_id"],
        certificate_fingerprint=row["certificate_fingerprint"],
        certificate_serial=getattr(request.state, "gateway_cert_serial", None),
        certificate_expires_at=row["certificate_expires_at"],
    )
    request.state.gateway_context = context
    request.state.gateway_id = str(context.gateway_id)
    request.state.tenant_id = str(context.tenant_id)
    await set_tenant_context(session, context.tenant_id)
    return context
