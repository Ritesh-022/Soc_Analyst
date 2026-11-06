"""Asset registry routes.

Public API:
  GET /api/v1/assets — list protected infrastructure
  GET /api/v1/assets/{asset_id} — view asset details and criticality
"""

from __future__ import annotations

import contextlib
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.api.dependencies.auth import get_tenant_id
from ascense.db import get_session
from ascense.models import Asset

router = APIRouter(tags=["Assets"])


@router.get("/api/v1/assets")
async def list_assets(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """List protected infrastructure for the current tenant."""
    tenant_id = await get_tenant_id(request)

    query = select(Asset).where(Asset.tenant_id == tenant_id)
    if cursor:
        with contextlib.suppress(ValueError):
            query = query.where(Asset.id < UUID(cursor))

    query = query.order_by(Asset.id.desc()).limit(limit + 1)
    result = await session.execute(query)
    assets = result.scalars().all()

    has_more = len(assets) > limit
    items = assets[:limit]
    next_cursor = str(items[-1].id) if has_more and items else None

    return {
        "items": [
            {
                "asset_id": str(a.id),
                "tenant_id": str(a.tenant_id),
                "hostname": a.hostname,
                "asset_type": a.asset_type,
                "criticality": a.criticality,
                "environment": a.environment,
                "location": a.location,
                "gateway_id": str(a.gateway_id) if a.gateway_id else None,
                "status": a.status,
                "ip_addresses": a.ip_addresses,
                "created_at": a.created_at.isoformat(),
                "updated_at": a.updated_at.isoformat(),
            }
            for a in items
        ],
        "next_cursor": next_cursor,
    }


@router.get("/api/v1/assets/{asset_id}")
async def get_asset(
    asset_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """View asset details and criticality. 403 if belongs to another tenant."""
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(Asset).where(Asset.id == asset_id)
    )
    asset = result.scalar_one_or_none()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if asset.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied")

    return {
        "asset_id": str(asset.id),
        "tenant_id": str(asset.tenant_id),
        "hostname": asset.hostname,
        "asset_type": asset.asset_type,
        "criticality": asset.criticality,
        "environment": asset.environment,
        "location": asset.location,
        "gateway_id": str(asset.gateway_id) if asset.gateway_id else None,
        "status": asset.status,
        "ip_addresses": asset.ip_addresses,
        "created_at": asset.created_at.isoformat(),
        "updated_at": asset.updated_at.isoformat(),
    }
