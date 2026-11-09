"""Event ingestion and search routes.

Edge API: POST /edge/v1/events:batch — gateway sends telemetry batch
Public API: GET /api/v1/events — search normalized events
Public API: GET /api/v1/events/{event_id} — get event details

Deduplication uses (source, id) which maps to
(gateway_id + sensor_instance_id, source_event_id).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from uuid import UUID, uuid7

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.api.dependencies.auth import get_tenant_id
from ascense.api.dependencies.gateway import GatewayAuthContext, get_gateway_context
from ascense.config import get_settings
from ascense.db import get_session
from ascense.models import Event, EventIngestionKey, Outbox

router = APIRouter(tags=["Events"])

# ---------------------------------------------------------------------------
# Allowed event types (explicit allowlist — sensors must not invent categories)
# ---------------------------------------------------------------------------
ALLOWED_EVENT_TYPES = {
    "com.ascense.network.connection.observed.v1",
}

# Allowed sensor names (controlled from approved sensor allowlist)
ALLOWED_SENSOR_NAMES = {"suricata", "zeek"}

# Maximum batch size (number of events per batch)
MAX_BATCH_SIZE = 1000

# Maximum payload size in bytes (10 MB)
MAX_PAYLOAD_BYTES = 10 * 1024 * 1024

# W3C source URN pattern: urn:ascense:gateway:{uuid}/sensor/{instance_id}
SOURCE_URN_PATTERN = re.compile(
    r"^urn:ascense:gateway:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}"
    r"-[89ab][0-9a-f]{3}-[0-9a-f]{12}/sensor/.+$"
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class EventBatchItem(BaseModel):
    """CloudEvents 1.0 envelope for a single event in a batch."""
    specversion: str = Field("1.0", description="CloudEvents spec version")
    id: str = Field(..., description="Unique within source; equals source_event_id")
    source: str = Field(..., description="URN: gateway + sensor instance")
    type: str = Field(..., description="Namespaced event type with version suffix")
    subject: str | None = None
    time: datetime = Field(..., description="Event occurrence time, UTC RFC 3339")
    datacontenttype: str | None = "application/json"
    dataschema: str | None = None
    tenantid: str | None = Field(None, description="Verified against authenticated gateway")
    gatewayid: str | None = Field(None, description="Must match authenticated gateway cert")
    data: dict


class EventBatchResponse(BaseModel):
    batch_id: str
    status: str = "accepted"
    accepted_count: int
    rejected_count: int
    rejections: list[dict] = Field(default_factory=list)
    received_at: datetime


class EventRejection(BaseModel):
    index: int
    code: str
    message: str


class EventRecord(BaseModel):
    event_id: str
    tenant_id: str
    source_event_id: str
    gateway_id: str
    sensor_name: str
    sensor_instance_id: str
    event_kind: str
    observed_at: datetime
    ingested_at: datetime
    asset_resolution_status: str
    data: dict


class EventPage(BaseModel):
    items: list[EventRecord]
    next_cursor: str | None = None


# ---------------------------------------------------------------------------
# Edge API: Event batch ingestion
# ---------------------------------------------------------------------------

@router.post("/edge/v1/events:batch", status_code=status.HTTP_202_ACCEPTED)
async def ingest_event_batch(
    batch: list[EventBatchItem],
    request: Request,
    session: AsyncSession = Depends(get_session),
    gateway_context: GatewayAuthContext = Depends(get_gateway_context),
) -> EventBatchResponse:
    """Accept a batch of events from an authenticated gateway.

    The tenantid and gatewayid extension attributes are verified against
    the authenticated gateway identity — never trusted from the payload alone.
    Deduplication uses (source, id) = (gateway_id + sensor_instance_id, source_event_id).

    A 202 response means the batch was accepted for processing, not that
    detection has completed. Partial acceptance is supported.
    """
    batch_id = str(uuid7())
    accepted = 0
    rejections: list[dict] = []

    authenticated_tenant_id = (
        str(gateway_context.tenant_id)
        if gateway_context.tenant_id
        else None
    )
    authenticated_gateway_id = (
        str(gateway_context.gateway_id)
        if gateway_context.gateway_id
        else None
    )

    # Resolve environment once at the top
    _is_dev = get_settings().is_dev

    # In production, authenticated gateway context is REQUIRED.
    # In dev mode, we fall back to headers for testing.
    if _is_dev:
        tenant_id_str = authenticated_tenant_id or request.headers.get("X-Tenant-ID")
        gateway_id_str = authenticated_gateway_id or request.headers.get("X-Gateway-ID")
    else:
        # Production: authenticated identity ONLY — no payload fallback
        tenant_id_str = authenticated_tenant_id
        gateway_id_str = authenticated_gateway_id

        if not tenant_id_str or not gateway_id_str:
            return EventBatchResponse(
                batch_id=batch_id,
                status="rejected",
                accepted_count=0,
                rejected_count=len(batch),
                rejections=[{
                    "index": 0,
                    "code": "UNAUTHENTICATED",
                    "message": "Authenticated gateway context required for event ingestion.",
                }],
                received_at=datetime.now(UTC),
            )

    # Parse the resolved identities once
    try:
        resolved_tenant_id = UUID(tenant_id_str) if tenant_id_str else None
        resolved_gateway_id = UUID(gateway_id_str) if gateway_id_str else None
    except (ValueError, TypeError):
        return EventBatchResponse(
            batch_id=batch_id,
            status="rejected",
            accepted_count=0,
            rejected_count=len(batch),
            rejections=[{
                "index": 0,
                "code": "UNAUTHENTICATED",
                "message": "Invalid authenticated gateway identity.",
            }],
            received_at=datetime.now(UTC),
        )

    for i, event in enumerate(batch):
        # Validate batch size limit
        if i >= MAX_BATCH_SIZE:
            rejections.append({
                "index": i,
                "code": "EVENT_BATCH_TOO_LARGE",
                "message": f"Batch exceeds maximum size of {MAX_BATCH_SIZE} events.",
            })
            continue

        # Validate CloudEvents spec version
        if event.specversion != "1.0":
            rejections.append({
                "index": i,
                "code": "INVALID_EVENT_SCHEMA",
                "message": f"Unsupported specversion: {event.specversion}",
            })
            continue

        # Validate required fields
        if not event.time:
            rejections.append({
                "index": i,
                "code": "INVALID_EVENT_SCHEMA",
                "message": "Missing required event timestamp.",
            })
            continue

        # Validate event type against allowlist
        if event.type not in ALLOWED_EVENT_TYPES:
            rejections.append({
                "index": i,
                "code": "UNSUPPORTED_EVENT_TYPE",
                "message": f"Event type '{event.type}' is not in the approved allowlist.",
            })
            continue

        # Validate source URN format (must include gateway + sensor instance)
        if not SOURCE_URN_PATTERN.match(event.source):
            rejections.append({
                "index": i,
                "code": "INVALID_EVENT_SCHEMA",
                "message": (
                    "Source must be a valid URN: "
                    "urn:ascense:gateway:{uuid}/sensor/{instance_id}"
                ),
            })
            continue

        # Extract data payload
        data = event.data
        source_event_id = data.get("source_event_id", event.id)
        sensor_info = data.get("sensor", {})
        asset_res = data.get("asset_resolution", {})

        # Validate sensor name against allowlist
        sensor_name = sensor_info.get("name", "")
        if sensor_name not in ALLOWED_SENSOR_NAMES:
            rejections.append({
                "index": i,
                "code": "INVALID_EVENT_SCHEMA",
                "message": f"Sensor '{sensor_name}' is not in the approved sensor allowlist.",
            })
            continue

        # Verify payload identity matches resolved identity whenever one is established.
        # This applies in both dev (X-Gateway-ID header) and production (mTLS cert).
        if resolved_gateway_id and event.gatewayid and event.gatewayid != str(resolved_gateway_id):
            rejections.append({
                "index": i,
                "code": "GATEWAY_ID_MISMATCH",
                "message": "gatewayid in payload does not match the authenticated gateway.",
            })
            continue

        if resolved_tenant_id and event.tenantid and event.tenantid != str(resolved_tenant_id):
            rejections.append({
                "index": i,
                "code": "TENANT_MISMATCH",
                "message": "tenantid in payload does not match the authenticated gateway tenant.",
            })
            continue

        # In production also verify the source URN matches the authenticated gateway
        if (
            not _is_dev
            and resolved_gateway_id
            and not event.source.startswith(
                f"urn:ascense:gateway:{resolved_gateway_id}/"
            )
        ):
            rejections.append({
                "index": i,
                "code": "GATEWAY_ID_MISMATCH",
                "message": "Source URN does not match the authenticated gateway identity.",
            })
            continue

        # Use resolved identities (from authenticated context or dev headers)
        tenant_id = resolved_tenant_id
        gateway_id = resolved_gateway_id

        if not tenant_id or not gateway_id:
            # In dev mode without headers, try payload as last resort
            if _is_dev:
                try:
                    tenant_id = UUID(event.tenantid) if event.tenantid else None
                    gateway_id = UUID(event.gatewayid) if event.gatewayid else None
                except (ValueError, TypeError):
                    pass

            if not tenant_id or not gateway_id:
                rejections.append({
                    "index": i,
                    "code": "UNAUTHENTICATED",
                    "message": "Unable to resolve tenant and gateway identity for this event.",
                })
                continue

        event_id = uuid7()
        key_result = await session.execute(
            insert(EventIngestionKey)
            .values(
                id=uuid7(),
                tenant_id=tenant_id,
                source=event.source,
                source_event_id=source_event_id,
                event_id=event_id,
            )
            .on_conflict_do_nothing(
                index_elements=[
                    EventIngestionKey.source,
                    EventIngestionKey.source_event_id,
                ]
            )
        )
        if key_result.rowcount == 0:
            accepted += 1
            continue

        # Create the normalized event record
        event_record = Event(
            id=event_id,
            tenant_id=tenant_id,
            source_event_id=source_event_id,
            source=event.source,
            event_type=event.type,
            gateway_id=gateway_id,
            sensor_name=sensor_info.get("name", "unknown"),
            sensor_instance_id=sensor_info.get("instance_id", "unknown"),
            event_kind=data.get("event_kind", "network.connection"),
            observed_at=event.time,
            ingested_at=datetime.now(UTC),
            asset_resolution_status=asset_res.get("status", "UNRESOLVED"),
            source_asset_id=(
                UUID(asset_res["source_asset_id"])
                if asset_res.get("source_asset_id") else None
            ),
            destination_asset_id=(
                UUID(asset_res["destination_asset_id"])
                if asset_res.get("destination_asset_id") else None
            ),
            data=data,
        )
        session.add(event_record)

        # Write outbox record in the same transaction (transactional outbox pattern)
        outbox_record = Outbox(
            id=uuid7(),
            tenant_id=tenant_id,
            aggregate_type="event",
            aggregate_id=event_record.id,
            message_type="telemetry.batch.accepted.v1",
            payload={
                "event_id": str(event_record.id),
                "tenant_id": str(tenant_id),
                "event_kind": event_record.event_kind,
                "source": event_record.source,
                "source_event_id": event_record.source_event_id,
                "gateway_id": str(event_record.gateway_id),
                "sensor_name": event_record.sensor_name,
                "sensor_instance_id": event_record.sensor_instance_id,
                "data": data,
            },
        )
        session.add(outbox_record)
        accepted += 1

    await session.commit()

    return EventBatchResponse(
        batch_id=batch_id,
        status="accepted",
        accepted_count=accepted,
        rejected_count=len(rejections),
        rejections=rejections,
        received_at=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# Public API: Event search
# ---------------------------------------------------------------------------

@router.get("/api/v1/events")
async def list_events(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = None,
    event_kind: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Search normalized events. Uses cursor-based pagination."""
    tenant_id = await get_tenant_id(request)

    query = select(Event).where(Event.tenant_id == tenant_id)

    if event_kind:
        query = query.where(Event.event_kind == event_kind)
    if cursor:
        try:
            cursor_id = UUID(cursor)
            query = query.where(Event.id < cursor_id)
        except ValueError:
            pass

    query = query.order_by(Event.id.desc()).limit(limit + 1)
    result = await session.execute(query)
    events = result.scalars().all()

    has_more = len(events) > limit
    items = events[:limit]
    next_cursor = str(items[-1].id) if has_more and items else None

    return {
        "items": [
            {
                "event_id": str(e.id),
                "tenant_id": str(e.tenant_id),
                "source_event_id": e.source_event_id,
                "gateway_id": str(e.gateway_id),
                "sensor_name": e.sensor_name,
                "sensor_instance_id": e.sensor_instance_id,
                "event_kind": e.event_kind,
                "observed_at": e.observed_at.isoformat(),
                "ingested_at": e.ingested_at.isoformat(),
                "asset_resolution_status": e.asset_resolution_status,
                "data": e.data,
            }
            for e in items
        ],
        "next_cursor": next_cursor,
    }


@router.get("/api/v1/events/{event_id}")
async def get_event(
    event_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Get event details. Returns 403 if the event belongs to another tenant."""
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(Event).where(Event.id == event_id)
    )
    event = result.scalar_one_or_none()

    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Cross-tenant access returns 403, not 404
    if event.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied")

    return {
        "event_id": str(event.id),
        "tenant_id": str(event.tenant_id),
        "source_event_id": event.source_event_id,
        "source": event.source,
        "event_type": event.event_type,
        "gateway_id": str(event.gateway_id),
        "sensor_name": event.sensor_name,
        "sensor_instance_id": event.sensor_instance_id,
        "event_kind": event.event_kind,
        "observed_at": event.observed_at.isoformat(),
        "ingested_at": event.ingested_at.isoformat(),
        "asset_resolution_status": event.asset_resolution_status,
        "source_asset_id": (
            str(event.source_asset_id) if event.source_asset_id else None
        ),
        "destination_asset_id": (
            str(event.destination_asset_id)
            if event.destination_asset_id else None
        ),
        "data": event.data,
    }
