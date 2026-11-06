"""Telemetry health monitoring routes.

Tracks gateway and sensor health states. When a customer's sensor process
crashes, Ascense must not show a green status implying no attacks — it must
show that visibility has been lost.

Telemetry health states:
  HEALTHY        — heartbeat current, sensors reporting, events arriving
  DEGRADED       — heartbeat current but one or more sensors not reporting
  DISCONNECTED   — no heartbeat within the expected window
  SENSOR_FAILURE — specific sensor process has stopped or is erroring
  TELEMETRY_STALE — events have not arrived within the expected freshness window
  UNKNOWN        — no baseline established yet
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.api.dependencies.auth import get_tenant_id
from ascense.db import get_session
from ascense.models import Event, Gateway

router = APIRouter(tags=["Telemetry"])

# Health thresholds
HEARTBEAT_STALE_SECONDS = 120  # No heartbeat for 2 minutes → DISCONNECTED
EVENT_STALE_SECONDS = 300  # No events for 5 minutes → TELEMETRY_STALE


async def compute_gateway_health(
    gateway: Gateway, session: AsyncSession
) -> dict:
    """Compute the overall telemetry health status for a gateway.

    A gateway can be ACTIVE while a specific sensor is in SENSOR_FAILURE.
    When sensors stop reporting, the dashboard must show degraded status —
    not a clean environment implying no attacks.
    """
    now = datetime.now(UTC)
    health = {
        "gateway_id": str(gateway.id),
        "gateway_name": gateway.name,
        "gateway_status": gateway.status,
        "overall_status": "UNKNOWN",
        "last_heartbeat_at": (
            gateway.last_heartbeat_at.isoformat()
            if gateway.last_heartbeat_at else None
        ),
        "last_event_at": None,
        "sensors": [],
    }

    # Check heartbeat freshness
    if gateway.last_heartbeat_at:
        heartbeat_age = (now - gateway.last_heartbeat_at).total_seconds()
        if heartbeat_age > HEARTBEAT_STALE_SECONDS:
            health["overall_status"] = "DISCONNECTED"
        elif heartbeat_age > 30:
            health["overall_status"] = "DEGRADED"

    # Check event freshness — get the most recent event for this gateway
    result = await session.execute(
        select(Event.observed_at)
        .where(Event.gateway_id == gateway.id)
        .order_by(desc(Event.observed_at))
        .limit(1)
    )
    last_event_time = result.scalar_one_or_none()

    if last_event_time:
        health["last_event_at"] = last_event_time.isoformat()
        event_age = (now - last_event_time).total_seconds()
        if event_age > EVENT_STALE_SECONDS:
            # Events are stale — this takes precedence
            if health["overall_status"] in ("UNKNOWN", "HEALTHY"):
                health["overall_status"] = "TELEMETRY_STALE"
        else:
            # Events are fresh — only promote to HEALTHY if currently UNKNOWN
            if (
                health["overall_status"] in ("UNKNOWN", "DISCONNECTED")
                and health["overall_status"] == "UNKNOWN"
            ):
                health["overall_status"] = "HEALTHY"

    return health


@router.get("/api/v1/gateways/{gateway_id}/sensors")
async def list_gateway_sensors(
    gateway_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """View installed and active sensors for a gateway. 403 if belongs
    to another tenant."""
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(Gateway).where(Gateway.id == gateway_id)
    )
    gateway = result.scalar_one_or_none()

    if not gateway:
        raise HTTPException(status_code=404, detail="Gateway not found")
    if gateway.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied")

    # In v1, sensor info is derived from events and heartbeats.
    # Query distinct sensors from the events table.
    result = await session.execute(
        select(Event.sensor_name, Event.sensor_instance_id)
        .where(Event.gateway_id == gateway_id)
        .group_by(Event.sensor_name, Event.sensor_instance_id)
    )
    sensor_rows = result.all()

    sensors = []
    for sensor_name, instance_id in sensor_rows:
        # Get last event time for this sensor
        result = await session.execute(
            select(Event.observed_at)
            .where(
                Event.gateway_id == gateway_id,
                Event.sensor_instance_id == instance_id,
            )
            .order_by(desc(Event.observed_at))
            .limit(1)
        )
        last_event_at = result.scalar_one_or_none()

        # Determine sensor status
        now = datetime.now(UTC)
        if last_event_at:
            age = (now - last_event_at).total_seconds()
            if age > EVENT_STALE_SECONDS:
                status = "SENSOR_FAILURE"
            elif age > 60:
                status = "DEGRADED"
            else:
                status = "HEALTHY"
        else:
            status = "UNKNOWN"

        sensors.append({
            "name": sensor_name,
            "instance_id": instance_id,
            "status": status,
            "last_event_at": last_event_at.isoformat() if last_event_at else None,
        })

    return {
        "gateway_id": str(gateway_id),
        "sensors": sensors,
    }


@router.get("/api/v1/gateways/{gateway_id}/telemetry-health")
async def get_telemetry_health(
    gateway_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Get telemetry health status for a gateway. Shows TELEMETRY_STALE
    when events stop arriving, not a clean environment with no alerts."""
    tenant_id = await get_tenant_id(request)

    result = await session.execute(
        select(Gateway).where(Gateway.id == gateway_id)
    )
    gateway = result.scalar_one_or_none()

    if not gateway:
        raise HTTPException(status_code=404, detail="Gateway not found")
    if gateway.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied")

    return await compute_gateway_health(gateway, session)
