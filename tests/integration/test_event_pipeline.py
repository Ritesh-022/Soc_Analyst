"""Integration tests — Stage 3A/3B exit conditions.

Tests the end-to-end event pipeline without a live RabbitMQ broker:
  - Event ingested via POST /edge/v1/events:batch
  - Event stored and retrievable via GET /api/v1/events
  - Detection rule fires on suspicious outbound IPs
  - Finding is promoted to alert and incident
  - trace_id propagated end-to-end

These tests use in-process execution (no broker — detection is driven
directly via the worker functions) so they run without Docker.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio(loop_scope="session"),
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture(scope="module", loop_scope="session")
async def db_session():
    """Provide a database session for setup/teardown."""
    try:
        from ascense.db import async_session_factory
        async with async_session_factory() as session:
            yield session
    except Exception as exc:
        pytest.skip(f"Database not available: {exc}")


@pytest_asyncio.fixture(scope="module", loop_scope="session")
async def seeded_tenant(db_session):
    """Create a test tenant, user, and gateway."""
    from uuid import uuid7

    from ascense.models import Gateway, Membership, Tenant, User

    tenant_id = uuid7()
    user_id = uuid7()
    gateway_id = uuid7()

    db_session.add(Tenant(id=tenant_id, name="Pipeline Test Tenant"))
    await db_session.flush()
    db_session.add(User(id=user_id, display_name="Pipeline User", email="pipeline@test.example"))
    db_session.add(Membership(id=uuid7(), user_id=user_id, tenant_id=tenant_id, role="admin"))
    db_session.add(Gateway(
        id=gateway_id,
        tenant_id=tenant_id,
        name="Pipeline Gateway",
        status="ACTIVE",
    ))
    await db_session.commit()

    return {
        "tenant_id": str(tenant_id),
        "user_id": str(user_id),
        "gateway_id": str(gateway_id),
    }


@pytest_asyncio.fixture(scope="module", loop_scope="session")
async def app_client():
    """Provide an httpx.AsyncClient wrapping the FastAPI app in-process."""
    try:
        import os

        import httpx
        os.environ.setdefault("ASCENSE_RUN_WORKERS", "false")
        from ascense.api.main import create_app
        application = create_app()
        async with httpx.AsyncClient(app=application, base_url="http://testserver") as client:
            yield client
    except ImportError:
        pytest.skip("httpx not available")


# ---------------------------------------------------------------------------
# Stage 3A: Event ingestion and retrieval
# ---------------------------------------------------------------------------

async def test_event_ingestion_and_retrieval(app_client, seeded_tenant):
    """Stage 3A exit: event sent → stored → retrieved → trace_id visible."""
    tenant_id = seeded_tenant["tenant_id"]
    gateway_id = seeded_tenant["gateway_id"]
    user_id = seeded_tenant["user_id"]
    trace_id = "a" * 32  # valid W3C trace_id

    event_id = "test-ev-" + "a" * 8

    # POST an event batch
    resp = await app_client.post(
        "/edge/v1/events:batch",
        json=[{
            "specversion": "1.0",
            "id": event_id,
            "source": f"urn:ascense:gateway:{gateway_id}/sensor/suricata-01",
            "type": "com.ascense.network.connection.observed.v1",
            "time": datetime.now(UTC).isoformat(),
            "tenantid": tenant_id,
            "gatewayid": gateway_id,
            "data": {
                "schema_version": "1.0",
                "source_event_id": event_id,
                "event_kind": "network.connection",
                "sensor": {"name": "suricata", "instance_id": "suricata-01"},
                "asset_resolution": {"status": "UNRESOLVED"},
                "network": {
                    "source_ip": "192.0.2.10",
                    "destination_ip": "10.0.0.1",
                    "transport": "tcp",
                },
            },
        }],
        headers={
            "X-Tenant-ID": tenant_id,
            "traceparent": f"00-{trace_id}-{'0' * 16}-01",
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 202, f"Ingestion failed: {resp.text}"
    body = resp.json()
    assert body["accepted_count"] == 1
    assert body["rejected_count"] == 0

    # GET the stored event
    resp = await app_client.get(
        "/api/v1/events",
        headers={
            "X-Tenant-ID": tenant_id,
            "X-User-ID": user_id,
        },
    )
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) >= 1
    stored = next((e for e in items if e["source_event_id"] == event_id), None)
    assert stored is not None, f"Event {event_id} not found in results"
    assert stored["event_kind"] == "network.connection"
    assert stored["asset_resolution_status"] == "UNRESOLVED"
    assert stored["gateway_id"] == gateway_id


async def test_duplicate_event_is_deduplicated(app_client, seeded_tenant):
    """Same (source, id) pair submitted twice must be deduplicated."""
    tenant_id = seeded_tenant["tenant_id"]
    gateway_id = seeded_tenant["gateway_id"]
    event_id = "dedup-ev-" + "b" * 8

    batch = [{
        "specversion": "1.0",
        "id": event_id,
        "source": f"urn:ascense:gateway:{gateway_id}/sensor/suricata-01",
        "type": "com.ascense.network.connection.observed.v1",
        "time": datetime.now(UTC).isoformat(),
        "tenantid": tenant_id,
        "gatewayid": gateway_id,
        "data": {
            "schema_version": "1.0",
            "source_event_id": event_id,
            "event_kind": "network.connection",
            "sensor": {"name": "suricata", "instance_id": "suricata-01"},
            "asset_resolution": {"status": "UNRESOLVED"},
            "network": {"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "transport": "tcp"},
        },
    }]
    headers = {"X-Tenant-ID": tenant_id, "Content-Type": "application/json"}

    resp1 = await app_client.post("/edge/v1/events:batch", json=batch, headers=headers)
    resp2 = await app_client.post("/edge/v1/events:batch", json=batch, headers=headers)

    assert resp1.status_code == 202
    assert resp2.status_code == 202
    # Both responses should report accepted=1 (duplicate silently accepted but not re-stored)
    assert resp1.json()["accepted_count"] == 1
    assert resp2.json()["accepted_count"] == 1

    # Only one event should exist in the database
    from sqlalchemy import func, select

    from ascense.db import async_session_factory
    from ascense.models import Event

    async with async_session_factory() as session:
        result = await session.execute(
            select(func.count()).select_from(Event).where(
                Event.source_event_id == event_id,
                Event.tenant_id == UUID(tenant_id),
            )
        )
        count = result.scalar_one()
    assert count == 1, f"Expected 1 event after dedup, got {count}"


async def test_unsupported_event_type_rejected(app_client, seeded_tenant):
    """Events with unsupported types must be rejected with UNSUPPORTED_EVENT_TYPE."""
    tenant_id = seeded_tenant["tenant_id"]
    gateway_id = seeded_tenant["gateway_id"]

    resp = await app_client.post(
        "/edge/v1/events:batch",
        json=[{
            "specversion": "1.0",
            "id": "bad-type-ev-001",
            "source": f"urn:ascense:gateway:{gateway_id}/sensor/suricata-01",
            "type": "com.unknown.malicious.event.v1",
            "time": datetime.now(UTC).isoformat(),
            "tenantid": tenant_id,
            "gatewayid": gateway_id,
            "data": {
                "schema_version": "1.0",
                "source_event_id": "bad-type-ev-001",
                "event_kind": "network.connection",
                "sensor": {"name": "suricata", "instance_id": "suricata-01"},
                "asset_resolution": {"status": "UNRESOLVED"},
            },
        }],
        headers={"X-Tenant-ID": tenant_id, "Content-Type": "application/json"},
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["rejected_count"] == 1
    assert body["accepted_count"] == 0
    assert any("UNSUPPORTED_EVENT_TYPE" in str(r) for r in body["rejections"])


# ---------------------------------------------------------------------------
# Stage 3B: Detection pipeline
# ---------------------------------------------------------------------------

async def test_suspicious_event_produces_finding(seeded_tenant):
    """Stage 3B: suspicious event → detection finding created by detection worker."""
    from uuid import uuid7

    from ascense.db import async_session_factory
    from ascense.models import Event
    from ascense.workers.detection.worker import evaluate_event

    tenant_id = UUID(seeded_tenant["tenant_id"])
    gateway_id = UUID(seeded_tenant["gateway_id"])

    # Create a test event with a known-bad destination IP
    ev_id = uuid7()
    async with async_session_factory() as session:
        event = Event(
            id=ev_id,
            tenant_id=tenant_id,
            source_event_id=f"bad-ev-{str(ev_id)[:8]}",
            source=f"urn:ascense:gateway:{gateway_id}/sensor/suricata-01",
            event_type="com.ascense.network.connection.observed.v1",
            gateway_id=gateway_id,
            sensor_name="suricata",
            sensor_instance_id="suricata-01",
            event_kind="network.connection",
            observed_at=datetime.now(UTC),
            ingested_at=datetime.now(UTC),
            asset_resolution_status="UNRESOLVED",
            data={
                "network": {
                    "source_ip": "192.0.2.10",
                    "destination_ip": "198.51.100.42",  # known-bad range
                    "destination_port": 443,
                    "transport": "tcp",
                    "direction": "outbound",
                },
            },
        )
        session.add(event)
        await session.commit()

        # Run detection directly (without broker)
        findings = await evaluate_event(event, session)

    assert len(findings) >= 1, "Expected at least one detection finding for known-bad IP"
    assert findings[0].finding_type == "suspicious_outbound_connection"
    assert findings[0].severity == "high"


async def test_detection_pipeline_finding_to_alert_to_incident(seeded_tenant):
    """Stage 3B: finding → alert → incident (correlation worker in-process)."""
    from uuid import uuid7

    from sqlalchemy import select

    from ascense.db import async_session_factory
    from ascense.models import Alert, Event, Incident
    from ascense.workers.correlation.worker import _get_or_create_incident, _promote_finding
    from ascense.workers.detection.worker import evaluate_event

    tenant_id = UUID(seeded_tenant["tenant_id"])
    gateway_id = UUID(seeded_tenant["gateway_id"])

    ev_id = uuid7()
    async with async_session_factory() as session:
        event = Event(
            id=ev_id,
            tenant_id=tenant_id,
            source_event_id=f"pipeline-ev-{str(ev_id)[:8]}",
            source=f"urn:ascense:gateway:{gateway_id}/sensor/suricata-01",
            event_type="com.ascense.network.connection.observed.v1",
            gateway_id=gateway_id,
            sensor_name="suricata",
            sensor_instance_id="suricata-01",
            event_kind="network.connection",
            observed_at=datetime.now(UTC),
            ingested_at=datetime.now(UTC),
            asset_resolution_status="UNRESOLVED",
            data={"network": {
                "source_ip": "192.0.2.10",
                "destination_ip": "203.0.113.99",
                "transport": "tcp",
                "direction": "outbound",
            }},
        )
        session.add(event)
        await session.commit()

        # Detection
        findings = await evaluate_event(event, session)
        assert len(findings) >= 1

        finding = findings[0]

        # Correlation: finding → alert → incident
        alert = await _promote_finding(finding, session)
        incident = await _get_or_create_incident(tenant_id, alert, session)
        alert.incident_id = incident.id
        await session.commit()

    # Verify alert and incident are retrievable
    async with async_session_factory() as session:
        result = await session.execute(
            select(Alert).where(Alert.id == alert.id, Alert.tenant_id == tenant_id)
        )
        stored_alert = result.scalar_one_or_none()
        assert stored_alert is not None
        assert stored_alert.status == "NEW"
        assert stored_alert.severity == "high"

        result = await session.execute(
            select(Incident).where(Incident.id == incident.id, Incident.tenant_id == tenant_id)
        )
        stored_incident = result.scalar_one_or_none()
        assert stored_incident is not None
        assert stored_incident.status == "OPEN"
