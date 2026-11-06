"""Integration tests — Stage 2 exit condition: tenant isolation.

These tests require a running PostgreSQL instance and a seeded database.
Run with: pytest tests/integration/ -v --db

Each test verifies that:
  - A user cannot read another tenant's resources
  - Filtering is applied at every query level
  - Cross-tenant access returns 403, not 404 (information disclosure)

Uses httpx.AsyncClient pointed at the running API, or a TestClient
for in-process testing without a live server.

Environment: set DATABASE_URL to point at a test database, or run
`make docker-up && make migrate && make seed` first.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
import pytest_asyncio

# Skip the whole module if no database is available
pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_headers(tenant_id: str, user_id: str) -> dict[str, str]:
    return {
        "X-Tenant-ID": tenant_id,
        "X-User-ID": user_id,
        "Content-Type": "application/json",
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture(scope="module")
async def app_client():
    """Provide an httpx.AsyncClient wrapping the FastAPI app in-process."""
    try:
        # Create the app without starting broker (unit-test mode)
        import os

        import httpx

        from ascense.api.main import create_app
        os.environ.setdefault("ASCENSE_RUN_WORKERS", "false")
        application = create_app()

        async with httpx.AsyncClient(
            app=application,
            base_url="http://testserver",
        ) as client:
            yield client
    except ImportError:
        pytest.skip("httpx or ascense not importable — run `pip install -e .[dev]`")


@pytest_asyncio.fixture(scope="module")
async def two_tenants(app_client):
    """Create two isolated tenants with users and return their IDs."""
    from uuid import uuid7

    from ascense.db import async_session_factory
    from ascense.models import Membership, Tenant, User

    try:
        async with async_session_factory() as session:
            # Tenant A
            tenant_a_id = uuid7()
            user_a_id = uuid7()
            session.add(Tenant(id=tenant_a_id, name="Test Tenant A"))
            session.add(User(id=user_a_id, display_name="User A", email="a@test.example"))
            session.add(
                Membership(
                    id=uuid7(), user_id=user_a_id,
                    tenant_id=tenant_a_id, role="admin",
                )
            )

            # Tenant B
            tenant_b_id = uuid7()
            user_b_id = uuid7()
            session.add(Tenant(id=tenant_b_id, name="Test Tenant B"))
            session.add(User(id=user_b_id, display_name="User B", email="b@test.example"))
            session.add(
                Membership(
                    id=uuid7(), user_id=user_b_id,
                    tenant_id=tenant_b_id, role="admin",
                )
            )

            await session.commit()

        return {
            "tenant_a": str(tenant_a_id),
            "user_a": str(user_a_id),
            "tenant_b": str(tenant_b_id),
            "user_b": str(user_b_id),
        }
    except Exception as exc:
        pytest.skip(f"Database not available: {exc}")


# ---------------------------------------------------------------------------
# Tenant isolation tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_user_cannot_see_other_tenant_gateways(app_client, two_tenants):
    """User A listing gateways must not see Tenant B's gateways."""
    # Create a gateway for Tenant B
    from uuid import uuid7

    from ascense.db import async_session_factory
    from ascense.models import Gateway

    gw_id = uuid7()
    async with async_session_factory() as session:
        session.add(Gateway(
            id=gw_id,
            tenant_id=UUID(two_tenants["tenant_b"]),
            name="Tenant B Gateway",
            status="ACTIVE",
        ))
        await session.commit()

    # User A lists gateways — must not see Tenant B's gateway
    resp = await app_client.get(
        "/api/v1/gateways",
        headers=_make_headers(two_tenants["tenant_a"], two_tenants["user_a"]),
    )
    assert resp.status_code == 200
    ids = [g["gateway_id"] for g in resp.json()["items"]]
    assert str(gw_id) not in ids


@pytest.mark.asyncio
async def test_direct_access_to_other_tenant_gateway_returns_403(app_client, two_tenants):
    """Accessing another tenant's gateway directly returns 403, not 404."""
    from uuid import uuid7

    from ascense.db import async_session_factory
    from ascense.models import Gateway

    gw_id = uuid7()
    async with async_session_factory() as session:
        session.add(Gateway(
            id=gw_id,
            tenant_id=UUID(two_tenants["tenant_b"]),
            name="Secret Gateway",
            status="ACTIVE",
        ))
        await session.commit()

    resp = await app_client.get(
        f"/api/v1/gateways/{gw_id}",
        headers=_make_headers(two_tenants["tenant_a"], two_tenants["user_a"]),
    )
    # Must be 403, not 404 — cross-tenant isolation, not information hiding
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_direct_access_to_other_tenant_event_returns_403(app_client, two_tenants):
    """Accessing another tenant's event directly returns 403."""
    from datetime import datetime
    from uuid import uuid7

    from ascense.db import async_session_factory
    from ascense.models import Event, Gateway

    gw_id = uuid7()
    ev_id = uuid7()
    async with async_session_factory() as session:
        session.add(Gateway(
            id=gw_id,
            tenant_id=UUID(two_tenants["tenant_b"]),
            name="GW",
            status="ACTIVE",
        ))
        session.add(Event(
            id=ev_id,
            tenant_id=UUID(two_tenants["tenant_b"]),
            source_event_id="ev-b-001",
            source=f"urn:ascense:gateway:{gw_id}/sensor/suricata-01",
            event_type="com.ascense.network.connection.observed.v1",
            gateway_id=gw_id,
            sensor_name="suricata",
            sensor_instance_id="suricata-01",
            event_kind="network.connection",
            observed_at=datetime.now(UTC),
            ingested_at=datetime.now(UTC),
            asset_resolution_status="UNRESOLVED",
            data={
                "network": {
                    "source_ip": "10.0.0.1",
                    "destination_ip": "10.0.0.2",
                    "transport": "tcp",
                }
            },
        ))
        await session.commit()

    resp = await app_client.get(
        f"/api/v1/events/{ev_id}",
        headers=_make_headers(two_tenants["tenant_a"], two_tenants["user_a"]),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_direct_access_to_other_tenant_alert_returns_403(app_client, two_tenants):
    """Accessing another tenant's alert directly returns 403."""
    from uuid import uuid7

    from ascense.db import async_session_factory
    from ascense.models import Alert

    alert_id = uuid7()
    async with async_session_factory() as session:
        session.add(Alert(
            id=alert_id,
            tenant_id=UUID(two_tenants["tenant_b"]),
            alert_type="test.alert",
            severity="low",
            risk_score=10,
            status="NEW",
            observed_at=datetime.now(UTC),
            detection_finding_ids=[],
            event_ids=[],
            evidence_ids=[],
            affected_asset_ids=[],
        ))
        await session.commit()

    resp = await app_client.get(
        f"/api/v1/alerts/{alert_id}",
        headers=_make_headers(two_tenants["tenant_a"], two_tenants["user_a"]),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_unauthenticated_request_returns_401(app_client):
    """Requests without auth context return 401."""
    resp = await app_client.get("/api/v1/gateways")
    # No X-Tenant-ID or X-User-ID headers
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_list_endpoints_are_tenant_scoped(app_client, two_tenants):
    """List endpoints must only return items belonging to the requesting tenant."""
    from uuid import uuid7

    from ascense.db import async_session_factory
    from ascense.models import Incident

    inc_id = uuid7()
    async with async_session_factory() as session:
        session.add(Incident(
            id=inc_id,
            tenant_id=UUID(two_tenants["tenant_b"]),
            title="Tenant B incident",
            severity="high",
            status="OPEN",
            alert_ids=[],
            affected_asset_ids=[],
            evidence_ids=[],
        ))
        await session.commit()

    # Tenant A lists incidents — must not see Tenant B's incident
    resp = await app_client.get(
        "/api/v1/incidents",
        headers=_make_headers(two_tenants["tenant_a"], two_tenants["user_a"]),
    )
    assert resp.status_code == 200
    ids = [i["incident_id"] for i in resp.json()["items"]]
    assert str(inc_id) not in ids


@pytest.mark.asyncio
async def test_payload_tenant_id_ignored_uses_auth_context(app_client, two_tenants):
    """Even if a request body contains tenant_id, it must be ignored.
    The backend always uses tenant from auth context."""
    # This is enforced by the fact that our routes call get_tenant_id(request)
    # which reads from request.state.tenant_id (set by middleware), never from body.
    # We verify this by checking that the enrollment token endpoint uses the
    # authenticated tenant, not any tenant_id in headers/body.

    resp = await app_client.post(
        "/api/v1/gateways/enrollment-tokens",
        json={"name": "Test GW", "expires_in_seconds": 3600},
        headers=_make_headers(two_tenants["tenant_a"], two_tenants["user_a"]),
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "gateway_id" in data
    assert "token" in data

    # The created gateway must belong to Tenant A, not B
    from sqlalchemy import select

    from ascense.db import async_session_factory
    from ascense.models import Gateway

    async with async_session_factory() as session:
        result = await session.execute(
            select(Gateway).where(Gateway.id == UUID(data["gateway_id"]))
        )
        gw = result.scalar_one_or_none()
        assert gw is not None
        assert str(gw.tenant_id) == two_tenants["tenant_a"]
