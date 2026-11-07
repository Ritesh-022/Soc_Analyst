"""Seed data for local development.

Creates a test tenant, user, gateway, and sample assets so the platform
can be exercised without external setup.

Run with: python -m database.seeds.seed_dev
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from sqlalchemy import select

from ascense.db import async_session_factory, engine
from ascense.models import Asset, Gateway, Membership, Tenant, User
from ascense.utils.uuid7 import uuid7


async def seed() -> None:
    """Create seed data for development."""
    async with async_session_factory() as session:
        # Check if seed already exists
        existing = await session.execute(select(Tenant).limit(1))
        if existing.scalar_one_or_none():
            print("Seed data already exists — skipping")
            return

        # Create a test tenant
        tenant_id = uuid7()
        tenant = Tenant(id=tenant_id, name="Test Organization")
        session.add(tenant)

        # Create a test user
        user_id = uuid7()
        user = User(
            id=user_id,
            display_name="Test Admin",
            email="admin@test.ascense.example",
        )
        session.add(user)

        # Create membership with admin role
        membership = Membership(
            id=uuid7(),
            user_id=user_id,
            tenant_id=tenant_id,
            role="admin",
        )
        session.add(membership)

        # Create a test gateway
        gateway_id = uuid7()
        gateway = Gateway(
            id=gateway_id,
            tenant_id=tenant_id,
            name="Test Gateway 01",
            status="ACTIVE",
            enrolled_at=datetime.now(UTC),
        )
        session.add(gateway)

        # Create sample assets
        for hostname, ip, crit in [
            ("web-server-01", "192.0.2.10", "high"),
            ("db-server-01", "192.0.2.20", "critical"),
            ("workstation-01", "192.0.2.30", "medium"),
        ]:
            asset = Asset(
                id=uuid7(),
                tenant_id=tenant_id,
                hostname=hostname,
                asset_type="server",
                criticality=crit,
                environment="production",
                gateway_id=gateway_id,
                status="active",
                ip_addresses=[{"address": ip, "first_seen_at": datetime.now(UTC).isoformat()}],
            )
            session.add(asset)

        await session.commit()
        print("Seed data created:")
        print(f"  Tenant ID: {tenant_id}")
        print(f"  User ID:   {user_id}")
        print(f"  Gateway ID: {gateway_id}")
        print(f"  Use X-Tenant-ID header: {tenant_id}")
        print(f"  Use X-User-ID header:   {user_id}")


async def main() -> None:
    await seed()
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
