"""Database session management and base model.

Uses SQLAlchemy 2.0 async with asyncpg. Every tenant-owned query must include
a tenant_id filter — the tenant authorization middleware enforces this at the
API layer, and repository functions accept tenant_id explicitly.

For defense-in-depth, routes that operate on tenant-owned data should use
get_tenant_session() which sets app.tenant_id via SET LOCAL, enabling
PostgreSQL Row-Level Security policies to block cross-tenant access at the
database level.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from uuid import UUID

from fastapi import Request
from sqlalchemy import MetaData
from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from ascense.config import get_settings

# Naming convention for constraints — keeps migrations clean and predictable
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=NAMING_CONVENTION)

engine = create_async_engine(
    get_settings().DATABASE_URL,
    echo=get_settings().DEBUG,
    pool_size=10,
    max_overflow=20,
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Declarative base for all Ascense models."""

    metadata = metadata


class TenantMixin:
    """Mixin for tenant-owned models. Every tenant-owned record must carry
    a tenant_id. Repository functions must filter by tenant_id on every query.
    """

    tenant_id: Mapped[UUID] = mapped_column(
        nullable=False, index=True, doc="Owner tenant — never trusted from caller payload"
    )


async def get_session(
    request: Request,
) -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that provides a database session.

    If middleware has already established a tenant, set the transaction-local
    RLS context before yielding the session. Gateway authentication establishes
    the context after registry authorization because its certificate lookup
    must not trust request headers.
    """
    async with async_session_factory() as session:
        tenant_id = getattr(request.state, "tenant_id", None)
        if tenant_id:
            await session.execute(
                sa_text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
                {"tenant_id": str(tenant_id)},
            )
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_tenant_session(
    request: Request,
) -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that provides a session with RLS tenant context.

    Sets `app.tenant_id` via SET LOCAL so that Row-Level Security policies
    enforce tenant isolation at the database level. This is defense-in-depth:
    even if a query forgets to filter by tenant_id, RLS blocks cross-tenant
    access.

    If tenant_id is not set on the request state (e.g. unauthenticated request),
    no RLS context is established — policies are fail-closed, so queries
    will return zero rows from tenant-owned tables.
    """
    tenant_id = getattr(request.state, "tenant_id", None)
    async with async_session_factory() as session:
        if tenant_id:
            await session.execute(
                sa_text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
                {"tenant_id": str(tenant_id)},
            )
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def set_tenant_context(session: AsyncSession, tenant_id: UUID) -> None:
    """Set the tenant context on a session for worker/background use.

    Workers must call this before processing tenant-scoped data to ensure
    RLS policies are enforced.
    """
    await session.execute(
        sa_text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
        {"tenant_id": str(tenant_id)},
    )
