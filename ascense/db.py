"""Database session management and base model.

Uses SQLAlchemy 2.0 async with asyncpg. Every tenant-owned query must include
a tenant_id filter — the tenant authorization middleware enforces this at the
API layer, and repository functions accept tenant_id explicitly.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from uuid import UUID

from sqlalchemy import MetaData
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


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that provides a database session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
