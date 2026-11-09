"""Harden Phase 1 identity and event uniqueness constraints."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006_phase1_identity_integrity"
down_revision: str | None = "0005_merge_heads"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_gateways_id_tenant_id",
        "gateways",
        ["id", "tenant_id"],
    )
    op.create_table(
        "event_ingestion_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source", sa.String(512), nullable=False),
        sa.Column("source_event_id", sa.String(512), nullable=False),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.UniqueConstraint(
            "source",
            "source_event_id",
            name="uq_event_ingestion_keys_source_event_id",
        ),
    )
    op.create_index("ix_event_ingestion_keys_tenant_id", "event_ingestion_keys", ["tenant_id"])
    op.create_foreign_key(
        "fk_gateway_certificates_tenant_id",
        "gateway_certificates",
        "tenants",
        ["tenant_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_gateway_certificates_gateway_tenant",
        "gateway_certificates",
        "gateways",
        ["gateway_id", "tenant_id"],
        ["id", "tenant_id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_gateway_certificates_gateway_tenant",
        "gateway_certificates",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_gateway_certificates_tenant_id",
        "gateway_certificates",
        type_="foreignkey",
    )
    op.drop_table("event_ingestion_keys")
    op.drop_constraint(
        "uq_gateways_id_tenant_id",
        "gateways",
        type_="unique",
    )
