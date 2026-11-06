"""Add outbox table and gateway certificate table.

Revision ID: 0002_outbox_and_audit
Revises: 0001_initial_schema
Create Date: 2026-11-06

The outbox table implements the transactional outbox pattern:
ingestion writes the event and an outbox record in the same database
transaction. A publisher worker reads pending outbox records and
publishes them to RabbitMQ, then marks each record as published.

Design for at-least-once delivery. Duplicate delivery is expected and
handled safely by idempotent consumers.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_outbox_and_audit"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- Transactional outbox ---
    # Ingestion writes event + outbox record in the same transaction.
    # Publisher worker reads pending records, publishes to RabbitMQ,
    # marks as published. Failed messages retry; repeated failures go to DLQ.
    op.create_table(
        "outbox",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("aggregate_type", sa.String(64), nullable=False,
                  comment="e.g. 'event', 'detection_finding', 'alert', 'incident'"),
        sa.Column("aggregate_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("message_type", sa.String(128), nullable=False,
                  comment="e.g. 'telemetry.event.normalized.v1'"),
        sa.Column("payload", postgresql.JSONB, nullable=False),
        sa.Column("trace_id", sa.String(32)),
        sa.Column("published", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("retry_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("next_retry_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_outbox_published", "outbox", ["published"])
    op.create_index("ix_outbox_next_retry_at", "outbox", ["next_retry_at"])
    op.create_index("ix_outbox_tenant_id", "outbox", ["tenant_id"])

    # --- Gateway certificate table (separate from gateway for rotation lifecycle) ---
    op.create_table(
        "gateway_certificates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("gateway_id", postgresql.UUID(as_uuid=True),
                   sa.ForeignKey("gateways.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("fingerprint", sa.String(128), nullable=False, unique=True),
        sa.Column("certificate_pem", sa.Text, nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True),
                   comment="Non-null when certificate has been revoked"),
        sa.Column("status", sa.String(32), nullable=False, server_default="ACTIVE",
                   comment="ACTIVE, EXPIRED, REVOKED"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_gateway_certificates_gateway_id", "gateway_certificates", ["gateway_id"])
    op.create_index("ix_gateway_certificates_status", "gateway_certificates", ["status"])


def downgrade() -> None:
    op.drop_table("gateway_certificates")
    op.drop_table("outbox")
