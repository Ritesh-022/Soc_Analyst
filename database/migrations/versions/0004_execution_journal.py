"""Add execution_journal table for durable gateway-side recording.

Revision ID: 0004_execution_journal
Revises: 0003_events_partitioning
Create Date: 2026-11-06

The execution journal is a durable record that the gateway creates
BEFORE performing any action. On reconnection after a crash, the
gateway reads the journal to determine what was already done and
avoid re-executing.

Idempotency: the gateway checks the journal by idempotency_key.
If a journal entry exists with journal_status COMPLETED, the gateway
does not re-execute.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_execution_journal"
down_revision: Union[str, None] = "0003_events_partitioning"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "execution_journal",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "command_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("commands.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("gateway_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("idempotency_key", sa.String(256), nullable=False, unique=True),
        sa.Column("command_hash", sa.String(128), nullable=False),
        sa.Column("action_type", sa.String(128), nullable=False),
        sa.Column("target", postgresql.JSONB, nullable=False),
        sa.Column("journal_status", sa.String(32), nullable=False, server_default="PENDING"),
        sa.Column("execution_result", postgresql.JSONB),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_execution_journal_command_id", "execution_journal", ["command_id"])
    op.create_index("ix_execution_journal_tenant_id", "execution_journal", ["tenant_id"])
    op.create_index("ix_execution_journal_gateway_id", "execution_journal", ["gateway_id"])
    op.create_index("ix_execution_journal_idempotency_key", "execution_journal", ["idempotency_key"])


def downgrade() -> None:
    op.drop_table("execution_journal")
