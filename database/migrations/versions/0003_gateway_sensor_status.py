"""Add sensor_status column to gateways.

Revision ID: 0003_gateway_sensor_status
Revises: 0002_outbox_and_audit
Create Date: 2026-11-06
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_gateway_sensor_status"
down_revision: Union[str, None] = "0002_outbox_and_audit"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "gateways",
        sa.Column("sensor_status", postgresql.JSONB, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("gateways", "sensor_status")
