"""Merge the two 0003 migration heads into a single linear graph.

Revision ID: 0005_merge_heads
Revises: 0003_events_partitioning, 0003_gateway_sensor_status
Create Date: 2026-11-07

Both 0003_events_partitioning and 0003_gateway_sensor_status branched
from 0002_outbox_and_audit. This merge revision depends on both,
creating a single head so that alembic upgrade head works correctly.
"""

from __future__ import annotations

from collections.abc import Sequence

revision: str = "0005_merge_heads"
down_revision: str | None = ("0003_events_partitioning", "0003_gateway_sensor_status")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Merge migration — no schema changes, just joins the two heads
    pass


def downgrade() -> None:
    # Cannot unmerge — this is a merge point
    pass
