"""Add durable detection and alert idempotency keys."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_detection_alert_idempotency"
down_revision: str | None = "0007_phase1_rls"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "detection_findings",
        sa.Column("dedupe_key", sa.String(512), nullable=True),
    )
    op.create_unique_constraint(
        "uq_detection_findings_dedupe_key",
        "detection_findings",
        ["dedupe_key"],
    )
    op.add_column(
        "alerts",
        sa.Column(
            "detection_finding_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
    )
    op.create_foreign_key(
        "fk_alerts_detection_finding_id",
        "alerts",
        "detection_findings",
        ["detection_finding_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_unique_constraint(
        "uq_alerts_detection_finding_id",
        "alerts",
        ["detection_finding_id"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_alerts_detection_finding_id",
        "alerts",
        type_="unique",
    )
    op.drop_constraint(
        "fk_alerts_detection_finding_id",
        "alerts",
        type_="foreignkey",
    )
    op.drop_column("alerts", "detection_finding_id")
    op.drop_constraint(
        "uq_detection_findings_dedupe_key",
        "detection_findings",
        type_="unique",
    )
    op.drop_column("detection_findings", "dedupe_key")
