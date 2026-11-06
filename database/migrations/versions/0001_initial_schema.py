"""Initial schema: tenants, users, gateways, assets, events, detection, response.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-11-06

Creates all tables for the v1 platform. Every tenant-owned table carries
a non-nullable tenant_id column. Cross-tenant access returns 403 at the
API layer and is additionally enforced by the application filtering on
tenant_id in every query.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- Identity and Tenancy ---
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("display_name", sa.String(256)),
        sa.Column("email", sa.String(256)),
        sa.Column("issuer", sa.String(512)),
        sa.Column("subject", sa.String(512)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "memberships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(64), nullable=False, server_default="viewer"),
    )
    op.create_index("ix_memberships_user_id", "memberships", ["user_id"])
    op.create_index("ix_memberships_tenant_id", "memberships", ["tenant_id"])

    # --- Gateway Registry ---
    op.create_table(
        "gateways",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="UNREGISTERED"),
        sa.Column("certificate_fingerprint", sa.String(128)),
        sa.Column("certificate_issued_at", sa.DateTime(timezone=True)),
        sa.Column("certificate_expires_at", sa.DateTime(timezone=True)),
        sa.Column("config_version", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True)),
        sa.Column("enrolled_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_gateways_tenant_id", "gateways", ["tenant_id"])

    op.create_table(
        "enrollment_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("gateway_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("gateways.id", ondelete="SET NULL")),
        sa.Column("token", sa.String(256), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_enrollment_tokens_tenant_id", "enrollment_tokens", ["tenant_id"])

    # --- Asset Registry ---
    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("hostname", sa.String(256)),
        sa.Column("asset_type", sa.String(64), nullable=False),
        sa.Column("criticality", sa.String(32), nullable=False, server_default="medium"),
        sa.Column("environment", sa.String(64)),
        sa.Column("location", sa.String(256)),
        sa.Column("gateway_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("gateways.id", ondelete="SET NULL")),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("ip_addresses", postgresql.JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_assets_tenant_id", "assets", ["tenant_id"])

    # --- Events ---
    op.create_table(
        "events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("source_event_id", sa.String(512), nullable=False),
        sa.Column("source", sa.String(512), nullable=False),
        sa.Column("event_type", sa.String(256), nullable=False),
        sa.Column("gateway_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("gateways.id"), nullable=False),
        sa.Column("sensor_name", sa.String(64), nullable=False),
        sa.Column("sensor_instance_id", sa.String(128), nullable=False),
        sa.Column("event_kind", sa.String(64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("asset_resolution_status", sa.String(32), nullable=False, server_default="UNRESOLVED"),
        sa.Column("source_asset_id", postgresql.UUID(as_uuid=True)),
        sa.Column("destination_asset_id", postgresql.UUID(as_uuid=True)),
        sa.Column("data", postgresql.JSONB, nullable=False),
    )
    op.create_index("ix_events_tenant_id", "events", ["tenant_id"])
    op.create_index("ix_events_source", "events", ["source", "source_event_id"])
    op.create_index("ix_events_observed_at", "events", ["observed_at"])
    op.create_index("ix_events_gateway_id", "events", ["gateway_id"])

    # --- Detection Findings ---
    op.create_table(
        "detection_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("detector_id", sa.String(128), nullable=False),
        sa.Column("detector_version", sa.String(64), nullable=False),
        sa.Column("model_version_id", postgresql.UUID(as_uuid=True)),
        sa.Column("rule_version", sa.String(64)),
        sa.Column("feature_schema_version", sa.String(64)),
        sa.Column("finding_type", sa.String(256), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("risk_score", sa.Integer, nullable=False),
        sa.Column("confidence", sa.Numeric(5, 4)),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("event_ids", postgresql.JSONB, nullable=False, server_default="[]"),
    )
    op.create_index("ix_detection_findings_tenant_id", "detection_findings", ["tenant_id"])

    # --- Incidents (must be before alerts due to FK) ---
    op.create_table(
        "incidents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("title", sa.String(512)),
        sa.Column("severity", sa.String(32)),
        sa.Column("status", sa.String(32), nullable=False, server_default="OPEN"),
        sa.Column("summary", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("alert_ids", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("affected_asset_ids", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("evidence_ids", postgresql.JSONB, nullable=False, server_default="[]"),
    )
    op.create_index("ix_incidents_tenant_id", "incidents", ["tenant_id"])
    op.create_index("ix_incidents_status", "incidents", ["status"])

    # --- Alerts ---
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="SET NULL")),
        sa.Column("alert_type", sa.String(256), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("risk_score", sa.Integer, nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="NEW"),
        sa.Column("summary", sa.Text),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("detection_finding_ids", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("event_ids", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("evidence_ids", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("affected_asset_ids", postgresql.JSONB, nullable=False, server_default="[]"),
    )
    op.create_index("ix_alerts_tenant_id", "alerts", ["tenant_id"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_incident_id", "alerts", ["incident_id"])

    # --- Evidence ---
    op.create_table(
        "evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("event_id", postgresql.UUID(as_uuid=True)),
        sa.Column("evidence_type", sa.String(64), nullable=False),
        sa.Column("storage_reference", sa.String(1024)),
        sa.Column("description", sa.Text),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_evidence_tenant_id", "evidence", ["tenant_id"])

    # --- Response: Proposals ---
    op.create_table(
        "action_proposals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("action_type", sa.String(128), nullable=False),
        sa.Column("target", postgresql.JSONB, nullable=False),
        sa.Column("affected_asset_ids", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("parameters", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("reason", sa.Text),
        sa.Column("evidence_ids", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("policy_version_id", postgresql.UUID(as_uuid=True)),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True)),
        sa.Column("status", sa.String(32), nullable=False, server_default="DRAFT"),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_action_proposals_tenant_id", "action_proposals", ["tenant_id"])
    op.create_index("ix_action_proposals_incident_id", "action_proposals", ["incident_id"])

    # --- Response: Approvals ---
    op.create_table(
        "approvals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("proposal_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("action_proposals.id"), nullable=False),
        sa.Column("decision", sa.String(32), nullable=False),
        sa.Column("reason", sa.Text),
        sa.Column("approver_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("approver_role", sa.String(64)),
        sa.Column("proposal_version", sa.String(64)),
        sa.Column("status", sa.String(32), nullable=False, server_default="PENDING"),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_approvals_tenant_id", "approvals", ["tenant_id"])
    op.create_index("ix_approvals_proposal_id", "approvals", ["proposal_id"])

    # --- Response: Commands ---
    op.create_table(
        "commands",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("gateway_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("gateways.id"), nullable=False),
        sa.Column("action_type", sa.String(128), nullable=False),
        sa.Column("target", postgresql.JSONB, nullable=False),
        sa.Column("parameters", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("proposal_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("action_proposals.id"), nullable=False),
        sa.Column("approval_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("approvals.id"), nullable=False),
        sa.Column("policy_version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="QUEUED"),
        sa.Column("nonce", sa.String(256), nullable=False),
        sa.Column("idempotency_key", sa.String(256), nullable=False),
        sa.Column("signature", sa.Text, nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_commands_tenant_id", "commands", ["tenant_id"])
    op.create_index("ix_commands_gateway_id", "commands", ["gateway_id"])
    op.create_index("ix_commands_status", "commands", ["status"])

    # --- Execution Attempts ---
    op.create_table(
        "execution_attempts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("command_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("commands.id"), nullable=False),
        sa.Column("gateway_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("command_hash", sa.String(128), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("execution_started_at", sa.DateTime(timezone=True)),
        sa.Column("execution_completed_at", sa.DateTime(timezone=True)),
        sa.Column("execution_status", sa.String(32), nullable=False, server_default="NOT_STARTED"),
        sa.Column("verification_status", sa.String(32), nullable=False, server_default="PENDING"),
        sa.Column("observed_enforcement_state", postgresql.JSONB),
        sa.Column("result_reference", sa.String(1024)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_execution_attempts_tenant_id", "execution_attempts", ["tenant_id"])
    op.create_index("ix_execution_attempts_command_id", "execution_attempts", ["command_id"])

    # --- Audit Events (append-only) ---
    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("action", sa.String(256), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("actor_type", sa.String(32), nullable=False),
        sa.Column("target_type", sa.String(64)),
        sa.Column("target_id", postgresql.UUID(as_uuid=True)),
        sa.Column("reason", sa.Text),
        sa.Column("outcome", sa.String(16), nullable=False, server_default="success"),
        sa.Column("trace_id", sa.String(32)),
        sa.Column("metadata", postgresql.JSONB),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_audit_events_tenant_id", "audit_events", ["tenant_id"])
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index("ix_audit_events_occurred_at", "audit_events", ["occurred_at"])

    # --- Policy Versions ---
    op.create_table(
        "policy_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("rules", postgresql.JSONB, nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_policy_versions_tenant_id", "policy_versions", ["tenant_id"])


def downgrade() -> None:
    op.drop_table("policy_versions")
    op.drop_table("audit_events")
    op.drop_table("execution_attempts")
    op.drop_table("commands")
    op.drop_table("approvals")
    op.drop_table("action_proposals")
    op.drop_table("evidence")
    op.drop_table("incidents")
    op.drop_table("alerts")
    op.drop_table("detection_findings")
    op.drop_table("events")
    op.drop_table("assets")
    op.drop_table("enrollment_tokens")
    op.drop_table("gateways")
    op.drop_table("memberships")
    op.drop_table("users")
    op.drop_table("tenants")
