"""SQLAlchemy models for all Ascense entities.

Domain ownership structure (from docs/03_MODULE_OWNERSHIP.md):

    Tenant
     ├── Users / Memberships
     ├── Gateways
     │    ├── Certificates
     │    ├── Sensors
     │    └── Configurations
     ├── Assets
     ├── Events (source events + normalized events)
     ├── Detection Findings
     │    └── Alerts
     │          └── Incidents
     │                ├── Evidence
     │                ├── Investigations
     │                └── Proposals
     │                      └── Approvals
     │                            └── Commands
     │                                  └── Execution Attempts
     └── Audit Records

PostgreSQL holds authoritative metadata. Large evidence objects live in
object storage; PostgreSQL holds their references and access controls.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ascense.db import Base, TenantMixin

# ---------------------------------------------------------------------------
# Identity and Tenancy
# ---------------------------------------------------------------------------

class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    memberships: Mapped[list[Membership]] = relationship(back_populates="tenant")


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    display_name: Mapped[str | None] = mapped_column(String(256))
    email: Mapped[str | None] = mapped_column(String(256), index=True)
    issuer: Mapped[str | None] = mapped_column(String(512))
    subject: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    memberships: Mapped[list[Membership]] = relationship(back_populates="user")


class Membership(Base):
    __tablename__ = "memberships"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(64), nullable=False, default="viewer")

    user: Mapped[User] = relationship(back_populates="memberships")
    tenant: Mapped[Tenant] = relationship(back_populates="memberships")


# ---------------------------------------------------------------------------
# Gateway Registry
# ---------------------------------------------------------------------------

class Gateway(Base, TenantMixin):
    __tablename__ = "gateways"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="UNREGISTERED")
    certificate_fingerprint: Mapped[str | None] = mapped_column(String(128))
    certificate_issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    certificate_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    config_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sensor_status: Mapped[list | None] = mapped_column(JSONB)
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class EnrollmentToken(Base, TenantMixin):
    __tablename__ = "enrollment_tokens"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    gateway_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("gateways.id", ondelete="SET NULL")
    )
    token: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


# ---------------------------------------------------------------------------
# Asset Registry
# ---------------------------------------------------------------------------

class Asset(Base, TenantMixin):
    __tablename__ = "assets"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    hostname: Mapped[str | None] = mapped_column(String(256))
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False)
    criticality: Mapped[str] = mapped_column(String(32), nullable=False, default="medium")
    environment: Mapped[str | None] = mapped_column(String(64))
    location: Mapped[str | None] = mapped_column(String(256))
    gateway_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("gateways.id", ondelete="SET NULL")
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    ip_addresses: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

class Event(Base, TenantMixin):
    """Normalized event record. The event_id is Ascense's internal identifier,
    distinct from source_event_id which is preserved from the sensor.
    Deduplication uses (source, id) = (gateway_id + sensor_instance_id, source_event_id).
    """

    __tablename__ = "events"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    source_event_id: Mapped[str] = mapped_column(String(512), nullable=False)
    source: Mapped[str] = mapped_column(String(512), nullable=False)
    event_type: Mapped[str] = mapped_column(String(256), nullable=False)
    gateway_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("gateways.id"), nullable=False
    )
    sensor_name: Mapped[str] = mapped_column(String(64), nullable=False)
    sensor_instance_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    asset_resolution_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="UNRESOLVED"
    )
    source_asset_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    destination_asset_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    data: Mapped[dict] = mapped_column(JSONB, nullable=False)

    # Deduplication constraint: one event per (source, id) pair
    __table_args__ = (
        # Unique constraint on (source, source_event_id) for deduplication
        # Using a unique index instead of a constraint since source is a URN string
    )


# ---------------------------------------------------------------------------
# Detection Findings → Alerts → Incidents
# ---------------------------------------------------------------------------

class DetectionFinding(Base, TenantMixin):
    __tablename__ = "detection_findings"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    detector_id: Mapped[str] = mapped_column(String(128), nullable=False)
    detector_version: Mapped[str] = mapped_column(String(64), nullable=False)
    model_version_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    rule_version: Mapped[str | None] = mapped_column(String(64))
    feature_schema_version: Mapped[str | None] = mapped_column(String(64))
    finding_type: Mapped[str] = mapped_column(String(256), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    confidence: Mapped[float | None] = mapped_column(Numeric(5, 4))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    event_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)


class Alert(Base, TenantMixin):
    __tablename__ = "alerts"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    incident_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL")
    )
    alert_type: Mapped[str] = mapped_column(String(256), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="NEW")
    summary: Mapped[str | None] = mapped_column(Text)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    detection_finding_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    event_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    evidence_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    affected_asset_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)


class Incident(Base, TenantMixin):
    __tablename__ = "incidents"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    title: Mapped[str | None] = mapped_column(String(512))
    severity: Mapped[str | None] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="OPEN")
    summary: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    alert_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    affected_asset_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    evidence_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

class Evidence(Base, TenantMixin):
    __tablename__ = "evidence"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    event_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_reference: Mapped[str | None] = mapped_column(String(1024))
    description: Mapped[str | None] = mapped_column(Text)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


# ---------------------------------------------------------------------------
# Response workflow: Proposal → Approval → Command → Execution
# ---------------------------------------------------------------------------

class ActionProposal(Base, TenantMixin):
    __tablename__ = "action_proposals"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    incident_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id"), nullable=False
    )
    action_type: Mapped[str] = mapped_column(String(128), nullable=False)
    target: Mapped[dict] = mapped_column(JSONB, nullable=False)
    affected_asset_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    parameters: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    reason: Mapped[str | None] = mapped_column(Text)
    evidence_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    policy_version_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    created_by: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by_user_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="DRAFT")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class Approval(Base, TenantMixin):
    __tablename__ = "approvals"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    proposal_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("action_proposals.id"), nullable=False
    )
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    approver_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    approver_role: Mapped[str | None] = mapped_column(String(64))
    proposal_version: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class Command(Base, TenantMixin):
    __tablename__ = "commands"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    gateway_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("gateways.id"), nullable=False
    )
    action_type: Mapped[str] = mapped_column(String(128), nullable=False)
    target: Mapped[dict] = mapped_column(JSONB, nullable=False)
    parameters: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    proposal_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("action_proposals.id"), nullable=False
    )
    approval_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("approvals.id"), nullable=False
    )
    policy_version_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="QUEUED")
    nonce: Mapped[str] = mapped_column(String(256), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(256), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ExecutionAttempt(Base, TenantMixin):
    """Execution status and verification status are separate fields.
    Only the gateway sets execution_status. Only the response verification
    service sets verification_status.
    """

    __tablename__ = "execution_attempts"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    command_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("commands.id"), nullable=False
    )
    gateway_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    command_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    execution_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    execution_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    execution_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="NOT_STARTED"
    )
    verification_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="PENDING"
    )
    observed_enforcement_state: Mapped[dict | None] = mapped_column(JSONB)
    result_reference: Mapped[str | None] = mapped_column(String(1024))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


# ---------------------------------------------------------------------------
# Audit Log (append-only, independently protected)
# ---------------------------------------------------------------------------

class AuditEvent(Base, TenantMixin):
    __tablename__ = "audit_events"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    action: Mapped[str] = mapped_column(String(256), nullable=False)
    actor_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True))
    reason: Mapped[str | None] = mapped_column(Text)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="success")
    trace_id: Mapped[str | None] = mapped_column(String(32))
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSONB)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


# ---------------------------------------------------------------------------
# Policy Registry
# ---------------------------------------------------------------------------

class PolicyVersion(Base, TenantMixin):
    __tablename__ = "policy_versions"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    description: Mapped[str | None] = mapped_column(Text)
    rules: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


# ---------------------------------------------------------------------------
# Execution Journal (gateway-side, durable record before action)
# ---------------------------------------------------------------------------

class ExecutionJournal(Base):
    """Durable record created BEFORE the gateway performs any action.

    The gateway writes this record before executing a command. On
    reconnection after a crash, the gateway reads the journal to
    determine what was already done and avoid re-executing.

    Idempotency: the gateway checks this journal by idempotency_key
    before executing. If a journal entry exists with execution_status
    SUCCEEDED, the gateway does not re-execute.
    """

    __tablename__ = "execution_journal"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    command_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("commands.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    gateway_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    idempotency_key: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    command_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    action_type: Mapped[str] = mapped_column(String(128), nullable=False)
    target: Mapped[dict] = mapped_column(JSONB, nullable=False)
    # Status of the journal entry, not the execution attempt
    # PENDING -> EXECUTING -> COMPLETED / FAILED / ROLLED_BACK
    journal_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="PENDING"
    )
    # What the gateway actually did
    execution_result: Mapped[dict | None] = mapped_column(JSONB)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

class Outbox(Base):
    """Outbox record written in the same transaction as the event.
    The publisher worker reads pending records and publishes to RabbitMQ.
    Design for at-least-once delivery — duplicate delivery is expected.
    """

    __tablename__ = "outbox"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    aggregate_type: Mapped[str] = mapped_column(String(64), nullable=False)
    aggregate_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    message_type: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    trace_id: Mapped[str | None] = mapped_column(String(32))
    published: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


# ---------------------------------------------------------------------------
# Gateway Certificate (separate from Gateway for rotation lifecycle)
# ---------------------------------------------------------------------------

class GatewayCertificate(Base):
    """Certificate issued to a gateway at enrollment. Supports
    renewal, rotation, and revocation without losing telemetry continuity.
    Private keys are stored with OS-level protection on the gateway side.
    """

    __tablename__ = "gateway_certificates"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    gateway_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("gateways.id", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    certificate_pem: Mapped[str] = mapped_column(Text, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
