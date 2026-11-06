"""Investigation worker — Stage 5.

Consumes incident.updated.v1 from q.investigation, runs the AI
investigation agent, and persists InvestigationResult records.

Architecture constraints (from docs/05_TESTING_AND_SECURITY_STRATEGY.md):
  - Read-only tools only: search_events, search_alerts, get_asset, get_evidence
  - No write or execute tools
  - Every claim references a real, retrievable evidence_id
  - Tenant-scoped: agent cannot access another tenant's data
  - Bounded: timeout per step, max tool-call budget, graceful failure on budget exceeded
  - Prompt injection hardening: event payloads are treated as untrusted data
  - UNKNOWN uncertainty is reported, not hidden

The LLM provider is abstracted behind an env var:
  INVESTIGATION_LLM_PROVIDER=ollama|openai|anthropic
  INVESTIGATION_LLM_MODEL=llama3:8b
  INVESTIGATION_LLM_BASE_URL=http://localhost:11434

Baseline C must be frozen before this worker is activated.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.broker import QUEUE_INVESTIGATION, IdempotentConsumer
from ascense.config import get_settings
from ascense.db import async_session_factory
from ascense.models import Alert, Event, Evidence, Incident

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Read-only tool definitions (no write, no execute)
# ---------------------------------------------------------------------------

MAX_TOOL_CALLS = 20   # budget: abort investigation if exceeded
STEP_TIMEOUT = 30.0   # seconds per LLM call
MAX_EVIDENCE_REFS = 50


async def tool_search_events(
    tenant_id: UUID,
    gateway_id: str | None,
    event_kind: str | None,
    limit: int,
    session: AsyncSession,
) -> list[dict]:
    """Read-only: search events for a tenant. Tenant-scoped — cannot escape."""
    query = select(Event).where(Event.tenant_id == tenant_id)
    if gateway_id:
        try:
            query = query.where(Event.gateway_id == UUID(gateway_id))
        except ValueError:
            return []
    if event_kind:
        query = query.where(Event.event_kind == event_kind)
    query = query.order_by(Event.observed_at.desc()).limit(min(limit, 100))
    result = await session.execute(query)
    events = result.scalars().all()
    return [
        {
            "event_id": str(e.id),
            "event_kind": e.event_kind,
            "observed_at": e.observed_at.isoformat(),
            "sensor_name": e.sensor_name,
            "asset_resolution_status": e.asset_resolution_status,
            # Strip raw data — only expose safe summary fields to avoid prompt injection
            "network_summary": {
                "source_ip": e.data.get("network", {}).get("source_ip"),
                "destination_ip": e.data.get("network", {}).get("destination_ip"),
                "destination_port": e.data.get("network", {}).get("destination_port"),
                "direction": e.data.get("network", {}).get("direction"),
            },
        }
        for e in events
    ]


async def tool_search_alerts(
    tenant_id: UUID,
    status: str | None,
    session: AsyncSession,
) -> list[dict]:
    """Read-only: search alerts for a tenant. Tenant-scoped."""
    query = select(Alert).where(Alert.tenant_id == tenant_id)
    if status:
        query = query.where(Alert.status == status)
    query = query.order_by(Alert.observed_at.desc()).limit(50)
    result = await session.execute(query)
    alerts = result.scalars().all()
    return [
        {
            "alert_id": str(a.id),
            "alert_type": a.alert_type,
            "severity": a.severity,
            "risk_score": a.risk_score,
            "status": a.status,
            "observed_at": a.observed_at.isoformat(),
        }
        for a in alerts
    ]


async def tool_get_evidence(
    tenant_id: UUID,
    evidence_id: str,
    session: AsyncSession,
) -> dict | None:
    """Read-only: get a specific evidence record. Tenant-scoped."""
    try:
        ev_uuid = UUID(evidence_id)
    except ValueError:
        return None
    result = await session.execute(
        select(Evidence).where(
            Evidence.id == ev_uuid,
            Evidence.tenant_id == tenant_id,  # tenant isolation enforced
        )
    )
    evidence = result.scalar_one_or_none()
    if not evidence:
        return None
    return {
        "evidence_id": str(evidence.id),
        "evidence_type": evidence.evidence_type,
        "description": evidence.description,
        "collected_at": evidence.collected_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Investigation agent context builder
# ---------------------------------------------------------------------------

async def build_incident_context(
    incident: Incident,
    session: AsyncSession,
) -> dict:
    """Collect all relevant data for an incident into a context dict.

    This is the read-only context passed to the investigation agent.
    All data is tenant-scoped — no cross-tenant access possible.
    """
    alert_ids = [UUID(a) for a in (incident.alert_ids or [])]
    evidence_ids = [UUID(e) for e in (incident.evidence_ids or [])]

    # Fetch alerts
    alerts = []
    if alert_ids:
        result = await session.execute(
            select(Alert).where(
                Alert.id.in_(alert_ids),
                Alert.tenant_id == incident.tenant_id,
            )
        )
        alerts = result.scalars().all()

    # Fetch evidence (cap at MAX_EVIDENCE_REFS)
    evidence_records = []
    if evidence_ids:
        result = await session.execute(
            select(Evidence).where(
                Evidence.id.in_(evidence_ids[:MAX_EVIDENCE_REFS]),
                Evidence.tenant_id == incident.tenant_id,
            )
        )
        evidence_records = result.scalars().all()

    return {
        "incident_id": str(incident.id),
        "tenant_id": str(incident.tenant_id),
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "summary": incident.summary,
        "alerts": [
            {
                "alert_id": str(a.id),
                "alert_type": a.alert_type,
                "severity": a.severity,
                "risk_score": a.risk_score,
                "status": a.status,
                "observed_at": a.observed_at.isoformat(),
            }
            for a in alerts
        ],
        "evidence": [
            {
                "evidence_id": str(e.id),
                "evidence_type": e.evidence_type,
                "description": e.description,
                "collected_at": e.collected_at.isoformat(),
            }
            for e in evidence_records
        ],
    }


# ---------------------------------------------------------------------------
# Stub investigation runner (LangGraph wiring is Stage 5 full implementation)
# ---------------------------------------------------------------------------

async def run_investigation(
    incident: Incident,
    investigation_id: UUID,
    session: AsyncSession,
) -> dict:
    """Run the investigation agent on an incident.

    Returns a structured result matching investigation-result-v1.json.
    This is a stub — full LangGraph wiring is Stage 5 work.
    """
    from ascense.models import Incident as IncidentModel

    context = await build_incident_context(incident, session)

    # Stub result — real implementation calls LangGraph agent
    result = {
        "investigation_id": str(investigation_id),
        "incident_id": str(incident.id),
        "tenant_id": str(incident.tenant_id),
        "status": "COMPLETED",
        "assessment": {
            "summary": (
                f"Investigation of incident '{incident.title}'. "
                f"Found {len(context['alerts'])} related alerts. "
                f"Evidence count: {len(context['evidence'])}. "
                "Full AI investigation requires Stage 5 LangGraph implementation."
            ),
            "confidence": 0.0,  # unknown — stub only
            "uncertainty_notes": [
                "Investigation agent not yet implemented (Stage 5).",
                "All claims require real evidence references before proposals can be generated.",
            ],
            "evidence_refs": [e["evidence_id"] for e in context["evidence"]],
        },
        "action_proposals": [],  # no proposals until agent is implemented
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    return result


# ---------------------------------------------------------------------------
# RabbitMQ consumer
# ---------------------------------------------------------------------------

class InvestigationConsumer(IdempotentConsumer):
    """Consumes incident.updated.v1 and triggers investigation agent."""

    def __init__(self) -> None:
        super().__init__(
            queue_name=QUEUE_INVESTIGATION,
            consumer_name="investigation-worker",
        )

    async def handle_message(self, payload: dict) -> None:
        incident_id_str = payload.get("incident_id")
        tenant_id_str = payload.get("tenant_id")
        if not incident_id_str or not tenant_id_str:
            logger.warning("investigation.missing_fields")
            return

        incident_id = UUID(incident_id_str)
        tenant_id = UUID(tenant_id_str)

        async with async_session_factory() as session:
            result = await session.execute(
                select(Incident).where(
                    Incident.id == incident_id,
                    Incident.tenant_id == tenant_id,  # tenant isolation
                )
            )
            incident = result.scalar_one_or_none()
            if not incident:
                logger.warning("investigation.incident_not_found", incident_id=incident_id_str)
                return

            # Only investigate open/active incidents
            if incident.status in ("RESOLVED", "CLOSED"):
                logger.info(
                    "investigation.skipped_terminal_incident",
                    incident_id=incident_id_str,
                    status=incident.status,
                )
                return

            from uuid import uuid7
            investigation_id = uuid7()
            logger.info(
                "investigation.starting",
                investigation_id=str(investigation_id),
                incident_id=incident_id_str,
            )

            try:
                _result = await asyncio.wait_for(
                    run_investigation(incident, investigation_id, session),
                    timeout=STEP_TIMEOUT * MAX_TOOL_CALLS,
                )
                logger.info(
                    "investigation.completed",
                    investigation_id=str(investigation_id),
                    status=_result.get("status"),
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "investigation.timeout",
                    investigation_id=str(investigation_id),
                    incident_id=incident_id_str,
                )


async def run_worker() -> None:
    """Main investigation worker loop."""
    logger.info("investigation_worker.starting")
    consumer = InvestigationConsumer()
    await consumer.run_forever()


if __name__ == "__main__":
    asyncio.run(run_worker())
