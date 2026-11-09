"""Correlation worker.

Consumes detection.finding.created.v1 from q.correlation, promotes
findings into alerts, and groups alerts into incidents.
Publishes alert.created.v1 and incident.updated.v1.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid7

import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.broker import QUEUE_CORRELATION, IdempotentConsumer, publish
from ascense.db import async_session_factory
from ascense.models import Alert, DetectionFinding, Incident

logger = structlog.get_logger(__name__)

# Group findings into an incident if they share the same finding_type
# and arrive within this window (seconds).
CORRELATION_WINDOW = 300  # 5 minutes


async def _promote_finding(
    finding: DetectionFinding, session: AsyncSession
) -> Alert:
    alert_id = uuid7()
    statement = (
        insert(Alert)
        .values(
            id=alert_id,
            tenant_id=finding.tenant_id,
            alert_type=finding.finding_type,
            severity=finding.severity,
            risk_score=finding.risk_score,
            status="NEW",
            summary=f"Detection: {finding.finding_type}",
            observed_at=finding.observed_at,
            detection_finding_ids=[str(finding.id)],
            event_ids=finding.event_ids,
            evidence_ids=[],
            affected_asset_ids=[],
            detection_finding_id=finding.id,
        )
        .on_conflict_do_nothing(
            index_elements=[Alert.detection_finding_id],
        )
        .returning(Alert.id)
    )
    result = await session.execute(statement)
    inserted_id = result.scalar_one_or_none()
    if inserted_id is None:
        result = await session.execute(
            select(Alert).where(Alert.detection_finding_id == finding.id)
        )
        alert = result.scalar_one()
    else:
        result = await session.execute(select(Alert).where(Alert.id == inserted_id))
        alert = result.scalar_one()
    return alert


async def _get_or_create_incident(
    tenant_id: UUID, alert: Alert, session: AsyncSession
) -> Incident:
    """Find an open incident of the same type within the correlation window,
    or create a new one."""
    from datetime import timedelta

    window_start = datetime.now(UTC) - timedelta(seconds=CORRELATION_WINDOW)
    result = await session.execute(
        select(Incident).where(
            Incident.tenant_id == tenant_id,
            Incident.status == "OPEN",
            Incident.created_at >= window_start,
        )
    )
    incident = result.scalars().first()

    if incident:
        incident.alert_ids = incident.alert_ids + [str(alert.id)]
        incident.updated_at = datetime.now(UTC)
    else:
        incident = Incident(
            id=uuid7(),
            tenant_id=tenant_id,
            title=f"Security incident: {alert.alert_type}",
            severity=alert.severity,
            status="OPEN",
            summary=f"Correlated alert: {alert.alert_type}",
            alert_ids=[str(alert.id)],
            affected_asset_ids=[],
            evidence_ids=[],
        )
        session.add(incident)
        await session.flush()

    return incident


class CorrelationConsumer(IdempotentConsumer):
    def __init__(self) -> None:
        super().__init__(QUEUE_CORRELATION, "correlation-worker")

    async def handle_message(self, payload: dict) -> None:
        finding_id = payload.get("finding_id")
        tenant_id_str = payload.get("tenant_id")
        if not finding_id or not tenant_id_str:
            logger.warning("correlation.missing_fields")
            return

        tenant_id = UUID(tenant_id_str)
        async with async_session_factory() as session:
            result = await session.execute(
                select(DetectionFinding).where(DetectionFinding.id == UUID(finding_id))
            )
            finding = result.scalar_one_or_none()
            if not finding:
                logger.warning("correlation.finding_not_found", finding_id=finding_id)
                return

            result = await session.execute(
                select(Alert).where(Alert.detection_finding_id == finding.id)
            )
            alert = result.scalar_one_or_none()
            if alert is None:
                alert = await _promote_finding(finding, session)
            incident = await _get_or_create_incident(tenant_id, alert, session)
            alert.incident_id = incident.id
            await session.commit()

            logger.info(
                "correlation.alert_created",
                alert_id=str(alert.id),
                incident_id=str(incident.id),
            )

            await publish(
                "alert.created.v1",
                {"alert_id": str(alert.id), "tenant_id": str(tenant_id)},
            )
            await publish(
                "incident.updated.v1",
                {"incident_id": str(incident.id), "tenant_id": str(tenant_id)},
            )


async def run_worker() -> None:
    logger.info("correlation_worker.starting")
    await CorrelationConsumer().run_forever()
