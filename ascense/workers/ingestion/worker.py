"""Normalization worker.

Consumes telemetry.batch.accepted.v1 from q.normalization, normalizes
Suricata EVE JSON to the canonical network event schema, and publishes
telemetry.event.normalized.v1 for the detection pipeline.

The ingestion API stores the raw event and writes an outbox record with
message_type "telemetry.batch.accepted.v1". This worker consumes that,
performs any additional normalization or enrichment, and forwards the
normalized event to the detection queue.

Design for at-least-once delivery. Duplicate delivery is expected and
handled safely — the detection worker checks for existing findings per
(event, rule) pair.
"""

from __future__ import annotations

import asyncio
from uuid import UUID

import structlog
from sqlalchemy import select

from ascense.broker import (
    QUEUE_NORMALIZATION,
    IdempotentConsumer,
    publish,
)
from ascense.db import async_session_factory
from ascense.models import Event

logger = structlog.get_logger(__name__)


async def normalize_event(event_id: UUID) -> dict | None:
    """Load an event from the database and produce a normalized payload
    suitable for the detection pipeline.

    In v1, events are already stored in canonical form by the ingestion
    API. This worker adds enrichment metadata and forwards to detection.
    """
    async with async_session_factory() as session:
        result = await session.execute(
            select(Event).where(Event.id == event_id)
        )
        event = result.scalar_one_or_none()
        if not event:
            logger.warning("normalization.event_not_found", event_id=str(event_id))
            return None

        # Build the normalized payload for detection
        payload = {
            "event_id": str(event.id),
            "tenant_id": str(event.tenant_id),
            "event_kind": event.event_kind,
            "source": event.source,
            "source_event_id": event.source_event_id,
            "gateway_id": str(event.gateway_id),
            "sensor_name": event.sensor_name,
            "sensor_instance_id": event.sensor_instance_id,
            "observed_at": event.observed_at.isoformat(),
            "ingested_at": event.ingested_at.isoformat(),
            "asset_resolution_status": event.asset_resolution_status,
            "source_asset_id": (
                str(event.source_asset_id) if event.source_asset_id else None
            ),
            "destination_asset_id": (
                str(event.destination_asset_id)
                if event.destination_asset_id else None
            ),
            "data": event.data,
        }

        logger.info(
            "normalization.event_normalized",
            event_id=str(event.id),
            event_kind=event.event_kind,
        )
        return payload


class NormalizationConsumer(IdempotentConsumer):
    """Consumes telemetry.batch.accepted.v1 and publishes
    telemetry.event.normalized.v1 to the detection queue."""

    def __init__(self) -> None:
        super().__init__(
            queue_name=QUEUE_NORMALIZATION,
            consumer_name="normalization-worker",
        )

    async def handle_message(self, payload: dict) -> None:
        event_id_str = payload.get("event_id")
        if not event_id_str:
            logger.warning("normalization.missing_event_id")
            return

        event_id = UUID(event_id_str)
        normalized = await normalize_event(event_id)
        if not normalized:
            return

        # Publish the normalized event for the detection pipeline
        await publish("telemetry.event.normalized.v1", normalized)


async def run_normalization_worker() -> None:
    """Main normalization worker loop."""
    logger.info("normalization_worker.starting")
    consumer = NormalizationConsumer()
    await consumer.run_forever()


async def run_worker() -> None:
    """Legacy entry point — delegates to the normalization worker."""
    await run_normalization_worker()


if __name__ == "__main__":
    asyncio.run(run_normalization_worker())
