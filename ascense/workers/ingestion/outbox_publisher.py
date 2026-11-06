"""Outbox publisher worker.

Polls the outbox table and publishes pending records to RabbitMQ.
Runs as a background task inside the FastAPI lifespan.
"""

from __future__ import annotations

import asyncio

import structlog

from ascense.broker import publish_pending_outbox
from ascense.db import async_session_factory

logger = structlog.get_logger(__name__)

POLL_INTERVAL = 2  # seconds


async def run_publisher() -> None:
    logger.info("outbox_publisher.starting")
    while True:
        try:
            async with async_session_factory() as session:
                count = await publish_pending_outbox(session)
            if count:
                logger.info("outbox_publisher.published", count=count)
        except Exception:
            logger.exception("outbox_publisher.error")
        await asyncio.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    asyncio.run(run_publisher())
