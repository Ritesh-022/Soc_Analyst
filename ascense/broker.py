"""RabbitMQ broker configuration and connection management.

Uses aio_pika for async RabbitMQ access. Implements the transactional
outbox pattern — ingestion writes to the database and outbox in one
transaction, then the outbox publisher sends to RabbitMQ.

At-least-once delivery. Duplicate delivery is expected and handled by
idempotent consumers.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import aio_pika
import structlog
from sqlalchemy import select

from ascense.config import get_settings
from ascense.models import Outbox

if TYPE_CHECKING:
    from aio_pika import Channel, Connection, Exchange
    from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Exchange and queue names
# ---------------------------------------------------------------------------

EXCHANGE_NAME = "ascense.events"
EXCHANGE_DLX = "ascense.dead_letter"

QUEUE_NORMALIZATION = "q.normalization"
QUEUE_DETECTION = "q.detection"
QUEUE_CORRELATION = "q.correlation"
QUEUE_INVESTIGATION = "q.investigation"
QUEUE_RESPONSE = "q.response"
QUEUE_VERIFICATION = "q.verification"
QUEUE_DEAD_LETTER = "q.dead_letter"

ROUTING_KEYS = {
    "telemetry.batch.accepted": "telemetry.batch.accepted.v1",
    "telemetry.event.normalized": "telemetry.event.normalized.v1",
    "detection.finding.created": "detection.finding.created.v1",
    "alert.created": "alert.created.v1",
    "incident.updated": "incident.updated.v1",
    "investigation.completed": "investigation.completed.v1",
    "response.proposal.created": "response.proposal.created.v1",
    "response.approval.recorded": "response.approval.recorded.v1",
    "response.command.created": "response.command.created.v1",
    "response.execution.reported": "response.execution.reported.v1",
    "response.verification.completed": "response.verification.completed.v1",
}

QUEUE_BINDINGS: dict[str, list[str]] = {
    QUEUE_NORMALIZATION: ["telemetry.batch.accepted.v1"],
    QUEUE_DETECTION: ["telemetry.event.normalized.v1"],
    QUEUE_CORRELATION: ["detection.finding.created.v1"],
    QUEUE_INVESTIGATION: ["incident.updated.v1", "investigation.completed.v1"],
    QUEUE_RESPONSE: ["response.approval.recorded.v1"],
    QUEUE_VERIFICATION: ["response.execution.reported.v1"],
}

# ---------------------------------------------------------------------------
# Connection pool (module-level singleton)
# ---------------------------------------------------------------------------

_connection: "Connection | None" = None
_channel: "Channel | None" = None
_exchange: "Exchange | None" = None


async def get_connection() -> "Connection":
    global _connection
    if _connection is None or _connection.is_closed:
        settings = get_settings()
        _connection = await aio_pika.connect_robust(settings.RABBITMQ_URL)
        logger.info("broker.connected")
    return _connection


async def get_channel() -> "Channel":
    global _channel
    conn = await get_connection()
    if _channel is None or _channel.is_closed:
        _channel = await conn.channel()
        await _channel.set_qos(prefetch_count=10)
    return _channel


async def get_exchange() -> "Exchange":
    global _exchange
    if _exchange is None:
        channel = await get_channel()
        _exchange = await channel.get_exchange(EXCHANGE_NAME)
    return _exchange


# ---------------------------------------------------------------------------
# Broker topology setup
# ---------------------------------------------------------------------------


async def setup_broker() -> None:
    """Declare exchanges, queues, and bindings. Idempotent — safe on restart."""
    logger.info("broker.setup_starting")
    channel = await get_channel()

    # Dead-letter exchange
    dlx = await channel.declare_exchange(
        EXCHANGE_DLX, aio_pika.ExchangeType.DIRECT, durable=True
    )
    dlq = await channel.declare_queue(QUEUE_DEAD_LETTER, durable=True)
    await dlq.bind(dlx, routing_key=QUEUE_DEAD_LETTER)

    # Main topic exchange
    exchange = await channel.declare_exchange(
        EXCHANGE_NAME, aio_pika.ExchangeType.TOPIC, durable=True
    )

    # Declare queues and bind routing keys
    for queue_name, routing_keys in QUEUE_BINDINGS.items():
        queue = await channel.declare_queue(
            queue_name,
            durable=True,
            arguments={
                "x-dead-letter-exchange": EXCHANGE_DLX,
                "x-dead-letter-routing-key": QUEUE_DEAD_LETTER,
                "x-message-ttl": 86_400_000,  # 24 h
            },
        )
        for rk in routing_keys:
            await queue.bind(exchange, routing_key=rk)

    global _exchange
    _exchange = exchange
    logger.info("broker.setup_complete")


async def close_broker() -> None:
    global _connection, _channel, _exchange
    if _channel and not _channel.is_closed:
        await _channel.close()
    if _connection and not _connection.is_closed:
        await _connection.close()
    _connection = None
    _channel = None
    _exchange = None
    logger.info("broker.closed")


# ---------------------------------------------------------------------------
# Publish helpers
# ---------------------------------------------------------------------------


async def publish(routing_key: str, payload: dict) -> None:
    """Publish a single message to the main exchange."""
    exchange = await get_exchange()
    body = json.dumps(payload, default=str).encode()
    await exchange.publish(
        aio_pika.Message(
            body=body,
            content_type="application/json",
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
        ),
        routing_key=routing_key,
    )


# ---------------------------------------------------------------------------
# Outbox publisher
# ---------------------------------------------------------------------------

MAX_RETRIES = 5
BASE_RETRY_DELAY = 1  # seconds


async def publish_pending_outbox(session: "AsyncSession") -> int:
    """Read pending outbox records and publish to RabbitMQ.

    Returns the number of records successfully published.
    """
    now = datetime.now(timezone.utc)
    result = await session.execute(
        select(Outbox)
        .where(
            Outbox.published == False,  # noqa: E712
            (Outbox.next_retry_at.is_(None)) | (Outbox.next_retry_at <= now),
            Outbox.retry_count < MAX_RETRIES,
        )
        .order_by(Outbox.created_at)
        .limit(100)
        .with_for_update(skip_locked=True)
    )
    records = result.scalars().all()
    if not records:
        return 0

    published = 0
    for record in records:
        try:
            await publish(record.message_type, record.payload)
            record.published = True
            record.published_at = datetime.now(timezone.utc)
            published += 1
            logger.info(
                "outbox.published",
                outbox_id=str(record.id),
                message_type=record.message_type,
            )
        except Exception as exc:
            record.retry_count += 1
            delay = BASE_RETRY_DELAY * (2**record.retry_count)
            record.next_retry_at = datetime.now(timezone.utc) + timedelta(seconds=delay)
            logger.error(
                "outbox.publish_failed",
                outbox_id=str(record.id),
                error=str(exc),
                retry_count=record.retry_count,
            )

    await session.commit()
    return published


# ---------------------------------------------------------------------------
# Idempotent consumer base class
# ---------------------------------------------------------------------------


class IdempotentConsumer:
    """Base class for RabbitMQ consumers with at-least-once delivery.

    Subclasses implement `handle_message(payload)` — the base class handles:
      - Message acknowledgment (nack on error → requeue)
      - Structured logging with message metadata
      - Graceful shutdown via the `_running` flag

    Idempotency is ensured at the domain level: each handler must check
    whether the operation has already been applied (e.g., finding exists
    for the same event + rule, alert already created for a finding).
    Duplicate delivery is expected and must be safe.
    """

    def __init__(
        self,
        queue_name: str,
        consumer_name: str | None = None,
    ) -> None:
        self.queue_name = queue_name
        self.consumer_name = consumer_name or self.__class__.__name__
        self._running = False

    async def handle_message(self, payload: dict) -> None:
        """Process a message. Must be idempotent — duplicate delivery is expected."""
        raise NotImplementedError

    async def _on_message(self, message: aio_pika.IncomingMessage) -> None:
        async with message.process(requeue=True):
            try:
                payload = json.loads(message.body)
                logger.info(
                    "consumer.message_received",
                    consumer=self.consumer_name,
                    routing_key=message.routing_key,
                    message_id=message.message_id,
                )
                await self.handle_message(payload)
            except Exception:
                logger.exception(
                    "consumer.message_error",
                    consumer=self.consumer_name,
                    routing_key=message.routing_key,
                )
                raise  # triggers requeue via message.process(requeue=True)

    async def start(self) -> None:
        """Begin consuming from the configured queue."""
        channel = await get_channel()
        queue = await channel.get_queue(self.queue_name)
        self._running = True
        await queue.consume(self._on_message)
        logger.info("consumer.started", consumer=self.consumer_name, queue=self.queue_name)

    async def stop(self) -> None:
        """Signal the consumer to stop."""
        self._running = False
        logger.info("consumer.stopped", consumer=self.consumer_name)

    async def run_forever(self) -> None:
        """Start consuming and block until cancelled."""
        await self.start()
        try:
            await asyncio.Future()  # block forever
        except asyncio.CancelledError:
            await self.stop()
