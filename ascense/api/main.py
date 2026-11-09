"""Ascense platform API application factory."""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from ascense.api.middleware.audit import AuditMiddleware
from ascense.api.middleware.body_limit import EventBodyLimitMiddleware
from ascense.api.middleware.mtls import GatewayMTLSMiddleware
from ascense.api.middleware.tenant import TenantMiddleware
from ascense.api.middleware.tracing import TracingMiddleware
from ascense.api.routes import (
    alerts,
    assets,
    commands,
    events,
    evidence,
    gateways,
    health,
    identity,
    incidents,
    investigations,
    policy,
    proposals,
    telemetry,
)
from ascense.broker import close_broker, setup_broker
from ascense.db import async_session_factory
from ascense.models import Gateway
from ascense.workers.ingestion.outbox_publisher import run_publisher

logger = structlog.get_logger(__name__)

TELEMETRY_STALE_THRESHOLD = 120  # seconds without an event → TELEMETRY_STALE
TELEMETRY_CHECK_INTERVAL = 30   # seconds between checks


async def _telemetry_stale_job() -> None:
    """Background job: mark gateways TELEMETRY_STALE when no events arrive."""
    logger.info("telemetry_stale_job.starting")
    while True:
        try:
            cutoff = datetime.now(UTC) - timedelta(seconds=TELEMETRY_STALE_THRESHOLD)
            async with async_session_factory() as session:
                result = await session.execute(
                    select(Gateway).where(
                        Gateway.status == "ACTIVE",
                        Gateway.last_heartbeat_at < cutoff,
                    )
                )
                stale = result.scalars().all()
                for gw in stale:
                    gw.status = "TELEMETRY_STALE"
                    logger.info("gateway.telemetry_stale", gateway_id=str(gw.id))
                if stale:
                    await session.commit()
        except Exception:
            logger.exception("telemetry_stale_job.error")
        await asyncio.sleep(TELEMETRY_CHECK_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Validate production configuration before starting
    from ascense.config import get_settings
    _settings = get_settings()
    _errors = _settings.validate_production()
    if _errors:
        for err in _errors:
            logger.error("config.production_check_failed", error=err)
        raise RuntimeError(
            "Production configuration validation failed: "
            + "; ".join(_errors)
        )

    await setup_broker()
    publisher_task = asyncio.create_task(run_publisher())
    stale_task = asyncio.create_task(_telemetry_stale_job())

    # Start detection and correlation workers as background tasks.
    # In production these run as separate processes; in development they
    # run inside the API process for convenience (toggle via env var).
    worker_tasks: list[asyncio.Task] = []
    run_workers = os.getenv("ASCENSE_RUN_WORKERS", "true").lower() == "true"
    if run_workers:
        from ascense.workers.correlation.worker import run_worker as run_correlation
        from ascense.workers.detection.worker import run_worker as run_detection
        from ascense.workers.ingestion.worker import run_normalization_worker
        from ascense.workers.investigation.worker import run_worker as run_investigation
        from ascense.workers.response.lease_expiry import run_lease_expiry_worker
        worker_tasks.append(asyncio.create_task(run_detection()))
        worker_tasks.append(asyncio.create_task(run_correlation()))
        worker_tasks.append(asyncio.create_task(run_normalization_worker()))
        worker_tasks.append(asyncio.create_task(run_lease_expiry_worker()))
        worker_tasks.append(asyncio.create_task(run_investigation()))

    try:
        yield
    finally:
        publisher_task.cancel()
        stale_task.cancel()
        for t in worker_tasks:
            t.cancel()
        await close_broker()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Ascense Platform API",
        version="0.1.0",
        description="Autonomous cyber defense platform API.",
        lifespan=lifespan,
    )

    # CORS — allow the Vite dev server and configured origins
    cors_origins = os.getenv("ASCENSE_CORS_ORIGINS", "http://localhost:5173").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in cors_origins],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "traceparent"],
    )

    app.add_middleware(TracingMiddleware)
    app.add_middleware(GatewayMTLSMiddleware)
    app.add_middleware(TenantMiddleware)
    app.add_middleware(AuditMiddleware)
    app.add_middleware(EventBodyLimitMiddleware)

    app.include_router(health.router)
    app.include_router(identity.router)
    app.include_router(events.router)
    app.include_router(gateways.router)
    app.include_router(alerts.router)
    app.include_router(incidents.router)
    app.include_router(assets.router)
    app.include_router(telemetry.router)
    app.include_router(proposals.router)
    app.include_router(commands.router)
    app.include_router(evidence.router)
    app.include_router(policy.router)
    app.include_router(investigations.router)

    return app


app = create_app()
