"""Command lease expiry worker.

Runs as a background task inside the API lifespan.
Periodically checks for commands whose lease has expired without
acknowledgement and returns them to QUEUED status (same command_id,
so the gateway can re-claim).

Also checks for expired approvals and marks them EXPIRED.
Also checks for QUEUED commands whose overall expiry has passed
and marks them EXPIRED (unrecoverable).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import structlog
from sqlalchemy import select

from ascense.db import async_session_factory
from ascense.models import Approval, Command

logger = structlog.get_logger(__name__)

# How often to run each sweep (seconds)
LEASE_CHECK_INTERVAL = 30
APPROVAL_CHECK_INTERVAL = 60


async def _expire_stale_leases() -> int:
    """Return LEASED commands with expired leases back to QUEUED.

    The command retains the same command_id — gateways can re-claim it.
    The lease_expires_at is cleared so the next claim sets a fresh window.
    """
    now = datetime.now(timezone.utc)
    count = 0
    async with async_session_factory() as session:
        result = await session.execute(
            select(Command).where(
                Command.status == "LEASED",
                Command.lease_expires_at <= now,
            )
        )
        commands = result.scalars().all()
        for cmd in commands:
            # Return to QUEUED — same command_id, gateway can re-claim
            cmd.status = "QUEUED"
            cmd.lease_expires_at = None
            count += 1
            logger.info(
                "command.lease_expired_requeued",
                command_id=str(cmd.id),
                gateway_id=str(cmd.gateway_id),
            )
        if commands:
            await session.commit()
    return count


async def _expire_dead_commands() -> int:
    """Mark QUEUED commands whose overall TTL has passed as EXPIRED.

    These commands can no longer be executed — the overall window has
    closed. Distinct from lease expiry (where the command can still
    be re-claimed within the overall TTL).
    """
    now = datetime.now(timezone.utc)
    count = 0
    async with async_session_factory() as session:
        result = await session.execute(
            select(Command).where(
                Command.status.in_(["QUEUED", "LEASED"]),
                Command.expires_at <= now,
            )
        )
        commands = result.scalars().all()
        for cmd in commands:
            cmd.status = "EXPIRED"
            count += 1
            logger.info(
                "command.expired",
                command_id=str(cmd.id),
                gateway_id=str(cmd.gateway_id),
            )
        if commands:
            await session.commit()
    return count


async def _expire_approvals() -> int:
    """Mark PENDING approvals whose expiry has passed as EXPIRED."""
    now = datetime.now(timezone.utc)
    count = 0
    async with async_session_factory() as session:
        result = await session.execute(
            select(Approval).where(
                Approval.status == "PENDING",
                Approval.expires_at <= now,
            )
        )
        approvals = result.scalars().all()
        for approval in approvals:
            approval.status = "EXPIRED"
            count += 1
            logger.info("approval.expired", approval_id=str(approval.id))
        if approvals:
            await session.commit()
    return count


async def run_lease_expiry_worker() -> None:
    """Background task: sweep for stale leases and expired commands."""
    logger.info("lease_expiry_worker.starting")
    tick = 0
    while True:
        try:
            requeued = await _expire_stale_leases()
            expired = await _expire_dead_commands()
            if requeued or expired:
                logger.info(
                    "lease_expiry.sweep",
                    requeued=requeued,
                    expired=expired,
                )
        except Exception:
            logger.exception("lease_expiry_worker.error")

        # Expire approvals on every other tick
        if tick % 2 == 0:
            try:
                exp_approvals = await _expire_approvals()
                if exp_approvals:
                    logger.info("approval_expiry.sweep", expired=exp_approvals)
            except Exception:
                logger.exception("approval_expiry_worker.error")

        tick += 1
        await asyncio.sleep(LEASE_CHECK_INTERVAL)
