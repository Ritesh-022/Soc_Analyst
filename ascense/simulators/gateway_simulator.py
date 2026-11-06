"""Gateway simulator.

Sends authenticated event batches and heartbeats to the Ascense platform
without requiring physical hardware. Generates valid CloudEvents 1.0
envelopes with sensor-level source URNs.

Usage:
    python -m platform.simulators.gateway_simulator \\
        --api-url http://localhost:8000 \\
        --tenant-id <uuid> \\
        --gateway-id <uuid> \\
        --rate 5 \\
        --duration 60

The simulator sends:
  - Heartbeats with per-sensor health status every 30 seconds
  - Event batches with network connection events at the specified rate
  - Some events that trigger detection rules (suspicious outbound to
    known-bad IP ranges 198.51.100.x and 203.0.113.x)
"""

from __future__ import annotations

import argparse
import asyncio
import random
import secrets
from datetime import UTC, datetime
from uuid import UUID

import httpx
import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SENSOR_NAME = "suricata"
SENSOR_INSTANCE_ID = "suricata-01"
SENSOR_VERSION = "7.0.0"

# IP ranges for generating realistic events
INTERNAL_IPS = ["192.0.2.10", "192.0.2.20", "192.0.2.30"]
EXTERNAL_IPS = ["10.0.0.1", "10.0.0.2", "172.16.0.1"]
KNOWN_BAD_IPS = ["198.51.100.5", "198.51.100.42", "203.0.113.7", "203.0.113.99"]
COMMON_PORTS = [22, 80, 443, 53, 8080, 3389, 445, 25]

HEARTBEAT_INTERVAL = 30  # seconds
BATCH_SIZE = 10


# ---------------------------------------------------------------------------
# Event generation
# ---------------------------------------------------------------------------


def generate_event(gateway_id: UUID) -> dict:
    """Generate a single CloudEvents 1.0 envelope with a network connection event."""
    event_id = secrets.token_hex(16)

    # 20% chance of a suspicious outbound to a known-bad IP
    is_suspicious = random.random() < 0.2
    if is_suspicious:
        dest_ip = random.choice(KNOWN_BAD_IPS)
        direction = "outbound"
    else:
        dest_ip = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
        direction = random.choice(["inbound", "outbound", "internal"])

    source_ip = random.choice(INTERNAL_IPS)
    dest_port = random.choice(COMMON_PORTS)
    source_port = random.randint(1024, 65535)
    transport = random.choice(["tcp", "udp"])

    source_urn = f"urn:ascense:gateway:{gateway_id}/sensor/{SENSOR_INSTANCE_ID}"

    return {
        "specversion": "1.0",
        "id": event_id,
        "source": source_urn,
        "type": "com.ascense.network.connection.observed.v1",
        "time": datetime.now(UTC).isoformat(),
        "datacontenttype": "application/json",
        "data": {
            "schema_version": "1.0",
            "source_event_id": event_id,
            "event_kind": "network.connection",
            "sensor": {
                "name": SENSOR_NAME,
                "instance_id": SENSOR_INSTANCE_ID,
                "version": SENSOR_VERSION,
            },
            "asset_resolution": {
                "status": "UNRESOLVED",
            },
            "network": {
                "source_ip": source_ip,
                "source_port": source_port,
                "destination_ip": dest_ip,
                "destination_port": dest_port,
                "transport": transport,
                "direction": direction,
                "bytes_sent": random.randint(64, 65536),
                "bytes_received": random.randint(64, 65536),
            },
        },
    }


def generate_heartbeat(gateway_id: UUID) -> dict:
    """Generate a heartbeat payload with sensor health status."""
    return {
        "gateway_id": str(gateway_id),
        "sent_at": datetime.now(UTC).isoformat(),
        "config_version": 0,
        "sensors": [
            {
                "name": SENSOR_NAME,
                "instance_id": SENSOR_INSTANCE_ID,
                "version": SENSOR_VERSION,
                "status": "HEALTHY",
                "last_event_at": datetime.now(UTC).isoformat(),
            },
        ],
    }


# ---------------------------------------------------------------------------
# Simulator
# ---------------------------------------------------------------------------


async def send_batch(
    client: httpx.AsyncClient,
    api_url: str,
    tenant_id: UUID,
    gateway_id: UUID,
    batch: list[dict],
) -> dict:
    """Send a batch of events to the ingestion API."""
    for event in batch:
        event["tenantid"] = str(tenant_id)
        event["gatewayid"] = str(gateway_id)

    resp = await client.post(
        f"{api_url}/edge/v1/events:batch",
        json=batch,
        headers={
            "X-Tenant-ID": str(tenant_id),
            "Content-Type": "application/json",
        },
    )
    if resp.status_code != 202:
        logger.error("simulator.batch_failed", status=resp.status_code, body=resp.text)
        return {"accepted": 0, "rejected": len(batch)}
    return resp.json()


async def send_heartbeat(
    client: httpx.AsyncClient,
    api_url: str,
    gateway_id: UUID,
    tenant_id: UUID,
) -> None:
    """Send a heartbeat to the gateway heartbeat endpoint."""
    payload = generate_heartbeat(gateway_id)
    resp = await client.post(
        f"{api_url}/edge/v1/gateways/{gateway_id}/heartbeat",
        json=payload,
        headers={"X-Tenant-ID": str(tenant_id)},
    )
    if resp.status_code != 200:
        logger.error("simulator.heartbeat_failed", status=resp.status_code)
    else:
        logger.info("simulator.heartbeat_sent", gateway_id=str(gateway_id))


async def run_simulator(
    api_url: str,
    tenant_id: UUID,
    gateway_id: UUID,
    rate: float,
    duration: int | None,
) -> None:
    """Run the gateway simulator.

    Args:
        api_url: Base URL of the Ascense API
        tenant_id: Tenant UUID
        gateway_id: Gateway UUID
        rate: Events per second to generate
        duration: How long to run in seconds (None = forever)
    """
    logger.info(
        "simulator.starting",
        api_url=api_url,
        tenant_id=str(tenant_id),
        gateway_id=str(gateway_id),
        rate=rate,
        duration=duration,
    )

    async with httpx.AsyncClient(timeout=30.0) as client:
        # Send initial heartbeat
        await send_heartbeat(client, api_url, gateway_id, tenant_id)

        interval = 1.0 / rate if rate > 0 else 1.0
        elapsed = 0
        heartbeat_timer = 0

        while duration is None or elapsed < duration:
            # Generate and send a batch of events
            batch = [generate_event(gateway_id) for _ in range(BATCH_SIZE)]
            result = await send_batch(client, api_url, tenant_id, gateway_id, batch)
            logger.info(
                "simulator.batch_sent",
                accepted=result.get("accepted_count", 0),
                rejected=result.get("rejected_count", 0),
            )

            # Send heartbeat periodically
            heartbeat_timer += interval
            if heartbeat_timer >= HEARTBEAT_INTERVAL:
                await send_heartbeat(client, api_url, gateway_id, tenant_id)
                heartbeat_timer = 0

            await asyncio.sleep(interval)
            elapsed += interval

    logger.info("simulator.stopped", elapsed=elapsed)


def main() -> None:
    parser = argparse.ArgumentParser(description="Ascense gateway simulator")
    parser.add_argument("--api-url", default="http://localhost:8000", help="API base URL")
    parser.add_argument("--tenant-id", required=True, help="Tenant UUID")
    parser.add_argument("--gateway-id", required=True, help="Gateway UUID")
    parser.add_argument("--rate", type=float, default=5, help="Events per second")
    parser.add_argument(
        "--duration", type=int, default=None,
        help="Duration in seconds (default: forever)",
    )
    parser.add_argument("--log-level", default="INFO", help="Log level")

    args = parser.parse_args()

    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ],
    )

    asyncio.run(
        run_simulator(
            api_url=args.api_url,
            tenant_id=UUID(args.tenant_id),
            gateway_id=UUID(args.gateway_id),
            rate=args.rate,
            duration=args.duration,
        )
    )


if __name__ == "__main__":
    main()
