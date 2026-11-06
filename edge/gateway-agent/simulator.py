"""Gateway simulator for development and testing.

Sends authenticated event batches and heartbeats to the Ascense platform
without requiring physical sensors. Generates valid CloudEvents 1.0
envelopes with sensor-level source URN format.

Usage:
    python -m edge.gateway_agent.simulator --gateway-id <uuid> --tenant-id <uuid>

The simulator:
  1. Sends heartbeats with per-sensor health status
  2. Generates simulated network connection events
  3. Sends events in batches to /edge/v1/events:batch
  4. Stops gracefully on Ctrl+C
"""

from __future__ import annotations

import argparse
import asyncio
import random
import sys
import time
from datetime import datetime, timezone
from uuid import uuid7

import httpx
import structlog

logger = structlog.get_logger(__name__)

API_BASE = "http://localhost:8000"

# Simulated sensor configurations
SENSORS = [
    {"name": "suricata", "instance_id": "suricata-01", "version": "7.0.0"},
    {"name": "zeek", "instance_id": "zeek-01", "version": "7.1.0"},
]

# Simulated network patterns
INTERNAL_IPS = ["192.0.2.10", "192.0.2.20", "192.0.2.30"]
SUSPICIOUS_DESTINATIONS = ["198.51.100.20", "203.0.113.50"]
NORMAL_DESTINATIONS = ["8.8.8.8", "1.1.1.1", "140.82.121.4"]


def make_cloudevent(
    gateway_id: str,
    sensor: dict,
    event_id: str,
    source_ip: str,
    dest_ip: str,
    dest_port: int,
    direction: str = "outbound",
) -> dict:
    """Create a valid CloudEvents 1.0 envelope for a network connection event."""
    return {
        "specversion": "1.0",
        "id": event_id,
        "source": f"urn:ascense:gateway:{gateway_id}/sensor/{sensor['instance_id']}",
        "type": "com.ascense.network.connection.observed.v1",
        "time": datetime.now(timezone.utc).isoformat(),
        "datacontenttype": "application/json",
        "dataschema": "https://schemas.ascense.example/events/network-connection/1.0.0",
        "data": {
            "schema_version": "1.0",
            "source_event_id": event_id,
            "event_kind": "network.connection",
            "sensor": {
                "name": sensor["name"],
                "instance_id": sensor["instance_id"],
                "version": sensor["version"],
            },
            "asset_resolution": {
                "status": "UNRESOLVED",
                "source_asset_id": None,
                "destination_asset_id": None,
            },
            "network": {
                "source_ip": source_ip,
                "source_port": random.randint(1024, 65535),
                "destination_ip": dest_ip,
                "destination_port": dest_port,
                "transport": "tcp",
                "direction": direction,
                "bytes_sent": random.randint(100, 5000),
                "bytes_received": random.randint(100, 5000),
            },
        },
    }


async def send_heartbeat(client: httpx.AsyncClient, gateway_id: str, tenant_id: str) -> None:
    """Send a gateway heartbeat with per-sensor health status."""
    heartbeat = {
        "gateway_id": gateway_id,
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "config_version": 0,
        "sensors": [
            {"name": s["name"], "instance_id": s["instance_id"],
             "version": s["version"], "status": "HEALTHY",
             "last_event_at": datetime.now(timezone.utc).isoformat()}
            for s in SENSORS
        ],
    }

    resp = await client.post(
        f"{API_BASE}/edge/v1/gateways/{gateway_id}/heartbeat",
        json=heartbeat,
        headers={"X-Tenant-ID": tenant_id},
    )
    if resp.status_code == 200:
        logger.info("heartbeat.sent", gateway_id=gateway_id, status=resp.status_code)
    else:
        logger.error("heartbeat.failed", status=resp.status_code, body=resp.text)


async def send_event_batch(
    client: httpx.AsyncClient,
    gateway_id: str,
    tenant_id: str,
    batch_size: int = 10,
) -> None:
    """Send a batch of simulated network events."""
    events = []
    for _ in range(batch_size):
        sensor = random.choice(SENSORS)
        event_id = str(uuid7())
        source_ip = random.choice(INTERNAL_IPS)

        # 20% chance of suspicious destination
        if random.random() < 0.2:
            dest_ip = random.choice(SUSPICIOUS_DESTINATIONS)
            dest_port = random.choice([443, 8080, 4444])
        else:
            dest_ip = random.choice(NORMAL_DESTINATIONS)
            dest_port = random.choice([443, 80, 53])

        events.append(make_cloudevent(gateway_id, sensor, event_id, source_ip, dest_ip, dest_port))

    resp = await client.post(
        f"{API_BASE}/edge/v1/events:batch",
        json=events,
        headers={"X-Tenant-ID": tenant_id},
    )
    if resp.status_code == 202:
        data = resp.json()
        logger.info(
            "batch.sent",
            accepted=data.get("accepted_count", 0),
            rejected=data.get("rejected_count", 0),
        )
    else:
        logger.error("batch.failed", status=resp.status_code, body=resp.text)


async def run_simulator(gateway_id: str, tenant_id: str, interval: float = 5.0) -> None:
    """Run the gateway simulator: sends heartbeats and event batches."""
    logger.info("simulator.starting", gateway_id=gateway_id, tenant_id=tenant_id)

    async with httpx.AsyncClient(timeout=30) as client:
        while True:
            await send_heartbeat(client, gateway_id, tenant_id)
            await send_event_batch(client, gateway_id, tenant_id, batch_size=10)
            await asyncio.sleep(interval)


def main() -> None:
    parser = argparse.ArgumentParser(description="Ascense Gateway Simulator")
    parser.add_argument("--gateway-id", required=True, help="Gateway UUID")
    parser.add_argument("--tenant-id", required=True, help="Tenant UUID")
    parser.add_argument("--interval", type=float, default=5.0, help="Seconds between batches")
    parser.add_argument("--api-base", default=API_BASE, help="API base URL")
    args = parser.parse_args()

    global API_BASE
    API_BASE = args.api_base

    try:
        asyncio.run(run_simulator(args.gateway_id, args.tenant_id, args.interval))
    except KeyboardInterrupt:
        logger.info("simulator.stopped")
        sys.exit(0)


if __name__ == "__main__":
    main()
