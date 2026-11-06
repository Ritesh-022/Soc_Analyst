"""Detection worker.

Consumes normalized events from q.detection, runs deterministic rules,
and persists DetectionFinding records. Publishes detection.finding.created.v1
for each finding so the correlation worker can pick them up.
"""

from __future__ import annotations

import asyncio
import json
from uuid import UUID, uuid7

import aio_pika
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from ascense.broker import QUEUE_DETECTION, get_channel, publish
from ascense.db import async_session_factory
from ascense.models import DetectionFinding, Event

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------


class DetectionRule:
    detector_id: str = ""
    detector_version: str = "1.0.0"
    rule_version: str = "1.0"
    finding_type: str = ""

    async def evaluate(self, event: Event) -> dict | None:
        raise NotImplementedError


class SuspiciousOutboundConnectionRule(DetectionRule):
    detector_id = "suspicious_outbound_v1"
    detector_version = "1.0.0"
    rule_version = "1.0"
    finding_type = "suspicious_outbound_connection"

    KNOWN_BAD_PREFIXES = ("198.51.100.", "203.0.113.")

    async def evaluate(self, event: Event) -> dict | None:
        dest_ip = event.data.get("network", {}).get("destination_ip", "")
        if not any(dest_ip.startswith(p) for p in self.KNOWN_BAD_PREFIXES):
            return None
        return {
            "severity": "high",
            "risk_score": 82,
            "confidence": 0.91,
        }


class HighRiskPortOutboundRule(DetectionRule):
    """Flags outbound connections to known-dangerous service ports.

    Port 4444 (Metasploit default), 1337 (leet hacker ports),
    and 6667/6697 (IRC — common C2 channel).
    """
    detector_id = "high_risk_port_outbound_v1"
    detector_version = "1.0.0"
    rule_version = "1.0"
    finding_type = "high_risk_port_outbound"

    HIGH_RISK_PORTS = {4444, 1337, 6667, 6697, 31337, 12345}

    async def evaluate(self, event: Event) -> dict | None:
        net = event.data.get("network", {})
        direction = net.get("direction", "")
        dest_port = net.get("destination_port", 0)
        if direction not in ("outbound", "unknown"):
            return None
        if dest_port not in self.HIGH_RISK_PORTS:
            return None
        return {
            "severity": "medium",
            "risk_score": 65,
            "confidence": 0.80,
        }


class LargeDataExfiltrationRule(DetectionRule):
    """Flags outbound connections with unusually large data transfers.

    More than 50 MB sent outbound in a single connection suggests
    potential data exfiltration.
    """
    detector_id = "large_data_exfiltration_v1"
    detector_version = "1.0.0"
    rule_version = "1.0"
    finding_type = "potential_data_exfiltration"

    EXFIL_THRESHOLD_BYTES = 50 * 1024 * 1024  # 50 MB

    async def evaluate(self, event: Event) -> dict | None:
        net = event.data.get("network", {})
        direction = net.get("direction", "")
        bytes_sent = net.get("bytes_sent", 0)
        if direction not in ("outbound", "unknown"):
            return None
        if bytes_sent < self.EXFIL_THRESHOLD_BYTES:
            return None
        return {
            "severity": "high",
            "risk_score": 75,
            "confidence": 0.70,
        }


class RDPExposedInternalRule(DetectionRule):
    """Flags inbound RDP (port 3389) connections from external IPs.

    RDP exposed to the internet is a common ransomware entry vector.
    """
    detector_id = "rdp_exposed_inbound_v1"
    detector_version = "1.0.0"
    rule_version = "1.0"
    finding_type = "rdp_exposed_inbound"

    # RFC 1918 internal ranges (src_ip must NOT start with these for external)
    INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                         "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                         "172.30.", "172.31.", "192.168.", "127.")

    async def evaluate(self, event: Event) -> dict | None:
        net = event.data.get("network", {})
        direction = net.get("direction", "")
        dest_port = net.get("destination_port", 0)
        src_ip = net.get("source_ip", "")

        if direction not in ("inbound", "unknown"):
            return None
        if dest_port != 3389:
            return None
        if any(src_ip.startswith(p) for p in self.INTERNAL_PREFIXES):
            return None  # internal source, not exposed
        return {
            "severity": "critical",
            "risk_score": 90,
            "confidence": 0.95,
        }


class DNSTunnelingRule(DetectionRule):
    """Detects potential DNS tunneling by flagging high-volume DNS traffic.

    DNS is commonly abused for C2 and data exfiltration because port 53
    is rarely blocked. More than 500 DNS packets from a single source
    within a connection observation window is anomalous.
    """
    detector_id = "dns_tunneling_v1"
    detector_version = "1.0.0"
    rule_version = "1.0"
    finding_type = "dns_tunneling_suspected"

    DNS_PACKET_THRESHOLD = 500  # packets in a single event observation

    async def evaluate(self, event: Event) -> dict | None:
        net = event.data.get("network", {})
        dest_port = net.get("destination_port", 0)
        bytes_sent = net.get("bytes_sent", 0)
        transport = net.get("transport", "")

        if dest_port != 53 or transport != "udp":
            return None
        # High byte count over UDP/53 indicates tunneling
        if bytes_sent < 32_000:  # < 32 KB is normal DNS
            return None
        return {
            "severity": "high",
            "risk_score": 78,
            "confidence": 0.75,
        }


class LateralMovementSMBRule(DetectionRule):
    """Flags internal-to-internal SMB connections from workstations.

    SMB (port 445) between workstations is unusual and often indicates
    lateral movement (e.g. EternalBlue, ransomware spread).
    """
    detector_id = "lateral_movement_smb_v1"
    detector_version = "1.0.0"
    rule_version = "1.0"
    finding_type = "lateral_movement_smb"

    WORKSTATION_PREFIXES = ("192.168.", "10.0.")  # typical workstation ranges

    async def evaluate(self, event: Event) -> dict | None:
        net = event.data.get("network", {})
        direction = net.get("direction", "")
        dest_port = net.get("destination_port", 0)
        src_ip = net.get("source_ip", "")
        dst_ip = net.get("destination_ip", "")

        if dest_port != 445:
            return None
        if direction not in ("internal", "unknown"):
            return None
        # Both endpoints should look like workstation ranges
        src_internal = any(src_ip.startswith(p) for p in self.WORKSTATION_PREFIXES)
        dst_internal = any(dst_ip.startswith(p) for p in self.WORKSTATION_PREFIXES)
        if not (src_internal and dst_internal):
            return None
        return {
            "severity": "high",
            "risk_score": 80,
            "confidence": 0.85,
        }


RULES: list[DetectionRule] = [
    SuspiciousOutboundConnectionRule(),
    HighRiskPortOutboundRule(),
    LargeDataExfiltrationRule(),
    RDPExposedInternalRule(),
    DNSTunnelingRule(),
    LateralMovementSMBRule(),
]


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


async def evaluate_event(event: Event, session: AsyncSession) -> list[DetectionFinding]:
    findings: list[DetectionFinding] = []
    for rule in RULES:
        try:
            result = await rule.evaluate(event)
            if not result:
                continue
            finding = DetectionFinding(
                id=uuid7(),
                tenant_id=event.tenant_id,
                detector_id=rule.detector_id,
                detector_version=rule.detector_version,
                rule_version=rule.rule_version,
                finding_type=rule.finding_type,
                severity=result["severity"],
                risk_score=result["risk_score"],
                confidence=result["confidence"],
                observed_at=event.observed_at,
                event_ids=[str(event.id)],
            )
            session.add(finding)
            findings.append(finding)
            logger.info(
                "detection.finding_created",
                finding_id=str(finding.id),
                detector_id=rule.detector_id,
            )
        except Exception:
            logger.exception("detection.rule_error", detector_id=rule.detector_id)

    if findings:
        await session.commit()
        for f in findings:
            await publish(
                "detection.finding.created.v1",
                {
                    "finding_id": str(f.id),
                    "tenant_id": str(f.tenant_id),
                    "finding_type": f.finding_type,
                    "severity": f.severity,
                    "risk_score": f.risk_score,
                    "event_ids": f.event_ids,
                },
            )
    return findings


async def _handle_message(message: aio_pika.IncomingMessage) -> None:
    async with message.process(requeue=True):
        try:
            payload = json.loads(message.body)
            event_id = payload.get("event_id")
            if not event_id:
                logger.warning("detection.missing_event_id")
                return

            async with async_session_factory() as session:
                from sqlalchemy import select

                result = await session.execute(
                    select(Event).where(Event.id == UUID(event_id))
                )
                event = result.scalar_one_or_none()
                if not event:
                    logger.warning("detection.event_not_found", event_id=event_id)
                    return
                await evaluate_event(event, session)
        except Exception:
            logger.exception("detection.message_error")
            raise  # triggers requeue


# ---------------------------------------------------------------------------
# Worker entry point
# ---------------------------------------------------------------------------


async def run_worker() -> None:
    logger.info("detection_worker.starting")
    channel = await get_channel()
    queue = await channel.get_queue(QUEUE_DETECTION)
    await queue.consume(_handle_message)
    logger.info("detection_worker.consuming", queue=QUEUE_DETECTION)
    await asyncio.Future()  # run forever
