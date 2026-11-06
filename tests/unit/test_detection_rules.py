"""Unit tests for detection rules.

Tests the SuspiciousOutboundConnectionRule and the detection worker's
evaluate_event function. These tests don't require a database or
RabbitMQ — they test the rule logic in isolation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid7

import pytest

from ascense.workers.detection.worker import (
    RULES,
    SuspiciousOutboundConnectionRule,
    evaluate_event,
)
from ascense.models import Event


def _make_event(dest_ip: str = "10.0.0.1") -> Event:
    """Create a test Event with the given destination IP."""
    return Event(
        id=uuid7(),
        tenant_id=uuid7(),
        source_event_id="test-ev-001",
        source="urn:ascense:gateway:0198e728-0000-7000-8000-000000000001/sensor/suricata-01",
        event_type="com.ascense.network.connection.observed.v1",
        gateway_id=uuid7(),
        sensor_name="suricata",
        sensor_instance_id="suricata-01",
        event_kind="network.connection",
        observed_at=datetime.now(timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        asset_resolution_status="UNRESOLVED",
        data={
            "network": {
                "source_ip": "192.0.2.10",
                "destination_ip": dest_ip,
                "destination_port": 443,
                "transport": "tcp",
                "direction": "outbound",
            }
        },
    )


class TestSuspiciousOutboundConnectionRule:
    """Tests for the SuspiciousOutboundConnectionRule detection rule."""

    @pytest.fixture
    def rule(self) -> SuspiciousOutboundConnectionRule:
        return SuspiciousOutboundConnectionRule()

    @pytest.mark.asyncio
    async def test_triggers_on_known_bad_ip_198(self, rule):
        """Rule should fire when destination is in 198.51.100.x range."""
        event = _make_event(dest_ip="198.51.100.5")
        result = await rule.evaluate(event)
        assert result is not None
        assert result["severity"] == "high"
        assert result["risk_score"] == 82
        assert result["confidence"] == 0.91

    @pytest.mark.asyncio
    async def test_triggers_on_known_bad_ip_203(self, rule):
        """Rule should fire when destination is in 203.0.113.x range."""
        event = _make_event(dest_ip="203.0.113.42")
        result = await rule.evaluate(event)
        assert result is not None

    @pytest.mark.asyncio
    async def test_does_not_trigger_on_normal_ip(self, rule):
        """Rule should not fire for non-suspicious IPs."""
        event = _make_event(dest_ip="10.0.0.1")
        result = await rule.evaluate(event)
        assert result is None

    @pytest.mark.asyncio
    async def test_does_not_trigger_on_internal_ip(self, rule):
        """Rule should not fire for internal IPs."""
        event = _make_event(dest_ip="192.0.2.10")
        result = await rule.evaluate(event)
        assert result is None

    def test_rule_metadata(self, rule):
        """Rule should have correct metadata."""
        assert rule.detector_id == "suspicious_outbound_v1"
        assert rule.detector_version == "1.0.0"
        assert rule.rule_version == "1.0"
        assert rule.finding_type == "suspicious_outbound_connection"


class TestRulesRegistry:
    """Tests for the rules registry."""

    def test_rules_list_is_not_empty(self):
        assert len(RULES) > 0

    def test_all_rules_have_metadata(self):
        for rule in RULES:
            assert rule.detector_id
            assert rule.detector_version
            assert rule.finding_type

    def test_has_four_rules(self):
        assert len(RULES) == 6

    def test_all_rule_ids_unique(self):
        ids = [r.detector_id for r in RULES]
        assert len(ids) == len(set(ids))


class TestHighRiskPortRule:
    """Tests for the HighRiskPortOutboundRule."""

    @pytest.fixture
    def rule(self):
        from ascense.workers.detection.worker import HighRiskPortOutboundRule
        return HighRiskPortOutboundRule()

    @pytest.mark.asyncio
    async def test_triggers_on_metasploit_port(self, rule):
        event = _make_event(dest_ip="10.0.0.99")
        event.data["network"]["destination_port"] = 4444
        event.data["network"]["direction"] = "outbound"
        result = await rule.evaluate(event)
        assert result is not None
        assert result["severity"] == "medium"

    @pytest.mark.asyncio
    async def test_does_not_trigger_on_normal_port(self, rule):
        event = _make_event(dest_ip="10.0.0.99")
        event.data["network"]["destination_port"] = 443
        event.data["network"]["direction"] = "outbound"
        result = await rule.evaluate(event)
        assert result is None

    @pytest.mark.asyncio
    async def test_does_not_trigger_on_inbound(self, rule):
        event = _make_event(dest_ip="10.0.0.99")
        event.data["network"]["destination_port"] = 4444
        event.data["network"]["direction"] = "inbound"
        result = await rule.evaluate(event)
        assert result is None


class TestRDPExposedInternalRule:
    """Tests for the RDPExposedInternalRule."""

    @pytest.fixture
    def rule(self):
        from ascense.workers.detection.worker import RDPExposedInternalRule
        return RDPExposedInternalRule()

    @pytest.mark.asyncio
    async def test_triggers_on_external_rdp(self, rule):
        event = _make_event(dest_ip="192.0.2.10")
        event.data["network"]["destination_port"] = 3389
        event.data["network"]["direction"] = "inbound"
        event.data["network"]["source_ip"] = "203.0.113.50"  # external
        result = await rule.evaluate(event)
        assert result is not None
        assert result["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_does_not_trigger_on_internal_rdp(self, rule):
        event = _make_event(dest_ip="192.0.2.10")
        event.data["network"]["destination_port"] = 3389
        event.data["network"]["direction"] = "inbound"
        event.data["network"]["source_ip"] = "10.0.0.5"  # internal
        result = await rule.evaluate(event)
        assert result is None
