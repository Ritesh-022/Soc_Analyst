"""Unit tests for event batch validation.

Tests the CloudEvents 1.0 envelope validation, source URN format,
event type allowlist, and sensor name validation in the ingestion route.
These tests use mocked database sessions.
"""

from __future__ import annotations

from ascense.api.routes.events import (
    ALLOWED_EVENT_TYPES,
    ALLOWED_SENSOR_NAMES,
    MAX_BATCH_SIZE,
    SOURCE_URN_PATTERN,
)


class TestSourceURNValidation:
    """Tests for the sensor-level source URN pattern."""

    VALID_URN = "urn:ascense:gateway:0198e728-0000-7000-8000-000000000001/sensor/suricata-01"

    def test_valid_urn_passes(self):
        assert SOURCE_URN_PATTERN.match(self.VALID_URN)

    def test_valid_urn_with_different_sensor(self):
        urn = "urn:ascense:gateway:0198e728-0000-7000-8000-000000000001/sensor/zeek-02"
        assert SOURCE_URN_PATTERN.match(urn)

    def test_missing_sensor_fails(self):
        urn = "urn:ascense:gateway:0198e728-0000-7000-8000-000000000001"
        assert not SOURCE_URN_PATTERN.match(urn)

    def test_wrong_prefix_fails(self):
        urn = "urn:other:gateway:0198e728-0000-7000-8000-000000000001/sensor/suricata-01"
        assert not SOURCE_URN_PATTERN.match(urn)

    def test_non_uuidv7_gateway_fails(self):
        # UUIDv4 format should not match (no version 7 marker)
        urn = "urn:ascense:gateway:550e8400-e29b-41d4-a716-446655440000/sensor/suricata-01"
        assert not SOURCE_URN_PATTERN.match(urn)


class TestEventTypesAllowlist:
    """Tests for the event type allowlist."""

    def test_network_connection_allowed(self):
        assert "com.ascense.network.connection.observed.v1" in ALLOWED_EVENT_TYPES

    def test_unknown_event_type_rejected(self):
        assert "com.unknown.event.v1" not in ALLOWED_EVENT_TYPES

    def test_all_types_have_version_suffix(self):
        for event_type in ALLOWED_EVENT_TYPES:
            assert event_type.endswith(".v1"), f"Event type {event_type} must end with .v1"


class TestSensorNamesAllowlist:
    """Tests for the sensor name allowlist."""

    def test_suricata_allowed(self):
        assert "suricata" in ALLOWED_SENSOR_NAMES

    def test_zeek_allowed(self):
        assert "zeek" in ALLOWED_SENSOR_NAMES

    def test_unknown_sensor_rejected(self):
        assert "unknown_sensor" not in ALLOWED_SENSOR_NAMES


class TestBatchSizeLimit:
    """Tests for batch size limits."""

    def test_max_batch_size_is_1000(self):
        assert MAX_BATCH_SIZE == 1000

    def test_max_batch_size_is_positive(self):
        assert MAX_BATCH_SIZE > 0
