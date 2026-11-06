"""Contract tests: validate JSON Schema files and OpenAPI specs.

For each event type and API endpoint, maintain:
  - A valid example that must pass schema validation
  - At least one invalid example that must fail schema validation
  - A producer test that verifies the component generates output matching the schema

Contract tests must pass before any integration test is run.
A failing contract test blocks the PR.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import jsonschema
import pytest
import yaml

BASE_DIR = Path(__file__).resolve().parent.parent.parent
CONTRACTS_DIR = BASE_DIR / "contracts"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_json_schema(relative_path: str) -> dict:
    path = CONTRACTS_DIR / relative_path
    with open(path) as f:
        return json.load(f)


def load_yaml(relative_path: str) -> dict:
    path = CONTRACTS_DIR / relative_path
    with open(path) as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# Contract Baseline A — Gateway and Ingestion
# ---------------------------------------------------------------------------

class TestIdentifiersRegistry:
    """Identifier registry must define all required identifiers."""

    def test_has_all_identifiers(self):
        data = load_yaml("common/identifiers.yaml")
        names = {id_obj["name"] for id_obj in data["identifiers"]}
        required = {
            "tenant_id", "user_id", "gateway_id", "asset_id",
            "source_event_id", "event_id", "detection_finding_id",
            "alert_id", "incident_id", "evidence_id", "investigation_id",
            "proposal_id", "approval_id", "command_id", "execution_attempt_id",
            "policy_version_id", "model_version_id", "request_id", "trace_id",
        }
        assert required.issubset(names), f"Missing identifiers: {required - names}"

    def test_trace_id_is_not_uuid(self):
        data = load_yaml("common/identifiers.yaml")
        trace = next(id_obj for id_obj in data["identifiers"] if id_obj["name"] == "trace_id")
        assert trace["format"] == "w3c_trace"


class TestEnumsRegistry:
    """Enum registry must define all required state machines."""

    def test_has_all_state_machines(self):
        data = load_yaml("common/enums.yaml")
        assert "gateway_states" in data
        assert "alert_status" in data
        assert "incident_status" in data
        assert "command_status" in data
        assert "execution_status" in data
        assert "verification_status" in data

    def test_dispatched_not_in_command_status(self):
        """DISPATCHED is NOT a command lifecycle state — it is an audit event."""
        data = load_yaml("common/enums.yaml")
        command_states = data["command_status"]
        # command_status is a list of dicts or strings
        state_names = set()
        for s in command_states:
            if isinstance(s, dict):
                state_names.update(s.keys())
            else:
                state_names.add(s)
        assert "DISPATCHED" not in state_names

    def test_execution_and_verification_are_separate(self):
        """Execution status and verification status must be distinct enum sets."""
        data = load_yaml("common/enums.yaml")
        exec_states = set()
        for s in data["execution_status"]:
            if isinstance(s, dict):
                exec_states.update(s.keys())
            else:
                exec_states.add(s)
        verif_states = set()
        for s in data["verification_status"]:
            if isinstance(s, dict):
                verif_states.update(s.keys())
            else:
                verif_states.add(s)
        # No overlap between execution and verification status values
        assert exec_states.isdisjoint(verif_states)


class TestErrorRegistry:
    """Error registry must define all required error codes."""

    def test_has_required_error_codes(self):
        data = load_yaml("common/errors.yaml")
        codes = set(data["error_codes"].keys())
        required = {
            "UNAUTHENTICATED", "FORBIDDEN", "TENANT_ACCESS_DENIED",
            "GATEWAY_MISMATCH", "INVALID_EVENT_SCHEMA", "DUPLICATE_EVENT",
            "UNSUPPORTED_EVENT_TYPE", "COMMAND_EXPIRED", "COMMAND_REPLAYED",
            "COMMAND_SIGNATURE_INVALID", "POLICY_CHANGED_AFTER_APPROVAL",
        }
        assert required.issubset(codes), f"Missing error codes: {required - codes}"

    def test_problem_details_format(self):
        data = load_yaml("common/errors.yaml")
        assert data["problem_details"]["content_type"] == "application/problem+json"
        assert "type" in data["problem_details"]["required_fields"]
        assert "title" in data["problem_details"]["required_fields"]
        assert "status" in data["problem_details"]["required_fields"]


class TestNetworkConnectionSchema:
    """Network connection event payload schema validation."""

    def test_valid_event_passes(self):
        schema = load_json_schema("events/network-connection-v1.json")
        valid = {
            "schema_version": "1.0",
            "source_event_id": "zeek-conn-001",
            "event_kind": "network.connection",
            "sensor": {"name": "zeek", "instance_id": "zeek-01", "version": "7.x"},
            "asset_resolution": {"status": "UNRESOLVED", "source_asset_id": None, "destination_asset_id": None},
            "network": {
                "source_ip": "192.0.2.10",
                "source_port": 51432,
                "destination_ip": "198.51.100.20",
                "destination_port": 443,
                "transport": "tcp",
                "direction": "outbound",
                "bytes_sent": 1200,
                "bytes_received": 5400,
            },
        }
        jsonschema.validate(valid, schema)

    def test_missing_source_event_id_fails(self):
        schema = load_json_schema("events/network-connection-v1.json")
        invalid = {
            "schema_version": "1.0",
            "event_kind": "network.connection",
            "sensor": {"name": "zeek", "instance_id": "zeek-01"},
            "asset_resolution": {"status": "UNRESOLVED"},
        }
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(invalid, schema)

    def test_unresolved_asset_is_valid(self):
        """Events with UNRESOLVED asset_resolution must be accepted, not rejected."""
        schema = load_json_schema("events/network-connection-v1.json")
        valid = {
            "schema_version": "1.0",
            "source_event_id": "ev-001",
            "event_kind": "network.connection",
            "sensor": {"name": "suricata", "instance_id": "suricata-01"},
            "asset_resolution": {"status": "UNRESOLVED", "source_asset_id": None, "destination_asset_id": None},
            "network": {"source_ip": "10.0.0.1", "destination_ip": "8.8.8.8", "transport": "tcp"},
        }
        jsonschema.validate(valid, schema)


# ---------------------------------------------------------------------------
# Contract Baseline B — Detection and Alerting
# ---------------------------------------------------------------------------

class TestDetectionFindingSchema:
    def test_ml_finding_has_model_version_not_rule(self):
        schema = load_json_schema("events/detection-finding-v1.json")
        valid = {
            "detection_finding_id": "0198e72b-0000-7000-8000-000000000001",
            "tenant_id": "0198e728-0000-7000-8000-000000000001",
            "event_ids": ["0198e72a-0000-7000-8000-000000000001"],
            "detector_id": "network_anomaly_v1",
            "detector_version": "1.2.0",
            "model_version_id": "0198e72f-0000-7000-8000-000000000001",
            "rule_version": None,
            "finding_type": "suspicious_outbound_connection",
            "severity": "high",
            "risk_score": 82,
            "confidence": 0.91,
            "observed_at": "2026-11-06T06:30:00Z",
        }
        jsonschema.validate(valid, schema)

    def test_rule_finding_has_rule_version_not_model(self):
        schema = load_json_schema("events/detection-finding-v1.json")
        valid = {
            "detection_finding_id": "0198e72b-0000-7000-8000-000000000002",
            "tenant_id": "0198e728-0000-7000-8000-000000000001",
            "event_ids": ["0198e72a-0000-7000-8000-000000000001"],
            "detector_id": "suspicious_outbound_v1",
            "detector_version": "1.0.0",
            "model_version_id": None,
            "rule_version": "1.0",
            "finding_type": "suspicious_outbound_connection",
            "severity": "high",
            "risk_score": 82,
            "observed_at": "2026-11-06T06:30:00Z",
        }
        jsonschema.validate(valid, schema)


class TestAlertSchema:
    def test_valid_alert(self):
        schema = load_json_schema("events/alert-v1.json")
        valid = {
            "alert_id": "0198e72c-0000-7000-8000-000000000001",
            "tenant_id": "0198e728-0000-7000-8000-000000000001",
            "incident_id": None,
            "alert_type": "suspicious_outbound_connection",
            "severity": "high",
            "risk_score": 82,
            "status": "NEW",
            "detection_finding_ids": ["0198e72b-0000-7000-8000-000000000001"],
            "event_ids": ["0198e72a-0000-7000-8000-000000000001"],
            "evidence_ids": [],
            "affected_asset_ids": [],
            "summary": "Unusual outbound connection.",
            "observed_at": "2026-11-06T06:30:00Z",
            "created_at": "2026-11-06T06:30:05Z",
        }
        jsonschema.validate(valid, schema)


# ---------------------------------------------------------------------------
# Contract Baseline D — Response
# ---------------------------------------------------------------------------

class TestActionCommandSchema:
    def test_dispatched_not_in_status_enum(self):
        """DISPATCHED must NOT be a valid command status."""
        schema = load_json_schema("response/action-command-v1.json")
        status_prop = schema["properties"]["status"]
        assert "DISPATCHED" not in status_prop["enum"]

    def test_signed_command_has_all_required_fields(self):
        schema = load_json_schema("response/action-command-v1.json")
        required = set(schema["required"])
        assert "signature" in required
        assert "nonce" in required
        assert "idempotency_key" in required
        assert "policy_version_id" in required
        assert "approval_id" in required
        assert "proposal_id" in required


class TestExecutionResultSchema:
    def test_execution_and_verification_are_separate(self):
        """execution_status and verification_status must have different enum values."""
        schema = load_json_schema("response/execution-result-v1.json")
        exec_enum = set(schema["properties"]["execution_status"]["enum"])
        verif_enum = set(schema["properties"]["verification_status"]["enum"])
        assert exec_enum.isdisjoint(verif_enum)
        assert "SUCCEEDED" in exec_enum
        assert "VERIFIED" in verif_enum
        assert "SUCCEEDED" not in verif_enum
        assert "VERIFIED" not in exec_enum


# ---------------------------------------------------------------------------
# OpenAPI specs
# ---------------------------------------------------------------------------

class TestOpenAPISpecs:
    def test_edge_api_has_mtls_security(self):
        data = load_yaml("openapi/edge-api-v1.yaml")
        schemes = data.get("components", {}).get("securitySchemes", {})
        assert "mutualTLS" in schemes

    def test_public_api_has_bearer_auth(self):
        data = load_yaml("openapi/public-api-v1.yaml")
        schemes = data.get("components", {}).get("securitySchemes", {})
        assert "bearerAuth" in schemes
        assert schemes["bearerAuth"]["scheme"] == "bearer"

    def test_internal_api_not_publicly_exposed(self):
        data = load_yaml("openapi/internal-api-v1.yaml")
        # Internal API should have a non-public security scheme
        schemes = data.get("components", {}).get("securitySchemes", {})
        assert "internalServiceAuth" in schemes
        desc = schemes["internalServiceAuth"].get("description", "")
        assert "internal" in desc.lower()

    def test_all_specs_use_openapi_3_2_1(self):
        for spec_file in ["edge-api-v1.yaml", "public-api-v1.yaml", "internal-api-v1.yaml"]:
            data = load_yaml(f"openapi/{spec_file}")
            assert data["openapi"] == "3.2.1", f"{spec_file} must use OpenAPI 3.2.1"

    def test_error_responses_use_problem_details(self):
        data = load_yaml("openapi/public-api-v1.yaml")
        found_problem_json = False
        # Check both inline path responses and reusable component responses
        for resp in data.get("components", {}).get("responses", {}).values():
            if not isinstance(resp, dict):
                continue
            content = resp.get("content", {})
            if "application/problem+json" in content:
                found_problem_json = True
                break
        if not found_problem_json:
            # Also check inline responses in paths
            for path_info in data.get("paths", {}).values():
                for method_info in path_info.values():
                    if not isinstance(method_info, dict):
                        continue
                    for resp_info in method_info.get("responses", {}).values():
                        content = resp_info.get("content", {}) if isinstance(resp_info, dict) else {}
                        if "application/problem+json" in content:
                            found_problem_json = True
                            break
        assert found_problem_json, "At least one error response must use application/problem+json"
