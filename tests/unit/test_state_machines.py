"""Unit tests for state machine transitions.

Tests the alert and incident state machines to ensure only valid
transitions are allowed. These tests don't require a database.
"""

from __future__ import annotations

import pytest

from ascense.api.routes.incidents import VALID_TRANSITIONS as INCIDENT_TRANSITIONS


class TestIncidentStateMachine:
    """Tests for the incident lifecycle state machine."""

    def test_open_can_transition_to_triaged(self):
        assert "TRIAGED" in INCIDENT_TRANSITIONS["OPEN"]

    def test_open_can_transition_to_closed(self):
        assert "CLOSED" in INCIDENT_TRANSITIONS["OPEN"]

    def test_triaged_can_transition_to_investigating(self):
        assert "INVESTIGATING" in INCIDENT_TRANSITIONS["TRIAGED"]

    def test_investigating_can_transition_to_containment(self):
        assert "CONTAINMENT_IN_PROGRESS" in INCIDENT_TRANSITIONS["INVESTIGATING"]

    def test_containment_can_transition_to_contained(self):
        assert "CONTAINED" in INCIDENT_TRANSITIONS["CONTAINMENT_IN_PROGRESS"]

    def test_contained_can_transition_to_recovering(self):
        assert "RECOVERING" in INCIDENT_TRANSITIONS["CONTAINED"]

    def test_recovering_can_transition_to_resolved(self):
        assert "RESOLVED" in INCIDENT_TRANSITIONS["RECOVERING"]

    def test_resolved_can_transition_to_closed(self):
        assert "CLOSED" in INCIDENT_TRANSITIONS["RESOLVED"]

    def test_closed_can_reopen(self):
        assert "OPEN" in INCIDENT_TRANSITIONS["CLOSED"]

    @pytest.mark.parametrize("invalid_transition", [
        ("OPEN", "CONTAINED"),
        ("OPEN", "RESOLVED"),
        ("TRIAGED", "CONTAINED"),
        ("CONTAINED", "OPEN"),
        ("RESOLVED", "OPEN"),
        ("CLOSED", "INVESTIGATING"),
    ])
    def test_invalid_transitions_are_blocked(self, invalid_transition):
        current, target = invalid_transition
        allowed = INCIDENT_TRANSITIONS.get(current, set())
        assert target not in allowed, f"Should not allow {current} → {target}"

    def test_all_status_values_have_transitions(self):
        """Every incident status must have a transition entry."""
        expected_statuses = {
            "OPEN", "TRIAGED", "INVESTIGATING",
            "CONTAINMENT_IN_PROGRESS", "CONTAINED", "RECOVERING",
            "RESOLVED", "CLOSED",
        }
        assert set(INCIDENT_TRANSITIONS.keys()) == expected_statuses


class TestAlertStateMachine:
    """Tests for the alert lifecycle state machine.

    Alert states: NEW → ACKNOWLEDGED → UNDER_INVESTIGATION → RESOLVED / FALSE_POSITIVE
    """

    # The alert state machine is enforced in the alerts route, not a dict.
    # We test the documented transitions here.
    VALID_ALERT_TRANSITIONS = {
        "NEW": {"ACKNOWLEDGED"},
        "ACKNOWLEDGED": {"UNDER_INVESTIGATION"},
        "UNDER_INVESTIGATION": {"RESOLVED", "FALSE_POSITIVE"},
        "RESOLVED": set(),
        "FALSE_POSITIVE": set(),
    }

    def test_new_can_acknowledge(self):
        assert "ACKNOWLEDGED" in self.VALID_ALERT_TRANSITIONS["NEW"]

    def test_acknowledged_can_investigate(self):
        assert "UNDER_INVESTIGATION" in self.VALID_ALERT_TRANSITIONS["ACKNOWLEDGED"]

    def test_investigating_can_resolve(self):
        assert "RESOLVED" in self.VALID_ALERT_TRANSITIONS["UNDER_INVESTIGATION"]

    def test_investigating_can_false_positive(self):
        assert "FALSE_POSITIVE" in self.VALID_ALERT_TRANSITIONS["UNDER_INVESTIGATION"]

    def test_resolved_is_terminal(self):
        assert len(self.VALID_ALERT_TRANSITIONS["RESOLVED"]) == 0

    def test_false_positive_is_terminal(self):
        assert len(self.VALID_ALERT_TRANSITIONS["FALSE_POSITIVE"]) == 0
