"""Tests for the Database module."""

import tempfile
from pathlib import Path

import pytest

from src.models import Alert, ActionResult, Incident
from src.database import Database


@pytest.fixture
def db():
    """Create a temporary database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Database(str(Path(tmpdir) / "test.db"))


@pytest.fixture
def sample_incident():
    return Incident(
        alert=Alert(
            rule_id="DET-001",
            title="SSH Brute Force",
            severity="High",
            source_ip="192.168.1.100",
            description="Brute force detected",
            timestamp="2024-01-15T10:30:00",
            count=15,
            mitre_technique="T1110 - Brute Force",
        ),
        playbook_name="block_ssh",
        playbook_description="Block SSH brute force",
        status="open",
        created_at="2024-01-15T10:30:00",
    )


class TestDatabase:
    def test_create_incident(self, db, sample_incident):
        inc_id = db.create_incident(sample_incident)
        assert inc_id > 0

    def test_get_incident(self, db, sample_incident):
        inc_id = db.create_incident(sample_incident)
        loaded = db.get_incident(inc_id)

        assert loaded is not None
        assert loaded.id == inc_id
        assert loaded.alert.rule_id == "DET-001"
        assert loaded.alert.source_ip == "192.168.1.100"
        assert loaded.playbook_name == "block_ssh"
        assert loaded.status == "open"

    def test_get_nonexistent_incident(self, db):
        loaded = db.get_incident(999)
        assert loaded is None

    def test_log_action(self, db, sample_incident):
        inc_id = db.create_incident(sample_incident)
        result = ActionResult(
            action_type="firewall_block",
            status="success",
            message="Blocked IP",
            data={"ip": "192.168.1.100"},
        )
        action_id = db.log_action(inc_id, result)
        assert action_id > 0

    def test_incident_includes_actions(self, db, sample_incident):
        inc_id = db.create_incident(sample_incident)

        db.log_action(inc_id, ActionResult(
            action_type="notify", status="success", message="Notified",
        ))
        db.log_action(inc_id, ActionResult(
            action_type="firewall_block", status="success", message="Blocked",
        ))

        loaded = db.get_incident(inc_id)
        assert len(loaded.results) == 2
        assert loaded.results[0].action_type == "notify"
        assert loaded.results[1].action_type == "firewall_block"

    def test_list_incidents(self, db, sample_incident):
        db.create_incident(sample_incident)
        db.create_incident(sample_incident)
        db.create_incident(sample_incident)

        incidents = db.list_incidents()
        assert len(incidents) == 3

    def test_list_incidents_filter_by_status(self, db, sample_incident):
        inc1 = db.create_incident(sample_incident)
        inc2 = db.create_incident(sample_incident)

        db.close_incident(inc2)

        open_incs = db.list_incidents(status="open")
        closed_incs = db.list_incidents(status="closed")

        assert len(open_incs) == 1
        assert len(closed_incs) == 1

    def test_close_incident(self, db, sample_incident):
        inc_id = db.create_incident(sample_incident)
        result = db.close_incident(inc_id)

        assert result is True
        loaded = db.get_incident(inc_id)
        assert loaded.status == "closed"
        assert loaded.resolved_at is not None

    def test_close_nonexistent_incident(self, db):
        result = db.close_incident(999)
        assert result is False

    def test_get_stats_empty(self, db):
        stats = db.get_stats()
        assert stats["total_incidents"] == 0
        assert stats["open"] == 0
        assert stats["closed"] == 0

    def test_get_stats_with_data(self, db, sample_incident):
        db.create_incident(sample_incident)
        inc2 = db.create_incident(sample_incident)
        db.close_incident(inc2)

        stats = db.get_stats()
        assert stats["total_incidents"] == 2
        assert stats["open"] == 1
        assert stats["closed"] == 1
        assert stats["severity_breakdown"]["High"] == 2

    def test_incident_alert_fields(self, db):
        """Verify all alert fields are stored and retrieved."""
        alert = Alert(
            rule_id="DET-005",
            title="Port Scan",
            severity="Medium",
            source_ip="10.0.0.1",
            description="Port scan detected",
            timestamp="2024-01-15T12:00:00",
            count=25,
            mitre_technique="T1046 - Scanning",
            recommendation="Block the IP",
        )
        incident = Incident(
            alert=alert,
            playbook_name="test",
            playbook_description="Test playbook",
        )
        inc_id = db.create_incident(incident)
        loaded = db.get_incident(inc_id)

        assert loaded.alert.rule_id == "DET-005"
        assert loaded.alert.severity == "Medium"
        assert loaded.alert.source_ip == "10.0.0.1"
        assert loaded.alert.count == 25
        assert loaded.alert.mitre_technique == "T1046 - Scanning"
        assert loaded.playbook_name == "test"
