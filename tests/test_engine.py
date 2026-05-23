"""Tests for the PlaybookEngine."""

import json
import os
import tempfile
from pathlib import Path

import pytest
import yaml

from src.models import Alert, Playbook, PlaybookAction
from src.engine import PlaybookEngine
from src.database import Database


@pytest.fixture
def sample_alert():
    return Alert(
        rule_id="DET-001",
        title="SSH Brute Force Detected",
        severity="High",
        source_ip="192.168.1.100",
        description="Multiple failed SSH login attempts",
        count=15,
        mitre_technique="T1110 - Brute Force",
    )


@pytest.fixture
def low_severity_alert():
    return Alert(
        rule_id="DET-003",
        title="Suspicious Request",
        severity="Low",
        source_ip="10.0.0.1",
    )


@pytest.fixture
def playbooks_dir():
    """Create a temporary directory with sample playbooks."""
    with tempfile.TemporaryDirectory() as tmpdir:
        playbook = {
            "name": "test_block_ssh",
            "description": "Block SSH brute force",
            "trigger_rule_ids": ["DET-001", "SSH_BRUTE_FORCE"],
            "min_severity": "medium",
            "actions": [
                {"type": "notify", "params": {"message": "Blocked {{alert.source_ip}}"}},
                {"type": "log_case", "params": {"summary": "Test case"}},
            ],
        }
        pb_dir = Path(tmpdir) / "playbooks"
        pb_dir.mkdir()
        with open(pb_dir / "block_ssh.yaml", "w") as f:
            yaml.dump(playbook, f)
        yield str(pb_dir)


@pytest.fixture
def db():
    """Create a temporary database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        yield Database(str(db_path))


class TestPlaybookEngine:
    def test_load_playbooks(self, playbooks_dir):
        engine = PlaybookEngine(playbooks_dir=playbooks_dir)
        assert len(engine.playbooks) == 1
        assert engine.playbooks[0].name == "test_block_ssh"
        assert engine.playbooks[0].trigger_rule_ids == ["DET-001", "SSH_BRUTE_FORCE"]

    def test_load_nonexistent_dir(self):
        engine = PlaybookEngine(playbooks_dir="/nonexistent/path")
        assert len(engine.playbooks) == 0

    def test_find_matching_playbooks(self, playbooks_dir, sample_alert):
        engine = PlaybookEngine(playbooks_dir=playbooks_dir)
        matching = engine.find_matching_playbooks(sample_alert)
        assert len(matching) == 1
        assert matching[0].name == "test_block_ssh"

    def test_no_match_for_unmatched_rule(self, playbooks_dir):
        engine = PlaybookEngine(playbooks_dir=playbooks_dir)
        alert = Alert(rule_id="NONEXISTENT", severity="High")
        matching = engine.find_matching_playbooks(alert)
        assert len(matching) == 0

    def test_no_match_for_low_severity(self, playbooks_dir, low_severity_alert):
        engine = PlaybookEngine(playbooks_dir=playbooks_dir)
        matching = engine.find_matching_playbooks(low_severity_alert)
        assert len(matching) == 0

    def test_run_alert_creates_incident(self, playbooks_dir, sample_alert, db):
        engine = PlaybookEngine(playbooks_dir=playbooks_dir, db=db)
        incident = engine.run_alert(sample_alert)

        assert incident is not None
        assert incident.id > 0
        assert incident.status == "open"
        assert incident.playbook_name == "test_block_ssh"
        assert incident.alert.rule_id == "DET-001"

    def test_run_alert_executes_actions(self, playbooks_dir, sample_alert, db):
        engine = PlaybookEngine(playbooks_dir=playbooks_dir, db=db)
        incident = engine.run_alert(sample_alert)

        assert len(incident.results) == 2
        assert incident.results[0].action_type == "notify"
        assert incident.results[1].action_type == "log_case"

    def test_run_alert_persists_to_db(self, playbooks_dir, sample_alert, db):
        engine = PlaybookEngine(playbooks_dir=playbooks_dir, db=db)
        incident = engine.run_alert(sample_alert)

        # Verify incident is in db
        loaded = db.get_incident(incident.id)
        assert loaded is not None
        assert loaded.alert.rule_id == "DET-001"
        assert len(loaded.results) == 2

    def test_run_alert_no_match(self, playbooks_dir, db):
        engine = PlaybookEngine(playbooks_dir=playbooks_dir, db=db)
        alert = Alert(rule_id="UNKNOWN", severity="Low")
        incident = engine.run_alert(alert)
        assert incident is None

    def test_list_playbooks(self, playbooks_dir):
        engine = PlaybookEngine(playbooks_dir=playbooks_dir)
        pb_list = engine.list_playbooks()
        assert len(pb_list) == 1
        assert pb_list[0]["name"] == "test_block_ssh"
        assert pb_list[0]["actions"] == ["notify", "log_case"]

    def test_playbook_matches_alert_by_rule_id(self):
        playbook = Playbook(
            name="test",
            trigger_rule_ids=["DET-001"],
            min_severity="Low",
        )
        alert = Alert(rule_id="DET-001", severity="Low")
        assert playbook.matches_alert(alert) is True

    def test_playbook_does_not_match_wrong_severity(self):
        playbook = Playbook(
            name="test",
            trigger_rule_ids=["DET-001"],
            min_severity="High",
        )
        alert = Alert(rule_id="DET-001", severity="Low")
        assert playbook.matches_alert(alert) is False

    def test_wildcard_trigger_matches_any(self):
        playbook = Playbook(
            name="test",
            trigger_rule_ids=["*"],
            min_severity="Low",
        )
        alert = Alert(rule_id="ANYTHING", severity="Low")
        assert playbook.matches_alert(alert) is True

    def test_wildcard_with_severity_filter(self):
        playbook = Playbook(
            name="test",
            trigger_rule_ids=["*"],
            min_severity="High",
        )
        low_alert = Alert(rule_id="ANY", severity="Low")
        high_alert = Alert(rule_id="ANY", severity="High")
        assert playbook.matches_alert(low_alert) is False
        assert playbook.matches_alert(high_alert) is True


class TestPlaybookActionCondition:
    """Tests for conditional action execution."""

    def test_empty_condition_always_runs(self):
        action = PlaybookAction(type="notify", condition="")
        alert = Alert(rule_id="DET-001", severity="High")
        assert action.evaluate_condition(alert) is True

    def test_severity_condition_match(self):
        action = PlaybookAction(type="notify", condition="severity == 'High'")
        alert = Alert(rule_id="DET-001", severity="High")
        assert action.evaluate_condition(alert) is True

    def test_severity_condition_no_match(self):
        action = PlaybookAction(type="notify", condition="severity == 'Critical'")
        alert = Alert(rule_id="DET-001", severity="High")
        assert action.evaluate_condition(alert) is False

    def test_count_condition(self):
        action = PlaybookAction(type="notify", condition="count >= 10")
        alert = Alert(rule_id="DET-001", count=15)
        assert action.evaluate_condition(alert) is True

        alert2 = Alert(rule_id="DET-001", count=3)
        assert action.evaluate_condition(alert2) is False

    def test_complex_condition(self):
        action = PlaybookAction(
            type="notify",
            condition="severity == 'High' and count >= 5 and source_ip != ''",
        )
        alert = Alert(rule_id="DET-001", severity="High", count=10, source_ip="1.2.3.4")
        assert action.evaluate_condition(alert) is True

        alert2 = Alert(rule_id="DET-001", severity="High", count=2)
        assert action.evaluate_condition(alert2) is False

    def test_alert_dict_access(self):
        """Test accessing via alert. prefix."""
        action = PlaybookAction(type="notify", condition="alert.severity == 'High'")
        alert = Alert(rule_id="DET-001", severity="High")
        assert action.evaluate_condition(alert) is True

    def test_invalid_condition_returns_false(self):
        """Invalid conditions should safely return False."""
        action = PlaybookAction(type="notify", condition="undefined_var > 5")
        alert = Alert(rule_id="DET-001", severity="High")
        assert action.evaluate_condition(alert) is False

    def test_invalid_syntax_returns_false(self):
        action = PlaybookAction(type="notify", condition="this is not valid @@")
        alert = Alert(rule_id="DET-001")
        assert action.evaluate_condition(alert) is False

    def test_stop_on_failure_from_dict(self):
        data = {
            "type": "firewall_block",
            "params": {"chain": "INPUT"},
            "stop_on_failure": True,
        }
        action = PlaybookAction.from_dict(data)
        assert action.type == "firewall_block"
        assert action.stop_on_failure is True

    def test_condition_from_dict(self):
        data = {
            "type": "notify",
            "params": {},
            "condition": "count >= 5",
        }
        action = PlaybookAction.from_dict(data)
        assert action.condition == "count >= 5"

    def test_true_false_in_condition(self):
        action = PlaybookAction(type="notify", condition="True")
        alert = Alert(rule_id="DET-001")
        assert action.evaluate_condition(alert) is True

        action2 = PlaybookAction(type="notify", condition="False")
        assert action2.evaluate_condition(alert) is False


class TestStopOnFailure:
    """Tests for stop_on_failure behavior in the engine."""

    def test_engine_stops_on_failure(self, db, sample_alert):
        """When an action has stop_on_failure=True and fails, subsequent actions should be skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pb_dir = Path(tmpdir) / "playbooks"
            pb_dir.mkdir()
            playbook = {
                "name": "test_stop_on_failure",
                "description": "Test stop on failure",
                "trigger_rule_ids": ["DET-001"],
                "min_severity": "Low",
                "actions": [
                    {
                        "type": "firewall_block",
                        "params": {"ip": "999.999.999.999", "chain": "INPUT"},
                        "stop_on_failure": True,
                    },
                    {"type": "notify", "params": {"message": "Should not run"}},
                ],
            }
            with open(pb_dir / "stop_test.yaml", "w") as f:
                yaml.dump(playbook, f)

            # Use execute=True so action actually tries iptables and fails
            engine = PlaybookEngine(playbooks_dir=str(pb_dir), db=db, execute=True)
            incident = engine.run_alert(sample_alert)

            assert incident is not None
            # Should have: firewall_block result + __stop__ entry but NOT notify
            action_types = [r.action_type for r in incident.results]
            assert "firewall_block" in action_types
            assert "__stop__" in action_types
            assert "notify" not in action_types, "notify should not run when firewall fails with stop_on_failure"

    def test_engine_continues_on_success(self, db, sample_alert):
        """When an action succeeds, stop_on_failure should not trigger."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pb_dir = Path(tmpdir) / "playbooks"
            pb_dir.mkdir()
            playbook = {
                "name": "test_continue_on_success",
                "description": "Test continue on success",
                "trigger_rule_ids": ["DET-001"],
                "min_severity": "Low",
                "actions": [
                    {"type": "notify", "params": {"message": "Step 1"}, "stop_on_failure": True},
                    {"type": "log_case", "params": {"summary": "Step 2"}},
                ],
            }
            with open(pb_dir / "continue_test.yaml", "w") as f:
                yaml.dump(playbook, f)

            engine = PlaybookEngine(playbooks_dir=str(pb_dir), db=db)
            incident = engine.run_alert(sample_alert)

            assert incident is not None
            action_types = [r.action_type for r in incident.results]
            assert "notify" in action_types
            assert "log_case" in action_types
            assert "__stop__" not in action_types

    def test_condition_skips_action_and_continues(self, db, sample_alert):
        """When a condition is not met, the action is skipped but the playbook continues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pb_dir = Path(tmpdir) / "playbooks"
            pb_dir.mkdir()
            playbook = {
                "name": "test_condition_skip",
                "description": "Test condition skip",
                "trigger_rule_ids": ["DET-001"],
                "min_severity": "Low",
                "actions": [
                    {
                        "type": "notify",
                        "params": {"message": "Skip this"},
                        "condition": "severity == 'Critical'",
                    },
                    {"type": "log_case", "params": {"summary": "Always runs"}},
                ],
            }
            with open(pb_dir / "condition_test.yaml", "w") as f:
                yaml.dump(playbook, f)

            engine = PlaybookEngine(playbooks_dir=str(pb_dir), db=db)
            incident = engine.run_alert(sample_alert)

            assert incident is not None
            action_types = [r.action_type for r in incident.results]
            assert "notify" in action_types  # Still executed but skipped
            assert "log_case" in action_types  # Should still run
            # Verify notify was skipped due to condition
            notify_result = [r for r in incident.results if r.action_type == "notify"][0]
            assert notify_result.status == "skipped"
            assert "condition" in notify_result.message.lower()
