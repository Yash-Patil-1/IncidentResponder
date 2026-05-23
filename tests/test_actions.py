"""Tests for action handlers."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from src.models import Alert, ActionResult
from src.actions.firewall import FirewallBlockAction
from src.actions.notify import NotifyAction
from src.actions.log_case import LogCaseAction
from src.actions.webhook import WebhookAction
from src.actions import ActionRegistry


@pytest.fixture
def sample_alert():
    return Alert(
        rule_id="DET-001",
        title="SSH Brute Force",
        severity="High",
        source_ip="192.168.1.100",
        count=15,
        mitre_technique="T1110 - Brute Force",
    )


class TestFirewallBlockAction:
    def test_dry_run_mode(self, sample_alert):
        action = FirewallBlockAction(execute=False)
        result = action.execute_action(sample_alert, {})

        assert result.status == "success"
        assert "[DRY-RUN]" in result.message
        assert "192.168.1.100" in result.message
        assert result.data["execute_mode"] is False

    def test_execute_mode(self, sample_alert):
        action = FirewallBlockAction(execute=True)
        result = action.execute_action(sample_alert, {})

        assert result.status in ("success", "failure", "skipped")
        assert result.data["ip"] == "192.168.1.100"

    def test_no_ip_skips(self):
        action = FirewallBlockAction(execute=False)
        alert = Alert(rule_id="DET-001", severity="Low")
        result = action.execute_action(alert, {})

        assert result.status == "skipped"
        assert "No source IP" in result.message

    def test_custom_params(self, sample_alert):
        action = FirewallBlockAction(execute=False)
        result = action.execute_action(sample_alert, {
            "ip": "10.0.0.5",
            "chain": "FORWARD",
            "comment": "Custom block",
        })

        assert "[DRY-RUN]" in result.message
        assert "10.0.0.5" in result.message
        assert "FORWARD" in result.message
        assert result.data["chain"] == "FORWARD"


class TestNotifyAction:
    def test_writes_notification(self, sample_alert):
        with tempfile.TemporaryDirectory() as tmpdir:
            action = NotifyAction(log_dir=tmpdir)
            result = action.execute_action(sample_alert, {
                "message": "Test notification for {{alert.source_ip}}",
            })

            assert result.status == "success"
            assert "Notification written" in result.message

            log_path = Path(tmpdir) / "notifications.log"
            assert log_path.exists()

            lines = log_path.read_text().strip().split("\n")
            assert len(lines) == 1
            entry = json.loads(lines[0])
            assert entry["message"] == "Test notification for 192.168.1.100"
            assert entry["alert_rule_id"] == "DET-001"

    def test_template_substitution(self, sample_alert):
        with tempfile.TemporaryDirectory() as tmpdir:
            action = NotifyAction(log_dir=tmpdir)
            result = action.execute_action(sample_alert, {
                "message": "{{alert.rule_id}}: {{alert.title}} from {{alert.source_ip}} ({{alert.count}} attempts)",
            })

            assert result.status == "success"
            log_path = Path(tmpdir) / "notifications.log"
            entry = json.loads(log_path.read_text().strip())
            assert entry["message"] == "DET-001: SSH Brute Force from 192.168.1.100 (15 attempts)"


class TestLogCaseAction:
    def test_logs_case(self, sample_alert):
        action = LogCaseAction()
        result = action.execute_action(sample_alert, {
            "summary": "Case: {{alert.rule_id}} from {{alert.source_ip}}",
        })

        assert result.status == "success"
        assert "Case: DET-001 from 192.168.1.100" in result.message
        assert result.data["summary"] == "Case: DET-001 from 192.168.1.100"


class TestWebhookAction:
    def test_skipped_when_no_url(self, sample_alert):
        """Without webhook URLs set, both types should skip gracefully."""
        # Ensure env vars are not set
        for env_var in ["SLACK_WEBHOOK_URL", "DISCORD_WEBHOOK_URL"]:
            os.environ.pop(env_var, None)

        action = WebhookAction()

        result = action.execute_action(sample_alert, {
            "type": "slack",
            "message": "Test alert",
        })
        assert result.status == "skipped"
        assert "SLACK_WEBHOOK_URL not set" in result.message

        result = action.execute_action(sample_alert, {
            "type": "discord",
            "message": "Test alert",
        })
        assert result.status == "skipped"
        assert "DISCORD_WEBHOOK_URL not set" in result.message

    def test_template_substitution(self, sample_alert):
        """Verify template rendering in webhook messages."""
        for env_var in ["SLACK_WEBHOOK_URL", "DISCORD_WEBHOOK_URL"]:
            os.environ.pop(env_var, None)

        action = WebhookAction()
        result = action.execute_action(sample_alert, {
            "type": "slack",
            "message": "{{alert.rule_id}}: {{alert.title}} from {{alert.source_ip}}",
        })

        assert result.status == "skipped"  # No URL configured
        assert result.data["message"] == "DET-001: SSH Brute Force from 192.168.1.100"

    def test_unknown_webhook_type(self, sample_alert):
        action = WebhookAction()
        result = action.execute_action(sample_alert, {
            "type": "teams",
            "message": "Test",
        })

        assert result.status == "skipped"
        assert "Unknown webhook type" in result.message

    def test_custom_url_param(self, sample_alert):
        """When 'url' param is provided, use it instead of env var."""
        action = WebhookAction()

        # Use an invalid URL so it fails at connection, not at config check
        result = action.execute_action(sample_alert, {
            "type": "slack",
            "url": "https://hooks.slack.com/services/test/test/test",
            "message": "Test",
        })

        # Should attempt connection since URL was provided
        assert result.status in ("success", "failure")
        assert "slack" in result.data["type"] or "Slack" in result.message


class TestActionRegistry:
    def test_get_handler(self):
        registry = ActionRegistry()
        handler = registry.get_handler("notify")
        assert handler is not None
        assert handler.__class__.__name__ == "NotifyAction"

    def test_get_webhook_handler(self):
        registry = ActionRegistry()
        handler = registry.get_handler("webhook")
        assert handler is not None
        assert handler.__class__.__name__ == "WebhookAction"

    def test_get_unknown_handler(self):
        registry = ActionRegistry()
        with pytest.raises(ValueError):
            registry.get_handler("nonexistent_action")

    def test_list_actions(self):
        registry = ActionRegistry()
        actions = registry.list_actions()
        assert "firewall_block" in actions
        assert "enrich_ip" in actions
        assert "notify" in actions
        assert "webhook" in actions
        assert "log_case" in actions

    def test_registry_passes_execute_flag(self):
        registry = ActionRegistry(execute=True)
        handler = registry.get_handler("firewall_block")
        assert handler.execute is True
