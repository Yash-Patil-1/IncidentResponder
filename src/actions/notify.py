"""
Incident Responder - Notification Action

Writes structured notifications to a log file (JSONL format).
Supports {{alert.field_name}} template substitution.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..models import ActionResult
from ..utils import render_template


class NotifyAction:
    """Action that writes notifications to a log file."""

    def __init__(self, log_dir: str = "~/.incident_responder"):
        self.log_dir = Path(log_dir).expanduser()
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def _get_log_path(self) -> Path:
        """Get the notifications log file path."""
        return self.log_dir / "notifications.log"

    def execute_action(self, alert, params: dict[str, Any]) -> ActionResult:
        """Write a notification entry to the log file."""
        message = params.get("message", "Alert triggered")
        channel = params.get("channel", "file")

        rendered_message = render_template(message, alert)

        entry = {
            "timestamp": datetime.now().isoformat(),
            "channel": channel,
            "message": rendered_message,
            "alert_rule_id": alert.rule_id,
            "alert_severity": alert.severity,
            "alert_source_ip": alert.source_ip,
        }

        log_path = self._get_log_path()
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        return ActionResult(
            action_type="notify",
            status="success",
            message=f"Notification written to {log_path}",
            data={
                "log_path": str(log_path),
                "entry": entry,
            },
        )
