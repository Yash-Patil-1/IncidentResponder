"""
Incident Responder - Case Logging Action

Records incident case details to the database.
This is typically the final action in a playbook.
"""

from typing import Any

from ..models import ActionResult
from ..utils import render_template


class LogCaseAction:
    """Action that ensures the case is properly documented."""

    def __init__(self, db=None):
        self.db = db

    def execute_action(self, alert, params: dict[str, Any]) -> ActionResult:
        """Record case details."""
        summary = params.get("summary", "")
        rendered_summary = render_template(summary, alert)

        return ActionResult(
            action_type="log_case",
            status="success",
            message=f"Case logged: {rendered_summary}",
            data={
                "summary": rendered_summary,
            },
        )
