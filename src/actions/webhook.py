"""
Incident Responder - Webhook Notification Action

Sends alert notifications to Slack and Discord webhooks.
Webhook URLs are configured via environment variables or playbook params.

Environment Variables:
    SLACK_WEBHOOK_URL    — Slack Incoming Webhook URL
    DISCORD_WEBHOOK_URL  — Discord Webhook URL
"""

import json
import os
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from ..models import ActionResult
from ..utils import render_template


class WebhookAction:
    """Action that sends notifications via Slack or Discord webhooks."""

    def __init__(self):
        self.slack_url = os.environ.get("SLACK_WEBHOOK_URL", "")
        self.discord_url = os.environ.get("DISCORD_WEBHOOK_URL", "")

    def _send_slack(self, message: str, webhook_url: str) -> tuple[bool, str]:
        """Send a message to a Slack webhook."""
        payload = json.dumps({"text": message}).encode("utf-8")
        try:
            req = Request(
                webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=15) as response:
                body = response.read().decode()
                # Slack returns "ok" for success
                if response.status == 200 and body == "ok":
                    return True, "Slack notification sent successfully"
                return True, f"Slack responded: {body[:100]}"
        except HTTPError as e:
            return False, f"Slack HTTP {e.code}: {e.reason}"
        except URLError as e:
            return False, f"Slack connection failed: {e.reason}"
        except OSError as e:
            return False, f"Slack error: {e}"

    def _send_discord(self, message: str, webhook_url: str) -> tuple[bool, str]:
        """Send a message to a Discord webhook."""
        payload = json.dumps({"content": message}).encode("utf-8")
        try:
            req = Request(
                webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=15) as response:
                # Discord returns 204 No Content on success
                return True, "Discord notification sent successfully"
        except HTTPError as e:
            return False, f"Discord HTTP {e.code}: {e.reason}"
        except URLError as e:
            return False, f"Discord connection failed: {e.reason}"
        except OSError as e:
            return False, f"Discord error: {e}"

    def execute_action(self, alert, params: dict[str, Any]) -> ActionResult:
        """Send a webhook notification."""
        message = params.get("message", "Alert triggered")
        webhook_type = params.get("type", "slack")  # 'slack' or 'discord'
        custom_url = params.get("url", "")  # Optional per-playbook override

        rendered_message = render_template(message, alert)

        data = {
            "type": webhook_type,
            "message": rendered_message,
        }

        if webhook_type == "slack":
            webhook_url = custom_url or self.slack_url
            data["webhook_url_specified"] = bool(webhook_url)

            if not webhook_url:
                return ActionResult(
                    action_type="webhook",
                    status="skipped",
                    message="SLACK_WEBHOOK_URL not set (set env var or pass 'url' in params)",
                    data=data,
                )

            success, msg = self._send_slack(rendered_message, webhook_url)
            data["webhook_url"] = webhook_url[:50] + "..." if len(webhook_url) > 50 else webhook_url

            return ActionResult(
                action_type="webhook",
                status="success" if success else "failure",
                message=msg,
                data=data,
            )

        elif webhook_type == "discord":
            webhook_url = custom_url or self.discord_url
            data["webhook_url_specified"] = bool(webhook_url)

            if not webhook_url:
                return ActionResult(
                    action_type="webhook",
                    status="skipped",
                    message="DISCORD_WEBHOOK_URL not set (set env var or pass 'url' in params)",
                    data=data,
                )

            success, msg = self._send_discord(rendered_message, webhook_url)
            data["webhook_url"] = webhook_url[:50] + "..." if len(webhook_url) > 50 else webhook_url

            return ActionResult(
                action_type="webhook",
                status="success" if success else "failure",
                message=msg,
                data=data,
            )

        else:
            return ActionResult(
                action_type="webhook",
                status="skipped",
                message=f"Unknown webhook type: {webhook_type} (use 'slack' or 'discord')",
                data=data,
            )
