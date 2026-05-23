"""
Incident Responder - Action Registry

Maps action type strings to their handler functions.
"""

from typing import Any

from .firewall import FirewallBlockAction
from .enrich import EnrichIPAction
from .notify import NotifyAction
from .log_case import LogCaseAction
from .webhook import WebhookAction


class ActionRegistry:
    """Registry mapping action type names to handler instances."""

    def __init__(self, execute: bool = False, db=None):
        self._handlers: dict[str, Any] = {
            "firewall_block": FirewallBlockAction(execute=execute),
            "enrich_ip": EnrichIPAction(),
            "notify": NotifyAction(),
            "webhook": WebhookAction(),
            "log_case": LogCaseAction(db=db),
        }

    def get_handler(self, action_type: str):
        """Get the handler for a given action type."""
        handler = self._handlers.get(action_type)
        if handler is None:
            raise ValueError(
                f"Unknown action type: {action_type}. "
                f"Available: {list(self._handlers.keys())}"
            )
        return handler

    def list_actions(self) -> list[str]:
        """List all registered action types."""
        return list(self._handlers.keys())
