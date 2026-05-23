"""
Incident Responder - Data Models

Defines the core data structures: Alert, Playbook, ActionResult, Incident.
Alert is designed for compatibility with LogSentinel's alert output format.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class Alert:
    """A security alert — compatible with LogSentinel's alert schema."""

    rule_id: str = ""
    title: str = ""
    severity: str = "Low"
    source_ip: str = ""
    description: str = ""
    timestamp: str = ""
    count: int = 1
    mitre_technique: str = ""
    recommendation: str = ""
    destination_ip: str = ""
    log_source: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Alert":
        """Create an Alert from a dictionary (JSON deserialization)."""
        return cls(
            rule_id=data.get("rule_id", ""),
            title=data.get("title", ""),
            severity=data.get("severity", "Low"),
            source_ip=data.get("source_ip", ""),
            description=data.get("description", ""),
            timestamp=str(data.get("timestamp", "")),
            count=data.get("count", 1),
            mitre_technique=data.get("mitre_technique", ""),
            recommendation=data.get("recommendation", ""),
            destination_ip=data.get("destination_ip", ""),
            log_source=data.get("log_source", ""),
            raw=data,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "description": self.description,
            "timestamp": self.timestamp,
            "count": self.count,
            "mitre_technique": self.mitre_technique,
            "recommendation": self.recommendation,
            "destination_ip": self.destination_ip,
            "log_source": self.log_source,
        }


@dataclass
class PlaybookAction:
    """A single action step within a playbook.

    Supports conditional execution:
      - condition: Python expression evaluated against alert dict.
                   Only runs action if condition is truthy.
                   Example: "alert.severity == 'High' and alert.count >= 10"
      - stop_on_failure: If True, stops the playbook when this action fails.
                   Subsequent actions in the playbook are skipped.
    """

    type: str  # 'firewall_block', 'enrich_ip', 'notify', 'log_case'
    params: dict[str, Any] = field(default_factory=dict)
    condition: str = ""  # Python expression (empty = always run)
    stop_on_failure: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PlaybookAction":
        return cls(
            type=data.get("type", ""),
            params=data.get("params", {}),
            condition=data.get("condition", ""),
            stop_on_failure=data.get("stop_on_failure", False),
        )

    def evaluate_condition(self, alert: "Alert") -> bool:
        """Evaluate the condition expression against an alert.

        Uses Python's eval() with a restricted namespace containing
        only the alert dict fields. The alert fields are also available
        as top-level variables for convenience, and via `alert.` prefix
        using a SimpleNamespace wrapper.

        Examples:
          condition: "severity == 'High'"
          condition: "count >= 10"
          condition: "source_ip and count > 5"
          condition: "alert.severity == 'Critical' or alert.count >= 50"
        """
        if not self.condition:
            return True  # No condition means always run

        alert_dict = alert.to_dict()
        # Build a namespace class for dotted access (alert.severity)
        from types import SimpleNamespace
        alert_ns = SimpleNamespace(**alert_dict)

        # Build a safe namespace with alert fields
        safe_namespace = {
            "alert": alert_ns,
            **alert_dict,  # Top-level access: severity, count, etc.
            "True": True,
            "False": False,
            "None": None,
            "int": int,
            "float": float,
            "str": str,
            "len": len,
            "abs": abs,
            "any": any,
            "all": all,
            "min": min,
            "max": max,
        }
        try:
            result = eval(self.condition, {"__builtins__": {}}, safe_namespace)
            return bool(result)
        except Exception:
            # If evaluation fails, skip the action to be safe
            return False


@dataclass
class Playbook:
    """A YAML-defined automated response playbook."""

    name: str = ""
    description: str = ""
    trigger_rule_ids: list[str] = field(default_factory=list)
    min_severity: str = "Low"
    actions: list[PlaybookAction] = field(default_factory=list)

    def matches_alert(self, alert: Alert) -> bool:
        """Check if this playbook should trigger for the given alert.

        Supports wildcard (*) in trigger_rule_ids which matches any rule_id.
        """
        severity_levels = ["Low", "Medium", "High", "Critical"]
        alert_sev_idx = severity_levels.index(alert.severity) if alert.severity in severity_levels else 0
        min_sev_idx = severity_levels.index(self.min_severity) if self.min_severity in severity_levels else 0

        if alert_sev_idx < min_sev_idx:
            return False

        # Wildcard (*) matches any rule_id
        if "*" in self.trigger_rule_ids:
            return True

        return alert.rule_id in self.trigger_rule_ids


@dataclass
class ActionResult:
    """Result of executing a single playbook action."""

    action_type: str = ""
    status: str = "pending"  # 'pending', 'success', 'failure', 'skipped'
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "status": self.status,
            "message": self.message,
            "data": self.data,
            "timestamp": self.timestamp,
        }


@dataclass
class Incident:
    """A tracked incident with all playbook execution results."""

    id: int = 0
    alert: Alert = field(default_factory=Alert)
    playbook_name: str = ""
    playbook_description: str = ""
    status: str = "open"  # 'open', 'closed'
    results: list[ActionResult] = field(default_factory=list)
    created_at: str = ""
    resolved_at: Optional[str] = None

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "alert": self.alert.to_dict(),
            "playbook_name": self.playbook_name,
            "playbook_description": self.playbook_description,
            "status": self.status,
            "results": [r.to_dict() for r in self.results],
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
        }
