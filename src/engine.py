"""
Incident Responder - Playbook Engine

Core orchestrator that loads playbooks, matches alerts, and executes actions.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml

from .models import Alert, Playbook, PlaybookAction, ActionResult, Incident
from .actions import ActionRegistry
from .database import Database


class PlaybookEngine:
    """Orchestrates playbook loading, alert matching, and action execution."""

    def __init__(
        self,
        playbooks_dir: Optional[str] = None,
        db: Optional[Database] = None,
        execute: bool = False,
    ):
        self.playbooks_dir = Path(playbooks_dir or self._default_playbooks_dir())
        self.db = db or Database()
        self.action_registry = ActionRegistry(execute=execute, db=self.db)
        self.execute = execute
        self.playbooks: list[Playbook] = []
        self.load_playbooks()

    @staticmethod
    def _default_playbooks_dir() -> str:
        """Find playbooks directory relative to project root or cwd."""
        src_dir = Path(__file__).resolve().parent
        candidates = [
            src_dir.parent / "config" / "playbooks",
            Path.cwd() / "config" / "playbooks",
        ]
        for path in candidates:
            if path.exists():
                return str(path)
        return str(candidates[0])

    def load_playbooks(self) -> list[Playbook]:
        """Load all YAML playbooks from the playbooks directory."""
        self.playbooks = []
        if not self.playbooks_dir.exists():
            return self.playbooks

        for yaml_file in sorted(self.playbooks_dir.glob("*.yaml")):
            try:
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)
                if data:
                    playbook = self._parse_playbook(data)
                    self.playbooks.append(playbook)
            except (yaml.YAMLError, IOError):
                pass

        return self.playbooks

    def _parse_playbook(self, data: dict[str, Any]) -> Playbook:
        """Parse a YAML dict into a Playbook object."""
        actions = []
        for action_data in data.get("actions", []):
            actions.append(PlaybookAction.from_dict(action_data))

        return Playbook(
            name=data.get("name", "unnamed"),
            description=data.get("description", ""),
            trigger_rule_ids=data.get("trigger_rule_ids", []),
            min_severity=data.get("min_severity", "Low"),
            actions=actions,
        )

    def find_matching_playbooks(self, alert: Alert) -> list[Playbook]:
        """Find all playbooks that match the given alert."""
        return [pb for pb in self.playbooks if pb.matches_alert(alert)]

    def run_alert(self, alert: Alert) -> Optional[Incident]:
        """Run all matching playbooks for the given alert.

        Returns the first Incident created.
        Supports conditional actions and stop_on_failure.
        """
        matching = self.find_matching_playbooks(alert)
        if not matching:
            return None

        incident = Incident(
            alert=alert,
            playbook_name=matching[0].name,
            playbook_description=matching[0].description,
            status="open",
            created_at=datetime.now().isoformat(),
        )

        incident.id = self.db.create_incident(incident)

        for playbook in matching:
            for action_def in playbook.actions:
                # Evaluate condition — skip if condition not met
                if not action_def.evaluate_condition(alert):
                    skipped = ActionResult(
                        action_type=action_def.type,
                        status="skipped",
                        message=f"Condition not met: {action_def.condition}" if action_def.condition else "Skipped by condition",
                        data={"condition": action_def.condition, "reason": "condition_not_met"},
                    )
                    incident.results.append(skipped)
                    self.db.log_action(incident.id, skipped)
                    continue

                handler = self.action_registry.get_handler(action_def.type)
                result = handler.execute_action(alert, action_def.params)
                incident.results.append(result)
                self.db.log_action(incident.id, result)

                # Stop on failure if configured
                if action_def.stop_on_failure and result.status == "failure":
                    stop_msg = ActionResult(
                        action_type="__stop__",
                        status="skipped",
                        message=f"Playbook '{playbook.name}' stopped after {action_def.type} failure",
                        data={"reason": "stop_on_failure", "failed_action": action_def.type},
                    )
                    incident.results.append(stop_msg)
                    self.db.log_action(incident.id, stop_msg)
                    break

        return incident

    def list_playbooks(self) -> list[dict]:
        """Return summary of loaded playbooks."""
        return [
            {
                "name": pb.name,
                "description": pb.description,
                "trigger_rule_ids": pb.trigger_rule_ids,
                "min_severity": pb.min_severity,
                "actions": [a.type for a in pb.actions],
            }
            for pb in self.playbooks
        ]
