"""
Incident Responder - SQLite Database

Tracks incidents and action results with a persistent SQLite database.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import Alert, ActionResult, Incident


class Database:
    """SQLite-backed incident database."""

    def __init__(self, db_path: str = "~/.incident_responder/incidents.db"):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_rule_id TEXT NOT NULL,
                    alert_title TEXT,
                    alert_severity TEXT,
                    alert_source_ip TEXT,
                    alert_description TEXT,
                    alert_timestamp TEXT,
                    alert_count INTEGER DEFAULT 1,
                    mitre_technique TEXT,
                    playbook_name TEXT,
                    playbook_description TEXT,
                    status TEXT DEFAULT 'open',
                    created_at TEXT NOT NULL,
                    resolved_at TEXT
                );

                CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    action_type TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    message TEXT,
                    data TEXT,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
                );
            """)

    def create_incident(self, incident: Incident) -> int:
        """Insert a new incident and return its ID."""
        with self._get_conn() as conn:
            cursor = conn.execute(
                """INSERT INTO incidents
                   (alert_rule_id, alert_title, alert_severity, alert_source_ip,
                    alert_description, alert_timestamp, alert_count, mitre_technique,
                    playbook_name, playbook_description, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    incident.alert.rule_id,
                    incident.alert.title,
                    incident.alert.severity,
                    incident.alert.source_ip,
                    incident.alert.description,
                    incident.alert.timestamp,
                    incident.alert.count,
                    incident.alert.mitre_technique,
                    incident.playbook_name,
                    incident.playbook_description,
                    incident.status,
                    incident.created_at,
                ),
            )
            return cursor.lastrowid

    def log_action(self, incident_id: int, result: ActionResult) -> int:
        """Record an action result for an incident."""
        with self._get_conn() as conn:
            cursor = conn.execute(
                """INSERT INTO actions
                   (incident_id, action_type, status, message, data, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    incident_id,
                    result.action_type,
                    result.status,
                    result.message,
                    json.dumps(result.data),
                    result.timestamp,
                ),
            )
            return cursor.lastrowid

    def get_incident(self, incident_id: int) -> Optional[Incident]:
        """Retrieve an incident by ID, including its actions."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()

            if not row:
                return None

            incident = Incident(
                id=row["id"],
                alert=Alert(
                    rule_id=row["alert_rule_id"],
                    title=row["alert_title"] or "",
                    severity=row["alert_severity"] or "Low",
                    source_ip=row["alert_source_ip"] or "",
                    description=row["alert_description"] or "",
                    timestamp=row["alert_timestamp"] or "",
                    count=row["alert_count"] or 1,
                    mitre_technique=row["mitre_technique"] or "",
                ),
                playbook_name=row["playbook_name"] or "",
                playbook_description=row["playbook_description"] or "",
                status=row["status"],
                created_at=row["created_at"],
                resolved_at=row["resolved_at"],
            )

            # Fetch related actions
            action_rows = conn.execute(
                "SELECT * FROM actions WHERE incident_id = ? ORDER BY timestamp",
                (incident_id,),
            ).fetchall()

            for arow in action_rows:
                data = {}
                if arow["data"]:
                    try:
                        data = json.loads(arow["data"])
                    except json.JSONDecodeError:
                        data = {"raw": arow["data"]}

                incident.results.append(ActionResult(
                    action_type=arow["action_type"],
                    status=arow["status"],
                    message=arow["message"] or "",
                    data=data,
                    timestamp=arow["timestamp"],
                ))

            return incident

    def list_incidents(self, status: Optional[str] = None, limit: int = 50) -> list[Incident]:
        """List incidents, optionally filtered by status."""
        with self._get_conn() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM incidents WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()

            incidents = []
            for row in rows:
                incidents.append(Incident(
                    id=row["id"],
                    alert=Alert(
                        rule_id=row["alert_rule_id"],
                        title=row["alert_title"] or "",
                        severity=row["alert_severity"] or "Low",
                        source_ip=row["alert_source_ip"] or "",
                        description=row["alert_description"] or "",
                        timestamp=row["alert_timestamp"] or "",
                        count=row["alert_count"] or 1,
                        mitre_technique=row["mitre_technique"] or "",
                    ),
                    playbook_name=row["playbook_name"] or "",
                    playbook_description=row["playbook_description"] or "",
                    status=row["status"],
                    created_at=row["created_at"],
                    resolved_at=row["resolved_at"],
                ))
            return incidents

    def close_incident(self, incident_id: int) -> bool:
        """Mark an incident as closed."""
        with self._get_conn() as conn:
            cursor = conn.execute(
                "UPDATE incidents SET status = 'closed', resolved_at = ? WHERE id = ?",
                (datetime.now().isoformat(), incident_id),
            )
            return cursor.rowcount > 0

    def get_stats(self) -> dict:
        """Get summary statistics from the database."""
        with self._get_conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            open_count = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE status = 'open'"
            ).fetchone()[0]
            closed = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE status = 'closed'"
            ).fetchone()[0]

            severity_rows = conn.execute(
                """SELECT alert_severity, COUNT(*) as cnt
                   FROM incidents GROUP BY alert_severity ORDER BY cnt DESC"""
            ).fetchall()

            return {
                "total_incidents": total,
                "open": open_count,
                "closed": closed,
                "severity_breakdown": {
                    row["alert_severity"]: row["cnt"] for row in severity_rows
                },
            }
