"""
Incident Responder - Report Generator

Generates HTML and JSON reports from incident data.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import Incident


class IncidentReporter:
    """Generates incident response reports in HTML and JSON formats."""

    def __init__(self, output_dir: str = "reports", templates_dir: Optional[str] = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        if templates_dir:
            self.templates_dir = Path(templates_dir)
        else:
            self.templates_dir = Path(__file__).resolve().parent / "templates"

    def generate_report(self, incident: Incident, fmt: str = "html") -> Optional[str]:
        """Generate a report in the specified format."""
        if fmt == "html":
            return self._generate_html(incident)
        elif fmt == "json":
            return self._generate_json(incident)
        return None

    def _generate_json(self, incident: Incident) -> str:
        """Generate a JSON report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"ir_incident_{incident.id}_{timestamp}.json"
        report_path = str(self.output_dir / report_name)

        with open(report_path, "w") as f:
            json.dump(incident.to_dict(), f, indent=2)

        return report_path

    def _generate_html(self, incident: Incident) -> str:
        """Generate an HTML report (inline, no Jinja2 dependency)."""
        severity_color = {
            "Critical": "#dc3545",
            "High": "#fd7e14",
            "Medium": "#ffc107",
            "Low": "#28a745",
        }.get(incident.alert.severity, "#6c757d")

        actions_rows = ""
        for i, result in enumerate(incident.results, 1):
            status_icon = "✅" if result.status == "success" else "❌" if result.status == "failure" else "⏭"
            actions_rows += f"""
            <tr>
                <td>{i}</td>
                <td><code>{result.action_type}</code></td>
                <td><span class="status-{result.status}">{status_icon} {result.status}</span></td>
                <td>{result.message}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Incident #{incident.id} - IR Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        h1 {{ color: #f0f6fc; font-size: 1.8rem; margin-bottom: 0.5rem; }}
        h2 {{ color: #f0f6fc; font-size: 1.3rem; margin: 1.5rem 0 0.5rem; }}
        .header {{ border-bottom: 1px solid #30363d; padding-bottom: 1rem; margin-bottom: 1.5rem; }}
        .badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 2em; font-size: 0.8rem; font-weight: 600; }}
        .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1.25rem; margin-bottom: 1rem; }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem 2rem; }}
        .grid .label {{ color: #8b949e; font-size: 0.85rem; }}
        .grid .value {{ color: #c9d1d9; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
        th {{ text-align: left; padding: 0.5rem; border-bottom: 2px solid #30363d; color: #8b949e; font-size: 0.85rem; }}
        td {{ padding: 0.5rem; border-bottom: 1px solid #21262d; font-size: 0.9rem; }}
        code {{ background: #1c2128; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.85rem; }}
        .status-success {{ color: #3fb950; }}
        .status-failure {{ color: #f85149; }}
        .status-skipped {{ color: #d29922; }}
        .status-pending {{ color: #8b949e; }}
        .footer {{ margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #30363d; color: #8b949e; font-size: 0.85rem; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 Incident #{incident.id}</h1>
            <p style="color: #8b949e;">{incident.playbook_name}</p>
        </div>

        <div class="card">
            <h2>Alert Summary</h2>
            <p style="margin: 0.75rem 0;">
                <span class="badge" style="background: {severity_color}; color: #000;">{incident.alert.severity}</span>
                <strong>{incident.alert.title}</strong> <code>{incident.alert.rule_id}</code>
            </p>
            <div class="grid">
                <div><span class="label">Source IP</span><div class="value">{incident.alert.source_ip or 'N/A'}</div></div>
                <div><span class="label">Status</span><div class="value">{incident.status}</div></div>
                <div><span class="label">Events</span><div class="value">{incident.alert.count}</div></div>
                <div><span class="label">MITRE</span><div class="value">{incident.alert.mitre_technique or 'N/A'}</div></div>
                <div><span class="label">Created</span><div class="value">{incident.created_at[:19]}</div></div>
                <div><span class="label">Resolved</span><div class="value">{incident.resolved_at or '—'}</div></div>
            </div>
        </div>

        <div class="card">
            <h2>Actions Taken</h2>
            <table>
                <thead>
                    <tr><th>#</th><th>Action</th><th>Status</th><th>Message</th></tr>
                </thead>
                <tbody>
                    {actions_rows}
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p>Generated by Incident Responder v1.0.0 at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>"""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"ir_incident_{incident.id}_{timestamp}.html"
        report_path = str(self.output_dir / report_name)

        with open(report_path, "w") as f:
            f.write(html)

        return report_path
