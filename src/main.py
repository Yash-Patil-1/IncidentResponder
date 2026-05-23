"""
Incident Responder - CLI Entry Point

Command-line tool for automated incident response playbooks.

Usage:
    incident-responder run alert.json
    incident-responder run --from-logsentinel report.json
    incident-responder list-playbooks
    incident-responder list-incidents
    incident-responder incident <id>
    incident-responder incident <id> close
    incident-responder stats
"""

import argparse
import json
import sys
import time
from pathlib import Path

from .models import Alert
from .engine import PlaybookEngine
from .database import Database
from .reporter import IncidentReporter
from . import __version__


def load_alert_from_file(filepath: str) -> Alert | None:
    """Load an alert from a JSON file (standalone or LogSentinel format)."""
    path = Path(filepath)
    if not path.exists():
        print(f"[!] File not found: {filepath}")
        return None

    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON in {filepath}: {e}")
        return None

    # Check if this is a LogSentinel report (has "alerts" array)
    if "alerts" in data and isinstance(data["alerts"], list):
        alerts = [Alert.from_dict(ad) for ad in data["alerts"]]
        if not alerts:
            print("[!] No alerts found in LogSentinel report")
            return None
        if len(alerts) > 1:
            print(f"[!] LogSentinel report contains {len(alerts)} alerts. Processing first.")
        return alerts[0]

    return Alert.from_dict(data)


def _process_single_alert(alert, args, engine, reporter) -> bool:
    """Process a single alert through the engine and report results.

    Returns True if processing succeeded, False otherwise.
    """
    matching = engine.find_matching_playbooks(alert)
    if not matching:
        print(f"[!] No matching playbooks for alert rule '{alert.rule_id}'")
        return False

    if hasattr(args, 'verbose') and args.verbose:
        print(f"[+] Matching playbooks: {', '.join(pb.name for pb in matching)}")
        print()

    incident = engine.run_alert(alert)
    if not incident:
        print("[!] Failed to process alert")
        return False

    print(f"\n{'='*60}")
    print(f"  Incident #{incident.id}: {alert.title}")
    print(f"{'='*60}")
    print(f"  Playbook: {incident.playbook_name}")
    print(f"  Status:   {incident.status}")
    print(f"  Alert:    [{alert.severity}] {alert.rule_id} - {alert.source_ip}")
    print(f"{'='*60}\n")

    for i, result in enumerate(incident.results, 1):
        icon = "✓" if result.status == "success" else "✗" if result.status == "failure" else "~"
        print(f"  Step {i}: [{icon}] {result.action_type}")
        print(f"           {result.message}\n")

    report_path = reporter.generate_report(incident, args.report_format)
    if report_path:
        print(f"[+] {args.report_format.upper()} report: {report_path}")

    return True


def _run_watch_mode(args: argparse.Namespace) -> int:
    """Run in watch mode — continuously monitor a directory for new alert files."""
    watch_dir = Path(args.watch_dir)
    watch_dir.mkdir(parents=True, exist_ok=True)
    processed_files: set[str] = set()

    # Process any existing files first
    for f in sorted(watch_dir.glob("*.json")):
        processed_files.add(str(f.resolve()))

    engine = PlaybookEngine(playbooks_dir=args.playbooks_dir, execute=args.execute)
    reporter = IncidentReporter(output_dir=args.output_dir)

    print(f"[i] Watch mode enabled — monitoring {watch_dir} every {args.watch_interval}s")
    print(f"[i] Press Ctrl+C to stop\n")

    try:
        while True:
            new_files = []
            for f in sorted(watch_dir.glob("*.json")):
                abs_path = str(f.resolve())
                if abs_path not in processed_files:
                    new_files.append(f)
                    processed_files.add(abs_path)

            for alert_file in new_files:
                timestamp = time.strftime("%H:%M:%S")
                print(f"\n[{timestamp}] New alert file detected: {alert_file.name}")
                alert = load_alert_from_file(str(alert_file))
                if alert:
                    if args.verbose:
                        print(f"  Alert: [{alert.severity}] {alert.title} ({alert.rule_id})")
                        print(f"  Mode: {'EXECUTE' if args.execute else 'DRY-RUN'}")
                    _process_single_alert(alert, args, engine, reporter)
                print()

            time.sleep(args.watch_interval)
    except KeyboardInterrupt:
        print("\n[i] Watch mode stopped")
        return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Execute the `run` command."""

    # Watch mode
    if args.watch:
        return _run_watch_mode(args)

    engine = PlaybookEngine(playbooks_dir=args.playbooks_dir, execute=args.execute)
    reporter = IncidentReporter(output_dir=args.output_dir)

    if args.from_logsentinel:
        alert = load_alert_from_file(args.from_logsentinel)
    elif args.alert_file:
        alert = load_alert_from_file(args.alert_file)
    else:
        print("[i] No alert file provided. Enter alert details manually:")
        alert = Alert(
            rule_id=input("  Rule ID (e.g., DET-001): ").strip(),
            title=input("  Title: ").strip(),
            severity=input("  Severity (Low/Medium/High/Critical): ").strip() or "Low",
            source_ip=input("  Source IP: ").strip(),
            description=input("  Description: ").strip(),
        )

    if not alert:
        return 1

    if args.verbose:
        print(f"[+] Alert: [{alert.severity}] {alert.title} ({alert.rule_id})")
        print(f"[+] Source IP: {alert.source_ip or 'N/A'}")
        print(f"[+] Mode: {'EXECUTE' if args.execute else 'DRY-RUN'}")
        print()

    if not _process_single_alert(alert, args, engine, reporter):
        return 1

    return 0


def cmd_list_playbooks(args: argparse.Namespace) -> int:
    """List all available playbooks."""
    engine = PlaybookEngine(playbooks_dir=args.playbooks_dir)
    playbooks = engine.list_playbooks()

    if not playbooks:
        print("[!] No playbooks loaded")
        print(f"    Looked in: {engine.playbooks_dir}")
        return 1

    print(f"\nAvailable Playbooks ({len(playbooks)}):")
    print(f"{'='*60}")
    for pb in playbooks:
        print(f"\n  {pb['name']}")
        print(f"  Description: {pb['description']}")
        print(f"  Triggers: {', '.join(pb['trigger_rule_ids'])}")
        print(f"  Min Severity: {pb['min_severity']}")
        print(f"  Actions: {', '.join(pb['actions'])}")
    print()
    return 0


def cmd_list_incidents(args: argparse.Namespace) -> int:
    """List tracked incidents."""
    db = Database()
    incidents = db.list_incidents(status=args.status)

    if not incidents:
        print("[!] No incidents found")
        return 0

    print(f"\nIncidents ({len(incidents)}):")
    print(f"{'='*70}")
    print(f"  {'ID':<4} {'Severity':<10} {'Rule ID':<10} {'Source IP':<16} {'Status':<8} {'Created'}")
    print(f"  {'-'*66}")
    for inc in incidents:
        created = inc.created_at[:19] if inc.created_at else "?"
        print(f"  {inc.id:<4} {inc.alert.severity:<10} {inc.alert.rule_id:<10} {inc.alert.source_ip:<16} {inc.status:<8} {created}")
    print()
    return 0


def cmd_incident(args: argparse.Namespace) -> int:
    """Show or manage a specific incident."""
    db = Database()
    incident = db.get_incident(args.incident_id)

    if not incident:
        print(f"[!] Incident #{args.incident_id} not found")
        return 1

    if args.close:
        db.close_incident(args.incident_id)
        print(f"[+] Incident #{args.incident_id} closed")
        return 0

    print(f"\nIncident #{incident.id}")
    print(f"{'='*60}")
    print(f"  Status:     {incident.status}")
    print(f"  Playbook:   {incident.playbook_name}")
    print(f"  Created:    {incident.created_at[:19]}")
    print(f"  Resolved:   {incident.resolved_at or 'N/A'}")
    print()
    print(f"  Alert Details:")
    print(f"    Rule:      {incident.alert.rule_id}")
    print(f"    Title:     {incident.alert.title}")
    print(f"    Severity:  {incident.alert.severity}")
    print(f"    Source IP: {incident.alert.source_ip or 'N/A'}")
    print(f"    Count:     {incident.alert.count}")
    print(f"    MITRE:     {incident.alert.mitre_technique or 'N/A'}")
    print()
    print(f"  Actions Taken ({len(incident.results)}):")
    for i, result in enumerate(incident.results, 1):
        icon = "✓" if result.status == "success" else "✗" if result.status == "failure" else "~"
        print(f"    {i}. [{icon}] {result.action_type}")
        print(f"       {result.message}")
    print()
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    """Show database statistics."""
    db = Database()
    stats = db.get_stats()

    print(f"\nIncident Responder - Database Statistics")
    print(f"{'='*50}")
    print(f"  Total Incidents: {stats['total_incidents']}")
    print(f"  Open:            {stats['open']}")
    print(f"  Closed:          {stats['closed']}")
    print()
    if stats.get("severity_breakdown"):
        print("  By Severity:")
        for sev, cnt in stats["severity_breakdown"].items():
            print(f"    {sev:<10}: {cnt}")
    print()
    return 0


def main() -> None:
    """CLI entry point with argument parsing."""
    parser = argparse.ArgumentParser(
        prog="incident-responder",
        description="Incident Responder - Automated IR Playbook Engine",
        epilog="Examples:\n"
        "  %(prog)s run alert.json\n"
        "  %(prog)s run --execute alert.json\n"
        "  %(prog)s run --from-logsentinel logsentinel_report.json\n"
        "  %(prog)s list-playbooks\n"
        "  %(prog)s list-incidents\n"
        "  %(prog)s incident 1\n"
        "  %(prog)s incident 1 close\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--version", action="store_true", help="Show version and exit")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Run command
    run_parser = subparsers.add_parser("run", help="Run playbooks for an alert")
    run_parser.add_argument("alert_file", nargs="?", help="Path to alert JSON file")
    run_parser.add_argument("--from-logsentinel", help="Path to LogSentinel report JSON")
    run_parser.add_argument("--execute", action="store_true", help="Actually execute actions (default: dry-run)")
    run_parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed output")
    run_parser.add_argument("--output-dir", "-o", default="./reports", help="Report output directory")
    run_parser.add_argument("--format", "-f", dest="report_format", choices=["html", "json"], default="html", help="Report format (default: html)")
    run_parser.add_argument("--playbooks-dir", help="Path to playbooks directory")
    watch_group = run_parser.add_argument_group("Watch mode")
    watch_group.add_argument("--watch", action="store_true", help="Watch directory for new alert files continuously")
    watch_group.add_argument("--watch-dir", default="./alerts", help="Directory to watch for new alert files (default: ./alerts)")
    watch_group.add_argument("--watch-interval", type=int, default=5, help="Polling interval in seconds (default: 5)")

    # List playbooks
    list_pb_parser = subparsers.add_parser("list-playbooks", help="List available playbooks")
    list_pb_parser.add_argument("--playbooks-dir", help="Path to playbooks directory")

    # List incidents
    list_inc_parser = subparsers.add_parser("list-incidents", help="List tracked incidents")
    list_inc_parser.add_argument("--status", choices=["open", "closed"], help="Filter by status")

    # Incident detail
    inc_parser = subparsers.add_parser("incident", help="Show or manage an incident")
    inc_parser.add_argument("incident_id", type=int, help="Incident ID")
    inc_parser.add_argument("close", nargs="?", help="Close the incident ('close')")

    # Stats
    subparsers.add_parser("stats", help="Show database statistics")

    args = parser.parse_args()

    if args.version:
        print(f"Incident Responder v{__version__}")
        sys.exit(0)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "run": cmd_run,
        "list-playbooks": cmd_list_playbooks,
        "list-incidents": cmd_list_incidents,
        "incident": cmd_incident,
        "stats": cmd_stats,
    }

    handler = commands.get(args.command)
    if handler:
        sys.exit(handler(args))

    parser.print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()
