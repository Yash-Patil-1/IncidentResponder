# Incident Responder — PRD

**Project:** Incident Responder — Automated IR Playbook Engine
**Type:** SOC Tool (Intermediate)
**Author:** Yash Patil
**Status:** Draft

---

## 1. Overview

**Incident Responder** is a CLI-based automated incident response tool that executes YAML-defined playbooks when security alerts are triggered. It complements LogSentinel (detection) by providing the **response** layer of the SOC workflow.

### Portfolio Narrative
- **LogSentinel** → Detect threats
- **Incident Responder** → Respond to threats
- **Project 3** → Hunt/Forensics

---

## 2. Goals

1. Build an automated SOAR-like playbook engine
2. Integrate with LogSentinel alert output
3. Demonstrate API integration (AbuseIPDB, VirusTotal)
4. Show system administration skills (iptables, notifications)
5. Produce portfolio-quality code with tests and docs

---

## 3. Features

### Core
- YAML-defined playbooks with trigger conditions (rule IDs, severity)
- Action types: firewall block, IP enrichment, file notifications, case logging
- Dry-run mode (default) vs. execute mode
- SQLite database for incident tracking and audit trail
- CLI with 5 commands: `run`, `list-playbooks`, `list-incidents`, `incident`, `stats`

### Alert Input
- Standalone alert JSON files
- LogSentinel report JSON (reads from `alerts[]` array)
- Manual interactive input mode

### Actions
| Action | Description | Config |
|--------|-------------|--------|
| `firewall_block` | Block IP via iptables (dry-run or execute) | chain, comment |
| `enrich_ip` | Query AbuseIPDB + VirusTotal for IP reputation | providers list |
| `notify` | Write notification to log file (JSONL) | message template |
| `log_case` | Record case summary in database | summary template |

### Template Variables
Playbook action params support `{{alert.field_name}}` template substitution using alert fields.

---

## 4. Architecture

```
Alert JSON → PlaybookEngine → Match Playbooks → Execute Actions → Incident DB → Reports
                                    │
                            ┌───────┼───────────┐
                            │       │           │
                     firewall  enrich_ip   notify  log_case
                     _block
```

### Data Flow
1. Ingest alert (JSON file, LogSentinel report, or manual)
2. Match against loaded playbooks by `trigger_rule_ids` and `min_severity`
3. Create incident record in SQLite
4. Execute each playbook action in order
5. Log each action result
6. Generate HTML or JSON report

---

## 5. Directory Structure

```
IncidentResponder/
├── PRD.md
├── requirements.txt
├── src/
│   ├── __init__.py
│   ├── main.py         — CLI entry point
│   ├── models.py       — Data models
│   ├── engine.py       — Playbook engine
│   ├── database.py     — SQLite database
│   ├── reporter.py     — Report generation
│   ├── actions/
│   │   ├── __init__.py — Action registry
│   │   ├── firewall.py — iptables block
│   │   ├── enrich.py   — IP enrichment
│   │   ├── notify.py   — File notifications
│   │   └── log_case.py — Case logging
│   └── templates/
│       └── report.html — Jinja2 HTML template
├── config/
│   └── playbooks/
│       ├── block_ssh_brute.yaml
│       ├── block_port_scan.yaml
│       └── notify_high_alert.yaml
├── Sample_alerts/
│   ├── ssh_brute_alert.json
│   └── port_scan_alert.json
└── tests/
    ├── test_engine.py
    ├── test_actions.py
    └── test_database.py
```

---

## 6. Playbook Format (YAML)

```yaml
name: block_ssh_brute_force
description: Block IP detected performing SSH brute force
trigger_rule_ids:
  - DET-001
  - SSH_BRUTE_FORCE
min_severity: medium
actions:
  - type: enrich_ip
    params:
      providers: [abuseipdb, virustotal]
  - type: firewall_block
    params:
      chain: INPUT
      comment: "Blocked by IncidentResponder - SSH brute force"
  - type: notify
    params:
      message: "Blocked {{alert.source_ip}} for SSH brute force ({{alert.count}} attempts)"
  - type: log_case
    params:
      summary: "SSH brute force from {{alert.source_ip}} - blocked"
```

---

## 7. Alert Format (JSON)

### Standalone
```json
{
  "rule_id": "DET-001",
  "title": "SSH Brute Force Detected",
  "severity": "High",
  "source_ip": "192.168.1.100",
  "description": "Multiple failed SSH login attempts",
  "timestamp": "2024-01-15T10:30:00",
  "count": 15,
  "mitre_technique": "T1110 - Brute Force",
  "recommendation": "Block the source IP"
}
```

### LogSentinel Compatible
```json
{
  "scan_time": "...",
  "total_alerts": 3,
  "alerts": [ { ... alert fields ... } ]
}
```

---

## 8. Testing

- Unit tests for PlaybookEngine (matching, execution, dry-run)
- Unit tests for actions (firewall, enrich, notify, log_case)
- Unit tests for Database (CRUD, stats)
- Integration: run against sample alerts

---

## 9. Future Enhancements

- Slack/Discord webhook notifications
- Docker container for isolated execution
- More enrichment providers (GreyNoise, Shodan)
- MITRE ATT&CK mapped playbook library
- Real-time log monitoring integration
