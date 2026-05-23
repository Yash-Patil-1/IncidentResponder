"""
Incident Responder - Shared Utilities

Template rendering and other shared functions.
"""

from typing import Any


def render_template(template: str, alert: Any) -> str:
    """Replace {{alert.field}} placeholders with actual alert values.

    Supports any field from alert.to_dict(), for example:
    - {{alert.source_ip}}
    - {{alert.rule_id}}
    - {{alert.title}}
    - {{alert.count}}
    - {{alert.severity}}
    """
    result = template
    if "{{" not in result:
        return result

    alert_dict = alert.to_dict() if hasattr(alert, "to_dict") else {}
    for key, value in alert_dict.items():
        result = result.replace("{{alert." + key + "}}", str(value))
    return result
