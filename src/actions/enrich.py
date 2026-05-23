"""
Incident Responder - IP Enrichment Action

Queries AbuseIPDB and VirusTotal APIs for IP reputation data.
Results are cached to avoid hitting API rate limits.
"""

import json
import os
import time
from pathlib import Path
from typing import Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from ..models import ActionResult


class EnrichIPAction:
    """Action that enriches an IP address using threat intel APIs."""

    CACHE_DIR = Path.home() / ".incident_responder" / "cache"
    CACHE_TTL = 3600  # 1 hour

    def __init__(self):
        self.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self.abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY", "")
        self.virustotal_key = os.environ.get("VIRUSTOTAL_API_KEY", "")

    def _get_cache_path(self, provider: str, ip: str) -> Path:
        return self.CACHE_DIR / f"{provider}_{ip}.json"

    def _load_cache(self, provider: str, ip: str) -> Optional[dict]:
        """Load cached result if it's still valid."""
        cache_path = self._get_cache_path(provider, ip)
        if cache_path.exists():
            try:
                data = json.loads(cache_path.read_text())
                age = time.time() - data.get("cached_at", 0)
                if age < self.CACHE_TTL:
                    return data.get("result")
            except (json.JSONDecodeError, KeyError):
                pass
        return None

    def _save_cache(self, provider: str, ip: str, result: dict) -> None:
        """Save API result to cache."""
        cache_path = self._get_cache_path(provider, ip)
        cache_path.write_text(json.dumps({
            "cached_at": time.time(),
            "result": result,
        }))

    def _query_abuseipdb(self, ip: str) -> dict[str, Any]:
        """Query AbuseIPDB API for IP reputation."""
        if not self.abuseipdb_key:
            return {"error": "ABUSEIPDB_API_KEY not set", "available": False}

        try:
            req = Request(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                headers={
                    "Key": self.abuseipdb_key,
                    "Accept": "application/json",
                },
            )
            with urlopen(req, timeout=15) as response:
                data = json.loads(response.read().decode())
                result = data.get("data", {})
                return {
                    "available": True,
                    "is_abuse": result.get("abuseConfidenceScore", 0) > 50,
                    "abuse_confidence_score": result.get("abuseConfidenceScore", 0),
                    "total_reports": result.get("totalReports", 0),
                    "last_reported_at": result.get("lastReportedAt", ""),
                    "country": result.get("countryCode", ""),
                    "isp": result.get("isp", ""),
                    "domain": result.get("domain", ""),
                    "usage_type": result.get("usageType", ""),
                }
        except HTTPError as e:
            return {"error": f"AbuseIPDB HTTP {e.code}: {e.reason}", "available": True}
        except (URLError, OSError) as e:
            return {"error": f"AbuseIPDB: {e}", "available": True}

    def _query_virustotal(self, ip: str) -> dict[str, Any]:
        """Query VirusTotal API for IP report."""
        if not self.virustotal_key:
            return {"error": "VIRUSTOTAL_API_KEY not set", "available": False}

        try:
            req = Request(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.virustotal_key},
            )
            with urlopen(req, timeout=15) as response:
                data = json.loads(response.read().decode())
                attrs = data.get("data", {}).get("attributes", {})

                last_analysis = attrs.get("last_analysis_stats", {})
                return {
                    "available": True,
                    "malicious": last_analysis.get("malicious", 0),
                    "suspicious": last_analysis.get("suspicious", 0),
                    "harmless": last_analysis.get("harmless", 0),
                    "undetected": last_analysis.get("undetected", 0),
                    "total_votes": attrs.get("total_votes", {}),
                    "reputation": attrs.get("reputation", 0),
                    "country": attrs.get("country", ""),
                    "as_owner": attrs.get("as_owner", ""),
                }
        except HTTPError as e:
            return {"error": f"VirusTotal HTTP {e.code}: {e.reason}", "available": True}
        except (URLError, OSError) as e:
            return {"error": f"VirusTotal: {e}", "available": True}

    def execute_action(self, alert, params: dict[str, Any]) -> ActionResult:
        """Execute IP enrichment."""
        ip = params.get("ip") or alert.source_ip
        providers = params.get("providers", ["abuseipdb", "virustotal"])

        if not ip:
            return ActionResult(
                action_type="enrich_ip",
                status="skipped",
                message="No source IP to enrich",
                data={"ip": None},
            )

        results = {}
        for provider in providers:
            cached = self._load_cache(provider, ip)
            if cached:
                results[provider] = {**cached, "cached": True}
                continue

            if provider == "abuseipdb":
                results[provider] = self._query_abuseipdb(ip)
            elif provider == "virustotal":
                results[provider] = self._query_virustotal(ip)
            else:
                results[provider] = {"error": f"Unknown provider: {provider}"}

            if "error" not in results[provider]:
                self._save_cache(provider, ip, results[provider])

        available_providers = [p for p, r in results.items() if r.get("available", False)]
        errored = [p for p, r in results.items() if "error" in r and r.get("available", True)]

        data = {
            "ip": ip,
            "enrichment": results,
            "api_keys_configured": {
                "abuseipdb": bool(self.abuseipdb_key),
                "virustotal": bool(self.virustotal_key),
            },
        }

        if not available_providers and errored:
            status = "failure"
            message = f"Enrichment failed for {ip}: {', '.join(errored)}"
        elif not available_providers:
            status = "skipped"
            message = "No enrichment providers configured (set ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY)"
        else:
            status = "success"
            message = f"Enriched {ip} via {', '.join(available_providers)}"

        return ActionResult(
            action_type="enrich_ip",
            status=status,
            message=message,
            data=data,
        )
