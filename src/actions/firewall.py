"""
Incident Responder - Firewall Block Action

Blocks IP addresses using iptables/nftables.
Dry-run mode logs what would be blocked without executing.

Features:
  - expire_hours: Auto-remove iptables rules after N hours (uses `at` scheduler)
  - iptables-save/restore: Persist rules across reboots
"""

import subprocess
import shutil
import os
import tempfile
from pathlib import Path
from typing import Any

from ..models import ActionResult


class FirewallBlockAction:
    """Action that blocks an IP address via iptables."""

    IPTABLES_DIR = Path.home() / ".incident_responder" / "iptables"

    def __init__(self, execute: bool = False):
        self.execute = execute
        self.IPTABLES_DIR.mkdir(parents=True, exist_ok=True)

    def _has_iptables(self) -> bool:
        """Check if iptables is available on the system."""
        return shutil.which("iptables") is not None

    def _has_at(self) -> bool:
        """Check if the `at` scheduler is available."""
        return shutil.which("at") is not None

    def _run_iptables(self, ip: str, chain: str = "INPUT") -> tuple[bool, str]:
        """Execute iptables rule to block an IP."""
        try:
            result = subprocess.run(
                [
                    "iptables", "-A", chain, "-s", ip, "-j", "DROP",
                    "-m", "comment", "--comment", "IncidentResponder",
                ],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return True, f"Blocked {ip} via iptables chain {chain}"
            return False, f"iptables failed: {result.stderr.strip()}"
        except FileNotFoundError:
            return False, "iptables not found on this system"
        except subprocess.TimeoutExpired:
            return False, "iptables command timed out"
        except PermissionError:
            return False, "Permission denied — need root/sudo for iptables"

    def _schedule_expiry(self, ip: str, chain: str, expire_hours: int) -> str:
        """Schedule automatic removal of iptables rule after N hours.

        Uses the `at` scheduler if available. Falls back to a script file.
        Returns a message describing what was scheduled.
        """
        if not self._has_at():
            # Fallback: write a removal script to disk
            script_path = self.IPTABLES_DIR / f"unblock_{ip}_{chain}.sh"
            script_content = (
                f"#!/bin/bash\n"
                f"# Scheduled unblock for {ip} on chain {chain}\n"
                f"# Created by IncidentResponder - expires after {expire_hours}h\n"
                f"iptables -D {chain} -s {ip} -j DROP 2>/dev/null || true\n"
            )
            script_path.write_text(script_content)
            os.chmod(str(script_path), 0o755)
            return (
                f"at scheduler not available. "
                f"Removal script created: {script_path}\n"
                f"  Run manually with: sudo {script_path}\n"
                f"  Or add to crontab: echo '0 */{expire_hours} * * * root {script_path}' >> /etc/crontab"
            )

        # Use `at` to schedule removal
        try:
            at_input = f"iptables -D {chain} -s {ip} -j DROP\n"
            result = subprocess.run(
                ["at", f"now + {expire_hours} hours"],
                input=at_input,
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                # Extract job ID from output (e.g., "job 5 at Thu May 21 15:00:00 2026")
                job_info = result.stdout.strip() or result.stderr.strip()
                return f"Scheduled removal via `at`: {job_info} (in {expire_hours}h)"
            return f"Failed to schedule removal with `at`: {result.stderr.strip()}"
        except FileNotFoundError:
            return "at command not found on this system"
        except subprocess.TimeoutExpired:
            return "at command timed out"

    def _check_existing_rule(self, ip: str, chain: str = "INPUT") -> bool:
        """Check if a block rule already exists for this IP."""
        try:
            result = subprocess.run(
                ["iptables", "-C", chain, "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
            return False

    def save_iptables(self) -> tuple[bool, str]:
        """Save current iptables rules to a persistent file.

        Writes rules to ~/.incident_responder/iptables/rules.v4
        so they can be restored after reboot.
        """
        if not self._has_iptables():
            return False, "iptables not available on this system"

        save_path = self.IPTABLES_DIR / "rules.v4"
        try:
            result = subprocess.run(
                ["iptables-save"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                save_path.write_text(result.stdout)
                return (
                    True,
                    f"iptables rules saved to {save_path} "
                    f"({len(result.stdout.splitlines())} lines)"
                )
            return False, f"iptables-save failed: {result.stderr.strip()}"
        except FileNotFoundError:
            return False, "iptables-save not found on this system"
        except subprocess.TimeoutExpired:
            return False, "iptables-save command timed out"
        except PermissionError:
            return False, "Permission denied — need root/sudo for iptables-save"

    def restore_iptables(self) -> tuple[bool, str]:
        """Restore iptables rules from a saved file.

        Loads rules from ~/.incident_responder/iptables/rules.v4
        """
        if not self._has_iptables():
            return False, "iptables not available on this system"

        save_path = self.IPTABLES_DIR / "rules.v4"
        if not save_path.exists():
            return False, f"No saved rules found at {save_path}"

        try:
            result = subprocess.run(
                ["iptables-restore"],
                input=save_path.read_text(),
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return True, f"iptables rules restored from {save_path}"
            return False, f"iptables-restore failed: {result.stderr.strip()}"
        except FileNotFoundError:
            return False, "iptables-restore not found on this system"
        except subprocess.TimeoutExpired:
            return False, "iptables-restore command timed out"
        except PermissionError:
            return False, "Permission denied — need root/sudo for iptables-restore"

    def generate_boot_persistence_hint(self) -> str:
        """Generate instructions for boot persistence of iptables rules."""
        save_path = self.IPTABLES_DIR / "rules.v4"
        return (
            f"To persist iptables rules across reboots:\n\n"
            f"1. Save rules after adding blocks:\n"
            f"   incident-responder run alert.json --execute --save-iptables\n\n"
            f"2. Restore on boot by adding to /etc/rc.local or a systemd service:\n"
            f"   iptables-restore < {save_path}\n\n"
            f"3. Or install a systemd oneshot service:\n"
            f"   [Unit]\n"
            f"   Description=Restore IncidentResponder iptables rules\n"
            f"   [Service]\n"
            f"   Type=oneshot\n"
            f"   ExecStart=iptables-restore {save_path}\n"
            f"   [Install]\n"
            f"   WantedBy=multi-user.target"
        )

    def execute_action(self, alert, params: dict[str, Any]) -> ActionResult:
        """Execute or simulate the firewall block action.

        Supports params:
          - ip: Override source IP (default: alert.source_ip)
          - chain: iptables chain (default: INPUT)
          - comment: Rule comment (default: "Blocked by IncidentResponder")
          - expire_hours: Auto-remove rule after N hours (0 = no expiry)
          - save: Save iptables rules after blocking (bool, default: false)
        """
        ip = params.get("ip") or alert.source_ip
        chain = params.get("chain", "INPUT")
        comment = params.get("comment", "Blocked by IncidentResponder")
        expire_hours = params.get("expire_hours", 0)
        save = params.get("save", False)

        if not ip:
            return ActionResult(
                action_type="firewall_block",
                status="skipped",
                message="No source IP to block",
                data={"ip": None, "reason": "No source IP in alert"},
            )

        data = {
            "ip": ip,
            "chain": chain,
            "comment": comment,
            "execute_mode": self.execute,
            "expire_hours": expire_hours,
            "iptables_available": self._has_iptables(),
        }

        # --- Dry-run mode ---
        if not self.execute:
            msg = f"[DRY-RUN] Would block {ip} via iptables chain {chain} ({comment})"
            if expire_hours > 0:
                msg += f"\n           [DRY-RUN] Would auto-remove after {expire_hours}h"
            if save:
                msg += "\n           [DRY-RUN] Would save iptables rules for persistence"
            return ActionResult(
                action_type="firewall_block",
                status="success",
                message=msg,
                data=data,
            )

        # --- Execute mode ---

        # Check if rule already exists
        if self._check_existing_rule(ip, chain):
            data["rule_exists"] = True
            return ActionResult(
                action_type="firewall_block",
                status="skipped",
                message=f"iptables rule already exists for {ip} on chain {chain}",
                data=data,
            )

        # Execute the block
        success, block_msg = self._run_iptables(ip, chain)
        data["block_result"] = block_msg

        if not success:
            return ActionResult(
                action_type="firewall_block",
                status="failure",
                message=block_msg,
                data=data,
            )

        # Schedule expiry if requested
        expiry_msgs = []
        if expire_hours > 0:
            expiry_msg = self._schedule_expiry(ip, chain, expire_hours)
            expiry_msgs.append(expiry_msg)
            data["expiry_scheduled"] = expiry_msg

        # Save iptables rules if requested
        if save:
            save_success, save_msg = self.save_iptables()
            expiry_msgs.append(save_msg)
            data["iptables_save_result"] = save_msg

        # Build final message
        final_msg = block_msg
        if expiry_msgs:
            final_msg += " | " + " | ".join(expiry_msgs)

        return ActionResult(
            action_type="firewall_block",
            status="success",
            message=final_msg,
            data=data,
        )
