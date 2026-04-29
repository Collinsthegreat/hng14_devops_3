"""
blocker.py — Adds iptables DROP rules for anomalous IPs.
Writes audit log entries. Notifies Slack within 10 seconds.

Fix #5: iptables -C check before -I to prevent duplicate DROP rules.
If the same IP triggers detection twice before the alert cooldown catches it
(race condition), a second -I would insert a duplicate rule. On unban, only
one -D is issued, leaving a ghost rule. We guard with -C (check) first.
"""
import subprocess
import time
import logging
import os

logger = logging.getLogger("blocker")


def _write_audit(path, action, ip, condition, rate, baseline, duration):
    entry = (
        f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] "
        f"{action} ip={ip} | condition={condition} | "
        f"rate={rate:.3f} | baseline={baseline:.3f} | duration={duration}\n"
    )
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as f:
            f.write(entry)
    except Exception as e:
        logger.warning(f"Audit write failed: {e}")


class Blocker:
    def __init__(self, cfg, shared_state, lock, notifier):
        self.cfg = cfg
        self.state = shared_state
        self.lock = lock
        self.notifier = notifier
        self.chain = cfg["block_chain"]

    def _rule_exists(self, ip):
        """
        Fix #5: Use iptables -C to check if a DROP rule for this IP already
        exists. Returns True if rule is already present (exit code 0).
        """
        try:
            result = subprocess.run(
                ["iptables", "-C", self.chain, "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except Exception as e:
            logger.warning(f"iptables -C check failed for {ip}: {e}")
            return False  # assume not present; proceed with insert attempt

    def _add_iptables_rule(self, ip):
        """Insert DROP rule at top of chain, only if not already present."""
        if self._rule_exists(ip):
            logger.info(f"iptables DROP rule already exists for {ip} — skipping duplicate insert")
            return
        try:
            result = subprocess.run(
                ["iptables", "-I", self.chain, "1", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                logger.info(f"iptables DROP rule added for {ip}")
            else:
                logger.error(f"iptables failed for {ip}: {result.stderr}")
        except Exception as e:
            logger.error(f"iptables exception for {ip}: {e}")

    def _get_unban_duration(self, ban_count):
        schedule = self.cfg["unban_schedule_minutes"]
        idx = min(ban_count, len(schedule) - 1)
        val = schedule[idx]
        if val == "permanent":
            return None  # None means permanent
        return int(val) * 60  # convert to seconds

    def ban(self, ip, condition, rate, mean):
        now = time.time()

        with self.lock:
            existing = self.state["banned_ips"].get(ip, {})
            ban_count = existing.get("ban_count", 0)
            new_ban_count = ban_count + 1

            unban_duration_secs = self._get_unban_duration(new_ban_count - 1)

            unban_time = (now + unban_duration_secs) if unban_duration_secs else None
            duration_label = (
                f"{int(unban_duration_secs // 60)} min"
                if unban_duration_secs else "permanent"
            )

            self.state["banned_ips"][ip] = {
                "ban_time": now,
                "ban_count": new_ban_count,
                "unban_time": unban_time,
                "condition": condition,
                "rate": rate,
                "baseline": mean,
                "duration": duration_label,
            }

        # Add iptables rule (with duplicate guard)
        self._add_iptables_rule(ip)

        # Write audit log
        _write_audit(
            self.state["audit_log_path"],
            "BAN", ip, condition, rate, mean, duration_label
        )

        # Slack alert (must fire within 10 seconds)
        self.notifier.send_ban_alert(ip, condition, rate, mean, duration_label)
        logger.info(f"Banned {ip} | {condition} | duration={duration_label}")
