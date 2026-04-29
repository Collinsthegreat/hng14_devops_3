"""
unbanner.py — Checks ban expiry every 30 seconds.
Removes iptables rules and sends Slack notification on unban.
Implements backoff schedule: 10min, 30min, 2h, then permanent.
"""
import subprocess
import time
import logging
import os

logger = logging.getLogger("unbanner")


class AutoUnbanner:
    def __init__(self, cfg, shared_state, lock, notifier):
        self.cfg = cfg
        self.state = shared_state
        self.lock = lock
        self.notifier = notifier
        self.chain = cfg["block_chain"]

    def _remove_iptables_rule(self, ip):
        try:
            result = subprocess.run(
                ["iptables", "-D", self.chain, "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                logger.info(f"iptables rule removed for {ip}")
            else:
                logger.warning(f"iptables remove failed for {ip}: {result.stderr}")
        except Exception as e:
            logger.error(f"iptables remove exception for {ip}: {e}")

    def _write_audit(self, ip, ban_info):
        entry = (
            f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] "
            f"UNBAN ip={ip} | condition={ban_info.get('condition', 'N/A')} | "
            f"rate={ban_info.get('rate', 0):.3f} | "
            f"baseline={ban_info.get('baseline', 0):.3f} | "
            f"duration={ban_info.get('duration', 'N/A')}\n"
        )
        path = self.state["audit_log_path"]
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "a") as f:
                f.write(entry)
        except Exception as e:
            logger.warning(f"Audit write failed: {e}")

    def run(self):
        logger.info("AutoUnbanner started")
        while True:
            time.sleep(30)
            now = time.time()
            to_unban = []

            with self.lock:
                for ip, info in list(self.state["banned_ips"].items()):
                    unban_time = info.get("unban_time")
                    if unban_time is None:
                        continue  # permanent ban
                    if now >= unban_time:
                        to_unban.append((ip, info))

            for ip, info in to_unban:
                logger.info(f"Unbanning {ip}")
                self._remove_iptables_rule(ip)
                self._write_audit(ip, info)
                self.notifier.send_unban_alert(ip, info)

                with self.lock:
                    if ip in self.state["banned_ips"]:
                        del self.state["banned_ips"][ip]
