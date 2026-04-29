"""
notifier.py — Sends Slack alerts for bans, unbans, and global anomalies.
All alerts include: condition, current rate, baseline, timestamp, ban duration.
"""
import time
import logging
import requests

logger = logging.getLogger("notifier")


class SlackNotifier:
    def __init__(self, cfg):
        self.webhook_url = cfg.get("slack_webhook_url", "")
        self.timeout = cfg.get("slack_timeout_seconds", 5)

    def _send(self, payload):
        if not self.webhook_url:
            logger.warning("Slack webhook URL not configured — skipping notification")
            return
        try:
            resp = requests.post(
                self.webhook_url,
                json=payload,
                timeout=self.timeout
            )
            if resp.status_code != 200:
                logger.warning(f"Slack returned {resp.status_code}: {resp.text}")
        except Exception as e:
            logger.error(f"Slack notification failed: {e}")

    def send_ban_alert(self, ip, condition, rate, baseline, duration):
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        payload = {
            "text": (
                f":rotating_light: *IP BANNED*\n"
                f">*IP:* `{ip}`\n"
                f">*Condition:* `{condition}`\n"
                f">*Current Rate:* `{rate:.3f} req/s`\n"
                f">*Baseline Mean:* `{baseline:.3f} req/s`\n"
                f">*Ban Duration:* `{duration}`\n"
                f">*Timestamp:* `{ts}`"
            )
        }
        self._send(payload)

    def send_unban_alert(self, ip, ban_info):
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        payload = {
            "text": (
                f":white_check_mark: *IP UNBANNED*\n"
                f">*IP:* `{ip}`\n"
                f">*Original Condition:* `{ban_info.get('condition', 'N/A')}`\n"
                f">*Rate at Ban:* `{ban_info.get('rate', 0):.3f} req/s`\n"
                f">*Baseline at Ban:* `{ban_info.get('baseline', 0):.3f} req/s`\n"
                f">*Ban Duration Was:* `{ban_info.get('duration', 'N/A')}`\n"
                f">*Unbanned At:* `{ts}`"
            )
        }
        self._send(payload)

    def send_global_alert(self, condition, rate, baseline):
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        payload = {
            "text": (
                f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
                f">*Condition:* `{condition}`\n"
                f">*Global Rate:* `{rate:.3f} req/s`\n"
                f">*Baseline Mean:* `{baseline:.3f} req/s`\n"
                f">*Timestamp:* `{ts}`\n"
                f">*Action:* Slack alert only — no global IP block"
            )
        }
        self._send(payload)
