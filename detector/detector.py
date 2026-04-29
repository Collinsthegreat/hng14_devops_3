"""
detector.py — Evaluates per-IP and global request rates against the baseline.
Uses z-score >= 3.0 OR rate >= 5x baseline mean to flag anomalies.
Tightens thresholds when an IP has an error surge.

Fix #2: run() loop includes monitor thread health check every 60 seconds.
If the monitor thread dies, detection silently stops — this surfaces that as a
CRITICAL log so the operator knows to intervene.
"""
import time
import logging
import threading

logger = logging.getLogger("detector")


class AnomalyDetector:
    def __init__(self, cfg, shared_state, lock, blocker, notifier):
        self.cfg = cfg
        self.state = shared_state
        self.lock = lock
        self.blocker = blocker
        self.notifier = notifier

        self.zscore_threshold = cfg["zscore_threshold"]
        self.rate_multiplier = cfg["rate_multiplier_threshold"]
        self.error_surge_multiplier = cfg["error_surge_multiplier"]
        self.error_surge_zscore = cfg["error_surge_zscore_tightening"]

        # Track which IPs have been recently alerted to avoid spam
        self._alerted = {}
        self._alert_lock = threading.Lock()
        self.alert_cooldown = cfg["ban_alert_cooldown_seconds"]

    def _get_baseline(self):
        with self.lock:
            mean = self.state.get("effective_mean", self.cfg["baseline_floor_mean"])
            stddev = self.state.get("effective_stddev", self.cfg["baseline_floor_stddev"])
        return mean, stddev

    def _zscore(self, rate, mean, stddev):
        if stddev == 0:
            return 0.0
        return (rate - mean) / stddev

    def _is_error_surge(self, ip_error_rate, baseline_mean):
        """Check if IP's error rate is 3x the baseline error rate."""
        # Assume 5% of normal traffic is errors
        baseline_error_rate = baseline_mean * 0.05
        if baseline_error_rate == 0:
            return False
        return ip_error_rate >= (baseline_error_rate * self.error_surge_multiplier)

    def evaluate(self, ip, ip_rate, ip_error_rate, global_rate, now):
        """Called by monitor for every log line. Evaluates anomaly conditions."""
        mean, stddev = self._get_baseline()

        # Determine effective thresholds (tighten if error surge)
        effective_zscore_threshold = self.zscore_threshold
        if self._is_error_surge(ip_error_rate, mean):
            effective_zscore_threshold = self.error_surge_zscore
            logger.info(
                f"Error surge detected for {ip} — "
                f"tightening zscore threshold to {effective_zscore_threshold}"
            )

        # Per-IP anomaly detection
        ip_zscore = self._zscore(ip_rate, mean, stddev)
        ip_anomaly = (
            ip_zscore >= effective_zscore_threshold or
            ip_rate >= (mean * self.rate_multiplier)
        )

        # Global anomaly detection
        global_zscore = self._zscore(global_rate, mean, stddev)
        global_anomaly = (
            global_zscore >= self.zscore_threshold or
            global_rate >= (mean * self.rate_multiplier)
        )

        with self.lock:
            already_banned = ip in self.state.get("banned_ips", {})

        if ip_anomaly and not already_banned:
            condition = (
                f"zscore={ip_zscore:.2f}>={effective_zscore_threshold}"
                if ip_zscore >= effective_zscore_threshold
                else f"rate={ip_rate:.2f}>={mean * self.rate_multiplier:.2f} (5x mean)"
            )
            self._trigger_ip_ban(ip, ip_rate, mean, condition, now)

        if global_anomaly:
            condition = (
                f"global_zscore={global_zscore:.2f}>={self.zscore_threshold}"
                if global_zscore >= self.zscore_threshold
                else f"global_rate={global_rate:.2f}>={mean * self.rate_multiplier:.2f} (5x mean)"
            )
            self._trigger_global_alert(global_rate, mean, condition, now)

    def _trigger_ip_ban(self, ip, rate, mean, condition, now):
        with self._alert_lock:
            last = self._alerted.get(ip, 0)
            if now - last < self.alert_cooldown:
                return
            self._alerted[ip] = now

        logger.warning(
            f"IP anomaly detected: {ip} | {condition} | "
            f"rate={rate:.3f} | mean={mean:.3f}"
        )
        self.blocker.ban(ip, condition, rate, mean)

    def _trigger_global_alert(self, rate, mean, condition, now):
        with self._alert_lock:
            last = self._alerted.get("__global__", 0)
            if now - last < self.alert_cooldown:
                return
            self._alerted["__global__"] = now

        logger.warning(
            f"Global anomaly detected: {condition} | "
            f"rate={rate:.3f} | mean={mean:.3f}"
        )
        self.notifier.send_global_alert(condition, rate, mean)

    def run(self):
        """
        Fix #2: Detection is event-driven via evaluate() called from the monitor
        thread. This run() loop exists for thread consistency and performs a
        health check — if the monitor thread dies, detection silently stops,
        so we surface that as a CRITICAL log every 60 seconds.
        """
        while True:
            time.sleep(60)
            monitor_alive = any(
                t.name == "monitor" and t.is_alive()
                for t in threading.enumerate()
            )
            if not monitor_alive:
                logger.critical(
                    "MONITOR THREAD IS DEAD — anomaly detection has stopped! "
                    "Container will restart shortly (restart: always). "
                    "Check logs for the root cause."
                )
