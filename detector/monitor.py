"""
monitor.py — Tails the Nginx JSON access log line by line.
Maintains two deque-based sliding windows: per-IP and global.
Feeds counts to baseline and triggers detector evaluation.
"""
import time
import json
import logging
import os
from collections import deque, defaultdict
import threading

logger = logging.getLogger("monitor")


class LogMonitor:
    def __init__(self, cfg, shared_state, lock, baseline_engine, detector):
        self.cfg = cfg
        self.state = shared_state
        self.lock = lock
        self.baseline = baseline_engine
        self.detector = detector
        self.log_path = cfg["log_path"]

        # per-IP window: ip -> deque of timestamps (last 60s)
        self.ip_window = defaultdict(deque)
        # global window: deque of timestamps (last 60s)
        self.global_window = deque()

        # per-IP error window: ip -> deque of (timestamp, is_error) tuples
        self.ip_error_window = defaultdict(deque)

        self.ip_window_seconds = cfg["per_ip_window_seconds"]
        self.global_window_seconds = cfg["global_window_seconds"]

        self._lock = threading.Lock()

    def _evict_old(self, now):
        """Remove entries older than window size from all deques."""
        cutoff_ip = now - self.ip_window_seconds
        cutoff_global = now - self.global_window_seconds

        # Evict global window
        while self.global_window and self.global_window[0] < cutoff_global:
            self.global_window.popleft()

        # Evict per-IP windows
        for ip in list(self.ip_window.keys()):
            dq = self.ip_window[ip]
            while dq and dq[0] < cutoff_ip:
                dq.popleft()
            # Evict error window too
            edq = self.ip_error_window[ip]
            while edq and edq[0][0] < cutoff_ip:
                edq.popleft()

    def _parse_line(self, line):
        """Parse a JSON log line. Returns dict or None."""
        line = line.strip()
        if not line:
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None

    def _update_state(self, now):
        """Update shared state with current window metrics."""
        with self._lock:
            global_count = len(self.global_window)
            global_req_per_sec = global_count / self.global_window_seconds

            # Top 10 IPs by count in window
            top_ips = {
                ip: len(dq)
                for ip, dq in self.ip_window.items()
                if len(dq) > 0
            }

            with self.lock:
                self.state["global_req_per_sec"] = global_req_per_sec
                self.state["top_ips"] = dict(
                    sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:10]
                )

            # Feed per-second count to baseline
            self.baseline.record(now, global_req_per_sec)

    def _get_ip_rate(self, ip):
        with self._lock:
            return len(self.ip_window[ip]) / self.ip_window_seconds

    def _get_ip_error_rate(self, ip):
        with self._lock:
            errors = sum(1 for _, is_err in self.ip_error_window[ip] if is_err)
            total = len(self.ip_error_window[ip])
            if total == 0:
                return 0.0
            return errors / self.ip_window_seconds

    def run(self):
        logger.info(f"Tailing log: {self.log_path}")

        # Wait for log file to exist
        while not os.path.exists(self.log_path):
            logger.info("Waiting for log file to appear...")
            time.sleep(2)

        with open(self.log_path, "r") as f:
            # Seek to end of file — only process new lines
            f.seek(0, 2)
            logger.info("Log file found. Monitoring started.")

            while True:
                line = f.readline()
                if not line:
                    # No new line — update state and sleep briefly
                    now = time.time()
                    with self._lock:
                        self._evict_old(now)
                    self._update_state(now)
                    time.sleep(0.1)
                    continue

                record = self._parse_line(line)
                if not record:
                    continue

                now = time.time()
                ip = record.get("source_ip", "")
                status = int(record.get("status", 0))
                is_error = status >= 400

                with self._lock:
                    # Append to sliding windows
                    self.global_window.append(now)
                    self.ip_window[ip].append(now)
                    self.ip_error_window[ip].append((now, is_error))

                    # Evict stale entries
                    self._evict_old(now)

                # Update shared state
                self._update_state(now)

                # Get current rates for this IP
                ip_rate = self._get_ip_rate(ip)
                ip_error_rate = self._get_ip_error_rate(ip)
                global_rate = self.state.get("global_req_per_sec", 0.0)

                # Trigger anomaly evaluation
                self.detector.evaluate(ip, ip_rate, ip_error_rate, global_rate, now)
