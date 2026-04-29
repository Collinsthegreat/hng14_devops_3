"""
baseline.py — Maintains a 30-minute rolling baseline of global req/s.
Recalculates mean and stddev every 60 seconds.
Maintains per-hour slots and prefers current hour's data when sufficient.
"""
import os
import time
import math
import logging
import threading
import datetime
from collections import deque

logger = logging.getLogger("baseline")


def _mean(values):
    if not values:
        return 0.0
    return sum(values) / len(values)


def _stddev(values, mean):
    if len(values) < 2:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(variance)


class BaselineEngine:
    def __init__(self, cfg, shared_state, lock):
        self.cfg = cfg
        self.state = shared_state
        self.lock = lock

        self.window_minutes = cfg["baseline_window_minutes"]
        self.recalc_interval = cfg["baseline_recalc_interval_seconds"]
        self.min_samples = cfg["baseline_min_samples"]
        self.floor_mean = cfg["baseline_floor_mean"]
        self.floor_stddev = cfg["baseline_floor_stddev"]

        # Rolling window: deque of (timestamp, req_per_sec)
        self._window = deque()
        self._window_lock = threading.Lock()

        # Per-hour slots: hour_key (int) -> list of req_per_sec values
        self._hour_slots = {}

        self._last_recalc = time.time()

    def record(self, timestamp, req_per_sec):
        """Called by monitor on every log line / tick."""
        cutoff = timestamp - (self.window_minutes * 60)
        with self._window_lock:
            self._window.append((timestamp, req_per_sec))
            # Evict entries older than window
            while self._window and self._window[0][0] < cutoff:
                self._window.popleft()

            # Accumulate per-hour slot
            hour_key = datetime.datetime.fromtimestamp(timestamp).hour
            if hour_key not in self._hour_slots:
                self._hour_slots[hour_key] = []
            self._hour_slots[hour_key].append(req_per_sec)

    def _recalculate(self):
        """Compute effective mean/stddev. Prefer current hour if it has enough data."""
        current_hour = datetime.datetime.now().hour

        with self._window_lock:
            hour_values = self._hour_slots.get(current_hour, [])
            use_hour = len(hour_values) >= self.min_samples

            if use_hour:
                values = list(hour_values)
                source = f"hour-slot:{current_hour}"
            else:
                values = [v for _, v in self._window]
                source = "rolling-window"

        if len(values) < self.min_samples:
            # Not enough data — use floor values
            effective_mean = self.floor_mean
            effective_stddev = self.floor_stddev
        else:
            effective_mean = max(_mean(values), self.floor_mean)
            effective_stddev = max(_stddev(values, effective_mean), self.floor_stddev)

        with self.lock:
            self.state["effective_mean"] = effective_mean
            self.state["effective_stddev"] = effective_stddev
            self.state["baseline_history"].append({
                "timestamp": time.time(),
                "effective_mean": effective_mean,
                "effective_stddev": effective_stddev,
                "source": source,
                "sample_count": len(values),
            })
            # Keep only last 200 history entries for the dashboard graph
            if len(self.state["baseline_history"]) > 200:
                self.state["baseline_history"] = self.state["baseline_history"][-200:]

        logger.info(
            f"Baseline recalculated [{source}] — "
            f"mean={effective_mean:.3f} stddev={effective_stddev:.3f} "
            f"samples={len(values)}"
        )

        # Write to audit log
        self._audit(effective_mean, effective_stddev, source, len(values))

    def _audit(self, mean, stddev, source, samples):
        """Write baseline recalculation entry to audit log."""
        entry = (
            f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] "
            f"BASELINE_RECALC ip=N/A | condition=recalculation | "
            f"rate={self.state.get('global_req_per_sec', 0):.3f} | "
            f"baseline={mean:.3f} | source={source} | samples={samples} | "
            f"stddev={stddev:.3f}\n"
        )
        try:
            os.makedirs(os.path.dirname(self.state["audit_log_path"]), exist_ok=True)
            with open(self.state["audit_log_path"], "a") as f:
                f.write(entry)
        except Exception as e:
            logger.warning(f"Audit log write failed: {e}")

    def run(self):
        logger.info("Baseline engine started")
        while True:
            time.sleep(self.recalc_interval)
            self._recalculate()
