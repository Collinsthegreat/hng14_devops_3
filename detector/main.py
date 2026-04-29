"""
main.py — Entry point. Wires all modules together and starts all threads.
"""
import threading
import logging
import signal
import sys
import time
import yaml
import os

from monitor import LogMonitor
from baseline import BaselineEngine
from detector import AnomalyDetector
from unbanner import AutoUnbanner
from dashboard import DashboardServer
from notifier import SlackNotifier
from blocker import Blocker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("main")


def load_config(path="/app/config.yaml"):
    with open(path, "r") as f:
        cfg = yaml.safe_load(f)
    # Override slack webhook from environment variable
    env_webhook = os.environ.get("SLACK_WEBHOOK_URL", "")
    if env_webhook:
        cfg["slack_webhook_url"] = env_webhook
    return cfg


def main():
    cfg = load_config()
    logger.info("Configuration loaded")

    # Shared state — all modules read/write to these thread-safe structures
    shared_state = {
        "banned_ips": {},           # ip -> {ban_time, ban_count, unban_time}
        "global_req_per_sec": 0.0,
        "top_ips": {},              # ip -> request count in last 60s
        "effective_mean": 0.0,
        "effective_stddev": 0.0,
        "uptime_start": time.time(),
        "baseline_history": [],     # list of (timestamp, req_per_sec) tuples
        "audit_log_path": cfg["audit_log_path"],
    }

    lock = threading.Lock()

    # Instantiate all modules
    notifier = SlackNotifier(cfg)
    blocker = Blocker(cfg, shared_state, lock, notifier)
    baseline_engine = BaselineEngine(cfg, shared_state, lock)
    detector = AnomalyDetector(cfg, shared_state, lock, blocker, notifier)
    unbanner = AutoUnbanner(cfg, shared_state, lock, notifier)
    monitor = LogMonitor(cfg, shared_state, lock, baseline_engine, detector)
    dashboard = DashboardServer(cfg, shared_state, lock)

    # Start all threads
    threads = [
        threading.Thread(target=baseline_engine.run, daemon=True, name="baseline"),
        threading.Thread(target=detector.run, daemon=True, name="detector"),
        threading.Thread(target=unbanner.run, daemon=True, name="unbanner"),
        threading.Thread(target=monitor.run, daemon=True, name="monitor"),
        threading.Thread(target=dashboard.run, daemon=True, name="dashboard"),
    ]

    for t in threads:
        t.start()
        logger.info(f"Started thread: {t.name}")

    def shutdown(signum, frame):
        logger.info("Shutdown signal received. Exiting.")
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    # Keep main thread alive
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
