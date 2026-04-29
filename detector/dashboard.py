"""
dashboard.py — Live metrics web dashboard served on port 8080.
Auto-refreshes every 3 seconds. Shows banned IPs, global req/s,
top 10 source IPs, CPU/memory, effective mean/stddev, uptime.

Includes a Chart.js time-series graph of effective_mean and effective_stddev
over the last 200 baseline recalculation cycles — required for Baseline-graph.png
screenshot showing at least two hourly slots with different effective_mean values.
"""
import time
import logging
import psutil
from flask import Flask, jsonify, render_template_string

logger = logging.getLogger("dashboard")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HNG Anomaly Detection Dashboard — Doflamingo</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #0d1117; color: #c9d1d9; font-family: 'Courier New', monospace; padding: 20px; }
    h1 { color: #58a6ff; text-align: center; margin-bottom: 20px; font-size: 1.5rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 20px; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
    .card h2 { color: #58a6ff; font-size: 0.9rem; text-transform: uppercase; margin-bottom: 12px; border-bottom: 1px solid #30363d; padding-bottom: 8px; }
    .metric { display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 0.85rem; }
    .metric .label { color: #8b949e; }
    .metric .value { color: #e6edf3; font-weight: bold; }
    .banned-ip { background: #2d1117; border: 1px solid #f85149; border-radius: 4px; padding: 8px; margin-bottom: 6px; font-size: 0.8rem; }
    .banned-ip .ip { color: #f85149; font-weight: bold; }
    .top-ip { display: flex; justify-content: space-between; margin-bottom: 4px; font-size: 0.82rem; }
    .status-bar { text-align: center; color: #3fb950; font-size: 0.75rem; margin-top: 16px; }
    .alert { background: #1f2d1e; border: 1px solid #3fb950; border-radius: 4px; padding: 6px 12px; text-align: center; color: #3fb950; margin-bottom: 16px; }
    .chart-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 20px; }
    .chart-card h2 { color: #58a6ff; font-size: 0.9rem; text-transform: uppercase; margin-bottom: 12px; border-bottom: 1px solid #30363d; padding-bottom: 8px; }
    .chart-wrapper { position: relative; height: 220px; }
    .source-badge { display: inline-block; font-size: 0.7rem; padding: 2px 6px; border-radius: 3px; margin-left: 8px; }
    .source-hour { background: #1f3a1f; color: #3fb950; border: 1px solid #3fb950; }
    .source-rolling { background: #1a2a3f; color: #58a6ff; border: 1px solid #58a6ff; }
  </style>
</head>
<body>
  <h1>&#x1F6E1;&#xFE0F; HNG Anomaly Detection Engine &#x2014; Doflamingo</h1>
  <div class="alert" id="status-bar">Connecting to live feed...</div>

  <div class="grid">
    <div class="card">
      <h2>&#x1F4CA; Global Metrics</h2>
      <div class="metric"><span class="label">Global req/s</span><span class="value" id="global-rps">&#x2014;</span></div>
      <div class="metric"><span class="label">Effective Mean</span><span class="value" id="eff-mean">&#x2014;</span></div>
      <div class="metric"><span class="label">Effective StdDev</span><span class="value" id="eff-stddev">&#x2014;</span></div>
      <div class="metric"><span class="label">Baseline Source</span><span class="value" id="baseline-source">&#x2014;</span></div>
      <div class="metric"><span class="label">Uptime</span><span class="value" id="uptime">&#x2014;</span></div>
    </div>

    <div class="card">
      <h2>&#x1F4BB; System Resources</h2>
      <div class="metric"><span class="label">CPU Usage</span><span class="value" id="cpu">&#x2014;</span></div>
      <div class="metric"><span class="label">Memory Usage</span><span class="value" id="memory">&#x2014;</span></div>
      <div class="metric"><span class="label">Memory Total</span><span class="value" id="memory-total">&#x2014;</span></div>
    </div>

    <div class="card">
      <h2>&#x1F6AB; Banned IPs (<span id="ban-count">0</span>)</h2>
      <div id="banned-list"><em style="color:#8b949e">No active bans</em></div>
    </div>

    <div class="card">
      <h2>&#x1F4C8; Top 10 Source IPs</h2>
      <div id="top-ips-list"></div>
    </div>
  </div>

  <!-- Baseline time-series chart — required for Baseline-graph.png screenshot -->
  <div class="chart-card">
    <h2>&#x1F4C9; Baseline Over Time — Effective Mean &amp; StdDev (last 200 recalculations)</h2>
    <div class="chart-wrapper">
      <canvas id="baselineChart"></canvas>
    </div>
  </div>

  <div class="status-bar" id="last-updated">Last updated: &#x2014;</div>

<script>
// Initialise Chart.js baseline time-series chart
const ctx = document.getElementById('baselineChart').getContext('2d');
const baselineChart = new Chart(ctx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      {
        label: 'Effective Mean (req/s)',
        data: [],
        borderColor: '#58a6ff',
        backgroundColor: 'rgba(88,166,255,0.08)',
        borderWidth: 2,
        pointRadius: 2,
        tension: 0.3,
        fill: true,
      },
      {
        label: 'Effective StdDev',
        data: [],
        borderColor: '#f0883e',
        backgroundColor: 'rgba(240,136,62,0.05)',
        borderWidth: 1.5,
        pointRadius: 1,
        tension: 0.3,
        borderDash: [4, 3],
        fill: false,
      }
    ]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    plugins: {
      legend: { labels: { color: '#c9d1d9', font: { size: 11 } } },
      tooltip: { mode: 'index', intersect: false }
    },
    scales: {
      x: {
        ticks: { color: '#8b949e', font: { size: 10 }, maxTicksLimit: 12 },
        grid: { color: '#21262d' }
      },
      y: {
        ticks: { color: '#8b949e', font: { size: 10 } },
        grid: { color: '#21262d' },
        beginAtZero: true
      }
    }
  }
});

function updateChart(history) {
  if (!history || history.length === 0) return;

  // Format timestamp as HH:MM:SS for x-axis labels
  const labels = history.map(h => {
    const d = new Date(h.timestamp * 1000);
    return d.toLocaleTimeString();
  });
  const means   = history.map(h => h.effective_mean);
  const stddevs = history.map(h => h.effective_stddev);

  baselineChart.data.labels = labels;
  baselineChart.data.datasets[0].data = means;
  baselineChart.data.datasets[1].data = stddevs;
  baselineChart.update('none'); // no animation for live refresh
}

async function refresh() {
  try {
    const r = await fetch('/api/metrics');
    const d = await r.json();

    document.getElementById('global-rps').textContent = d.global_req_per_sec.toFixed(3) + ' req/s';
    document.getElementById('eff-mean').textContent = d.effective_mean.toFixed(3);
    document.getElementById('eff-stddev').textContent = d.effective_stddev.toFixed(3);
    document.getElementById('uptime').textContent = d.uptime;
    document.getElementById('cpu').textContent = d.cpu_percent + '%';
    document.getElementById('memory').textContent = d.memory_used_mb + ' MB (' + d.memory_percent + '%)';
    document.getElementById('memory-total').textContent = d.memory_total_mb + ' MB';
    document.getElementById('ban-count').textContent = d.banned_count;

    // Show baseline source with colour-coded badge
    const src = d.baseline_source || 'unknown';
    const isHour = src.startsWith('hour-slot');
    document.getElementById('baseline-source').innerHTML =
      `<span class="source-badge ${isHour ? 'source-hour' : 'source-rolling'}">${src}</span>`;

    const bannedDiv = document.getElementById('banned-list');
    if (d.banned_ips.length === 0) {
      bannedDiv.innerHTML = '<em style="color:#8b949e">No active bans</em>';
    } else {
      bannedDiv.innerHTML = d.banned_ips.map(b =>
        `<div class="banned-ip">
          <span class="ip">${b.ip}</span>
          <div>Rate: ${b.rate.toFixed(3)} req/s | Duration: ${b.duration}</div>
          <div>Condition: ${b.condition}</div>
        </div>`
      ).join('');
    }

    const topDiv = document.getElementById('top-ips-list');
    topDiv.innerHTML = d.top_ips.map(t =>
      `<div class="top-ip"><span>${t.ip}</span><span style="color:#58a6ff">${t.count} req</span></div>`
    ).join('');

    // Update the baseline time-series chart
    updateChart(d.baseline_history);

    document.getElementById('status-bar').textContent = '\u2705 Live \u2014 refreshing every 3s';
    document.getElementById('last-updated').textContent = 'Last updated: ' + new Date().toLocaleTimeString();
  } catch(e) {
    document.getElementById('status-bar').textContent = '\u26A0\uFE0F Connection error \u2014 retrying...';
  }
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""


class DashboardServer:
    def __init__(self, cfg, shared_state, lock):
        self.cfg = cfg
        self.state = shared_state
        self.lock = lock
        self.app = Flask(__name__)
        self._register_routes()

    def _register_routes(self):
        state = self.state
        lock = self.lock

        @self.app.route("/")
        def index():
            return render_template_string(HTML_TEMPLATE)

        # Also serve at /dashboard path (for Nginx location /dashboard proxy block)
        @self.app.route("/dashboard")
        def dashboard():
            return render_template_string(HTML_TEMPLATE)

        @self.app.route("/api/metrics")
        def metrics():
            with lock:
                banned_ips_raw   = dict(state.get("banned_ips", {}))
                global_rps       = state.get("global_req_per_sec", 0.0)
                top_ips_raw      = dict(state.get("top_ips", {}))
                eff_mean         = state.get("effective_mean", 0.0)
                eff_stddev       = state.get("effective_stddev", 0.0)
                uptime_start     = state.get("uptime_start", time.time())
                # Expose full baseline history for the time-series chart
                baseline_history = list(state.get("baseline_history", []))

            uptime_secs = int(time.time() - uptime_start)
            h, rem = divmod(uptime_secs, 3600)
            m, s   = divmod(rem, 60)
            uptime_str = f"{h:02d}:{m:02d}:{s:02d}"

            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()

            banned_list = [
                {
                    "ip":        ip,
                    "rate":      info.get("rate", 0.0),
                    "duration":  info.get("duration", "N/A"),
                    "condition": info.get("condition", "N/A"),
                    "ban_time":  info.get("ban_time", 0),
                }
                for ip, info in banned_ips_raw.items()
            ]

            top_ips_list = [
                {"ip": ip, "count": count}
                for ip, count in sorted(
                    top_ips_raw.items(), key=lambda x: x[1], reverse=True
                )[:10]
            ]

            # Derive the current baseline source from the most recent history entry
            baseline_source = (
                baseline_history[-1].get("source", "rolling-window")
                if baseline_history else "rolling-window"
            )

            return jsonify({
                "global_req_per_sec": round(global_rps, 4),
                "effective_mean":     round(eff_mean, 4),
                "effective_stddev":   round(eff_stddev, 4),
                "baseline_source":    baseline_source,
                "baseline_history":   baseline_history,   # full history for chart
                "uptime":             uptime_str,
                "cpu_percent":        cpu,
                "memory_used_mb":     round(mem.used  / 1024 / 1024, 1),
                "memory_total_mb":    round(mem.total / 1024 / 1024, 1),
                "memory_percent":     mem.percent,
                "banned_count":       len(banned_list),
                "banned_ips":         banned_list,
                "top_ips":            top_ips_list,
            })

        @self.app.route("/health")
        def health():
            return jsonify({"status": "ok"})

    def run(self):
        logger.info(
            f"Dashboard starting on "
            f"{self.cfg['dashboard_host']}:{self.cfg['dashboard_port']}"
        )
        import logging as pylog
        pylog.getLogger("werkzeug").setLevel(pylog.WARNING)
        self.app.run(
            host=self.cfg["dashboard_host"],
            port=self.cfg["dashboard_port"],
            threaded=True,
            use_reloader=False,
        )
