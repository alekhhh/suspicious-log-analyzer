from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from flask import Flask, Response, render_template_string, request

from config import AppConfig
from detector import DetectionConfig, DetectionEngine
from parser import parse_log_file
from reporter import build_report_rows, report_rows_to_csv_text

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

_CSV_CACHE: dict[str, str] = {}

HTML_TEMPLATE = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Log Analyzer</title>
    <style>
      :root {
        --bg: #060807;
        --panel: #0b0f0d;
        --text: #e5ffe5;
        --muted: #98b798;
        --line: #1a2a1f;
        --accent: #00ff87;
        --accent-dim: #0ecf77;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: Consolas, "Courier New", monospace;
        background: var(--bg);
        color: var(--text);
      }
      .container {
        width: min(920px, 92vw);
        margin: 36px auto;
      }
      h2, h3 {
        margin: 0 0 14px 0;
        letter-spacing: 0.3px;
      }
      .card {
        background: var(--panel);
        border: 1px solid var(--line);
        padding: 18px;
        border-radius: 10px;
        margin-bottom: 18px;
      }
      .muted { color: var(--muted); margin-top: 10px; }
      .stats { display: flex; gap: 20px; flex-wrap: wrap; margin: 14px 0 14px; }
      .stat {
        min-width: 220px;
        padding: 10px 12px;
        border: 1px solid var(--line);
        border-radius: 8px;
      }
      .alert {
        padding: 9px 0;
        border-bottom: 1px solid var(--line);
        color: #ccffd9;
        word-break: break-word;
      }
      .alert:last-child { border-bottom: none; }
      .btn {
        display: inline-block;
        padding: 10px 14px;
        background: var(--accent);
        color: #03210f;
        text-decoration: none;
        border-radius: 8px;
        border: 1px solid var(--accent-dim);
        cursor: pointer;
        font-weight: 700;
      }
      .btn:hover { filter: brightness(1.05); }
      input[type=file] {
        margin: 10px 0 14px;
        width: 100%;
        color: var(--text);
      }
    </style>
  </head>
  <body>
    <div class="container">
      <h2>Suspicious Activity Log Analyzer</h2>
      <div class="card">
        <form method="post" action="/analyze" enctype="multipart/form-data">
          <label>Upload one or more .log, .txt, or .csv files:</label><br>
          <input type="file" name="logs" accept=".log,.txt,.csv" multiple required>
          <br>
          <button class="btn" type="submit">Analyze</button>
        </form>
        <p class="muted">Supported: custom logs, Linux auth.log (sshd), Apache access auth endpoints, CSV (timestamp, ip, user, action).</p>
      </div>

      {% if result %}
        <div class="card">
          <h3>Results</h3>
          {% if result.csv_id %}
            <p><a class="btn" href="/download/{{ result.csv_id }}">Download CSV Report</a></p>
          {% endif %}
          <div class="stats">
            <div class="stat"><strong>Total parsed events:</strong> {{ result.total_events }}</div>
            <div class="stat"><strong>Total detections:</strong> {{ result.total_detections }}</div>
            <div class="stat"><strong>Unique IPs:</strong> {{ result.unique_ips }}</div>
            <div class="stat"><strong>Failed attempts:</strong> {{ result.failed_attempts }}</div>
            <div class="stat"><strong>Invalid lines:</strong> {{ result.invalid_lines }}</div>
          </div>
        </div>
        <div class="card">
          <h3>Alerts</h3>
          {% if result.alerts %}
            {% for alert in result.alerts %}
              <div class="alert">{{ alert }}</div>
            {% endfor %}
          {% else %}
            <p>No alerts generated.</p>
          {% endif %}
        </div>
      {% endif %}
    </div>
  </body>
</html>
"""


def _build_engine() -> DetectionEngine:
    cfg = AppConfig()
    detection_config = DetectionConfig(
        failed_limit=cfg.failed_limit,
        brute_force_user_limit=cfg.brute_force_user_limit,
        brute_force_ip_limit=cfg.brute_force_ip_limit,
        unusual_start_hour=cfg.unusual_start_hour,
        unusual_end_hour=cfg.unusual_end_hour,
        burst_window_minutes=cfg.burst_window_minutes,
    )
    return DetectionEngine(config=detection_config)


@app.get("/")
def index() -> str:
    return render_template_string(HTML_TEMPLATE, result=None)


@app.post("/analyze")
def analyze() -> str:
    uploaded = request.files.getlist("logs")
    files = [f for f in uploaded if f and f.filename]
    if not files:
        return render_template_string(
            HTML_TEMPLATE,
            result={
                "alerts": ["No files uploaded."],
                "csv_id": "",
                "total_events": 0,
                "total_detections": 0,
                "unique_ips": 0,
                "failed_attempts": 0,
                "invalid_lines": 0,
            },
        )

    all_events = []
    invalid_count = 0

    with TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        for i, file_obj in enumerate(files):
            original_suffix = Path(file_obj.filename).suffix.lower()
            safe_suffix = original_suffix if original_suffix in {".log", ".txt", ".csv"} else ".log"
            target = tmp_dir / f"upload_{i}{safe_suffix}"
            file_obj.save(target)
            events, invalid_lines = parse_log_file(target)
            all_events.extend(events)
            invalid_count += len(invalid_lines)

    all_events.sort(key=lambda e: e.timestamp)
    engine = _build_engine()
    detections = engine.analyze(all_events)

    rows = build_report_rows(all_events, detections)
    csv_text = report_rows_to_csv_text(rows)
    csv_id = str(uuid4())
    _CSV_CACHE[csv_id] = csv_text

    alerts = [
        f"[{d.severity.upper()}] {d.kind} | {d.timestamp.isoformat(sep=' ')} | {d.message}"
        for d in detections
    ]
    return render_template_string(
        HTML_TEMPLATE,
        result={
            "alerts": alerts,
            "csv_id": csv_id,
            "total_events": len(all_events),
            "total_detections": len(detections),
            "unique_ips": len({e.ip for e in all_events}),
            "failed_attempts": sum(1 for e in all_events if e.action == "login_failed"),
            "invalid_lines": invalid_count,
        },
    )


@app.get("/download/<csv_id>")
def download(csv_id: str) -> Response:
    csv_text = _CSV_CACHE.get(csv_id)
    if csv_text is None:
        return Response("CSV not found or expired.", status=404)

    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": 'attachment; filename="alerts_report.csv"'},
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
