#!/usr/bin/env python3
# reporter.py — HTML and PDF Report Generator
# Improvements:
#   - FIX: weasyprint import crashes if not installed → graceful fallback with install hint
#   - FIX: reads alerts from JSONL (alert_logger now uses .jsonl format)
#   - NEW: report includes event_id column
#   - NEW: generate_pdf_report() returns path on success

import json
import os
from datetime import datetime
from jinja2 import Template

os.makedirs("reports", exist_ok=True)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  body       { font-family: 'Courier New', monospace; background: #0f1117; color: #cdd9e5; padding: 40px; }
  h1         { color: #38bdf8; border-bottom: 1px solid #2a3547; padding-bottom: 12px; margin-bottom: 24px; }
  h2         { color: #e6edf3; margin: 28px 0 12px; font-size: 1rem; }
  table      { width: 100%; border-collapse: collapse; margin-bottom: 24px; }
  th         { background: #1a2234; color: #38bdf8; padding: 8px 12px; text-align: left; }
  td         { padding: 8px 12px; border-bottom: 1px solid #2a3547; font-size: 0.85rem; }
  .HIGH      { color: #f87171; font-weight: bold; }
  .MEDIUM    { color: #fbbf24; }
  .LOW       { color: #34d399; }
  .stat-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; margin-bottom: 24px; }
  .stat-box  { background: #1c2333; border: 1px solid #2a3547; border-radius: 6px; padding: 16px; }
  .stat-val  { font-size: 1.8rem; color: #38bdf8; font-weight: bold; }
  .stat-lbl  { font-size: 0.75rem; color: #4d6178; margin-top: 4px; }
  .meta      { color: #4d6178; font-size: 0.75rem; }
</style>
</head>
<body>
  <h1>&#x1F6E1; IDS Session Report</h1>
  <p class="meta">Generated: {{ generated_at }}</p>

  <h2>Traffic Summary</h2>
  <div class="stat-grid">
    <div class="stat-box">
      <div class="stat-val">{{ summary.total_packets }}</div>
      <div class="stat-lbl">Total Packets</div>
    </div>
    <div class="stat-box">
      <div class="stat-val">{{ summary.unique_src_ips }}</div>
      <div class="stat-lbl">Unique Source IPs</div>
    </div>
    <div class="stat-box">
      <div class="stat-val">{{ alerts | length }}</div>
      <div class="stat-lbl">Alerts Fired</div>
    </div>
  </div>

  <h2>Protocol Breakdown</h2>
  <table>
    <tr><th>Protocol</th><th>Packet Count</th></tr>
    {% for proto, count in summary.protocol_counts.items() %}
    <tr><td>{{ proto }}</td><td>{{ count }}</td></tr>
    {% endfor %}
  </table>

  <h2>Alerts ({{ alerts | length }} total)</h2>
  {% if alerts %}
  <table>
    <tr>
      <th>Event ID</th><th>Time</th><th>Rule</th>
      <th>Source IP</th><th>Count</th><th>Severity</th>
    </tr>
    {% for a in alerts %}
    <tr>
      <td class="meta">{{ a.get('event_id', '—')[:8] }}...</td>
      <td>{{ a.timestamp }}</td>
      <td>{{ a.rule }}</td>
      <td>{{ a.src_ip }}</td>
      <td>{{ a.count }}</td>
      <td class="{{ a.severity }}">{{ a.severity }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p class="meta">No alerts triggered this session.</p>
  {% endif %}

  <p class="meta">School Network IDS &mdash; BMCS3413 Project II &mdash; TAR UMT</p>
</body>
</html>
"""


def _load_summary() -> dict:
    try:
        with open("data/summary.json") as f:
            return json.load(f)
    except Exception:
        return {"total_packets": 0, "unique_src_ips": 0, "protocol_counts": {}}


def _load_alerts() -> list:
    """
    FIX: Load alerts from JSONL file (one JSON object per line).
    Falls back to legacy alerts.json if JSONL not found.
    """
    from alert_logger import get_all_alerts_json
    alerts = get_all_alerts_json()

    # Legacy fallback
    if not alerts and os.path.exists("data/alerts.json"):
        try:
            with open("data/alerts.json") as f:
                alerts = json.load(f)
        except Exception:
            pass

    return alerts


def generate_html_report(path: str = "reports/session_report.html") -> str:
    summary = _load_summary()
    alerts  = _load_alerts()

    html = Template(TEMPLATE).render(
        summary=summary,
        alerts=alerts,
        generated_at=datetime.now().strftime("%d %b %Y  %H:%M:%S")
    )
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        f.write(html)
    print(f"[REPORT] HTML saved → {path}")
    return path


def generate_pdf_report(path: str = "reports/session_report.pdf") -> str | None:
    """
    FIX: weasyprint was imported inside the function without error handling.
    Now provides a clear install hint if the library is missing.
    """
    try:
        from weasyprint import HTML as WP
    except ImportError:
        print(
            "[WARN] weasyprint is not installed — cannot generate PDF.\n"
            "[HINT] Install it with:\n"
            "       sudo pip install weasyprint --break-system-packages\n"
            "       sudo apt install libpango-1.0-0 libpangoft2-1.0-0 -y\n"
            "Generating HTML report instead."
        )
        generate_html_report()
        return None

    html_path = generate_html_report()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    WP(html_path).write_pdf(path)
    print(f"[REPORT] PDF saved → {path}")
    return path
