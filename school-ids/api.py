#!/usr/bin/env python3
# api.py — REST API for IDS Learning Platform
# Provides endpoints for the ids_learning.html website to fetch real alert data
#
# Usage:
#   python3 api.py
#   Then open ids_learning.html in browser
#
# Endpoints:
#   GET /api/alerts       — all alerts (newest first)
#   GET /api/summary      — total counts by rule and severity
#   GET /api/packets      — recent captured packets
#   GET /api/status       — IDS system status
#
# Install dependencies (one time):
#   pip install flask flask-cors --break-system-packages

import json
import os
import logging

try:
    from flask import Flask, jsonify, send_from_directory
    from flask_cors import CORS
except ImportError:
    raise SystemExit(
        "\n[ERROR] Flask not installed.\n"
        "Fix: pip install flask flask-cors --break-system-packages\n"
    )

from alert_logger import get_all_alerts, get_summary

app = Flask(__name__, static_folder=os.path.dirname(os.path.abspath(__file__)))
CORS(app)

# ---------------------------------------------------------------------------
# Serve ids_learning.html and static files directly
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "ids_learning.html")

@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(app.static_folder, filename)


# ---------------------------------------------------------------------------
# GET /api/alerts
# Returns all alerts from SQLite, newest first
# ---------------------------------------------------------------------------

@app.route("/api/alerts")
def api_alerts():
    try:
        alerts = get_all_alerts()
        return jsonify(alerts)
    except Exception as e:
        logging.error(f"[API] /api/alerts error: {e}")
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# GET /api/summary
# Returns aggregated counts by rule and severity
# ---------------------------------------------------------------------------

@app.route("/api/summary")
def api_summary():
    try:
        summary = get_summary()
        return jsonify(summary)
    except Exception as e:
        logging.error(f"[API] /api/summary error: {e}")
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# GET /api/packets
# Returns last 100 captured packets from CSV
# ---------------------------------------------------------------------------

@app.route("/api/packets")
def api_packets():
    csv_path = "data/packets.csv"
    if not os.path.exists(csv_path):
        return jsonify([])
    try:
        import pandas as pd
        df = pd.read_csv(csv_path)
        # Return last 100 rows, newest first
        rows = df.tail(100).iloc[::-1]
        return jsonify(rows.to_dict(orient="records"))
    except Exception as e:
        logging.error(f"[API] /api/packets error: {e}")
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# GET /api/status
# Returns current IDS system status
# ---------------------------------------------------------------------------

@app.route("/api/status")
def api_status():
    try:
        alerts     = get_all_alerts()
        csv_exists = os.path.exists("data/packets.csv")
        db_exists  = os.path.exists("data/alerts.db")

        # Count packets if CSV exists
        pkt_count = 0
        if csv_exists:
            import pandas as pd
            try:
                df        = pd.read_csv("data/packets.csv")
                pkt_count = len(df)
            except Exception:
                pass

        return jsonify({
            "status":        "online",
            "total_alerts":  len(alerts),
            "total_packets": pkt_count,
            "csv_ready":     csv_exists,
            "db_ready":      db_exists,
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ---------------------------------------------------------------------------
# POST /api/chat
# Proxy route — forwards chat messages to Google Gemini API (free tier).
#
# Setup:
#   1. Get free API key at: https://aistudio.google.com/app/apikey
#   2. export GEMINI_API_KEY="your-key-here"
#   3. python3 api.py
#
# Request body:  { "messages": [...], "system": "..." }
# Response:      { "reply": "..." }
# ---------------------------------------------------------------------------

@app.route("/api/chat", methods=["POST"])
def api_chat():
    import os, json as _json
    from flask import request

    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        return _json.dumps({
            "error": "GEMINI_API_KEY not set.\nRun: export GEMINI_API_KEY=your-key-here\nGet a free key at: https://aistudio.google.com/app/apikey"
        }), 400, {"Content-Type": "application/json"}

    try:
        import urllib.request as _req
        body = request.get_json()
        system_prompt = body.get("system", "")
        messages      = body.get("messages", [])

        # Build Gemini contents array from message history
        # Gemini uses "user" / "model" roles (not "assistant")
        contents = []

        # Inject system prompt as first user/model exchange
        if system_prompt:
            contents.append({"role": "user",  "parts": [{"text": "System instructions: " + system_prompt}]})
            contents.append({"role": "model", "parts": [{"text": "Understood. I will follow those instructions."}]})

        for msg in messages:
            role = "model" if msg["role"] == "assistant" else "user"
            contents.append({"role": role, "parts": [{"text": msg["content"]}]})

        payload = _json.dumps({"contents": contents}).encode()

        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        req = _req.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with _req.urlopen(req) as resp:
            data  = _json.loads(resp.read())
            reply = data["candidates"][0]["content"]["parts"][0]["text"]
            return _json.dumps({"reply": reply}), 200, {"Content-Type": "application/json"}

    except Exception as e:
        logging.error(f"[API] /api/chat error: {e}")
        return _json.dumps({"error": str(e)}), 500, {"Content-Type": "application/json"}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n" + "="*50)
    print("  IDS Learning Platform API")
    print("  Running at: http://localhost:5050")
    print("="*50)
    print("\n  Endpoints:")
    print("  GET /api/alerts   — all alerts")
    print("  GET /api/summary  — alert summary")
    print("  GET /api/packets  — recent packets")
    print("  GET /api/status   — system status")
    print("\n  Open ids_learning.html in your browser")
    print("  Make sure main.py --start is also running!\n")

    app.run(host="0.0.0.0", port=5000, debug=False)