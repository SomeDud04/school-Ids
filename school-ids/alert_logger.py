#!/usr/bin/env python3
# alert_logger.py — Alert Storage Module
# Improvements:
#   - FIX: timedelta.seconds → total_seconds() (silent bug across hour boundaries)
#   - FIX: JSON rewrite-on-every-alert → O(1) JSONL append
#   - FIX: open() without 'with' → proper context manager (resource leak)
#   - FIX: Added event_id UUID to match design schema (Report Section 4.3.2)
#   - FIX: Added log_version field as per design schema
#   - NEW: IP anonymisation feature (Report Section 4.5.4)
#   - NEW: get_all_alerts_json() reads JSONL format

import json
import logging
import os
import sqlite3
import uuid
from datetime import datetime

DB_PATH        = "data/alerts.db"
JSONL_PATH     = "data/alerts.jsonl"          # FIX: was alerts.json (full rewrite); now JSONL (append)
COOLDOWN_SECS  = 15

# NEW: Set IDS_ANONYMISE=true in environment to mask last IP octet (Report 4.5.4)
ANONYMISE_IPS  = os.environ.get("IDS_ANONYMISE", "false").lower() == "true"

_cooldowns: dict = {}


# ---------------------------------------------------------------------------
# IP anonymisation (Report Section 4.5.4)
# ---------------------------------------------------------------------------

def _anonymise(ip: str) -> str:
    """Replace the last octet of an IPv4 address with 'X' if anonymisation is on."""
    if not ANONYMISE_IPS:
        return ip
    parts = ip.split(".")
    if len(parts) == 4:
        parts[-1] = "X"
    return ".".join(parts)


# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------

def init_db() -> None:
    os.makedirs("data", exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id     TEXT    NOT NULL,
                timestamp    TEXT    NOT NULL,
                rule         TEXT    NOT NULL,
                src_ip       TEXT    NOT NULL,
                count        INTEGER NOT NULL,
                severity     TEXT    NOT NULL,
                acknowledged INTEGER DEFAULT 0
            )
        """)


# ---------------------------------------------------------------------------
# Core logging function
# ---------------------------------------------------------------------------

def log_alert(alert: dict) -> None:
    """
    Persist an alert to SQLite and JSONL, subject to per-(rule, ip) cooldown.
    Adds event_id, log_version, and anonymises IPs if configured.
    """
    key = (alert["rule"], alert["src_ip"])
    now = datetime.now()

    last_seen = _cooldowns.get(key)
    # FIX: was (now - last_seen).seconds — silently wrong across hour boundaries
    if last_seen and (now - last_seen).total_seconds() < COOLDOWN_SECS:
        return

    _cooldowns[key] = now

    # FIX: Add event_id UUID — required by design schema (Report Section 4.3.2)
    alert["event_id"]    = str(uuid.uuid4())
    alert["log_version"] = "1.0"

    # NEW: Anonymise source IP if configured
    alert["src_ip"] = _anonymise(alert["src_ip"])

    # Persist to SQLite
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """INSERT INTO alerts
               (event_id, timestamp, rule, src_ip, count, severity)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (alert["event_id"], alert["timestamp"], alert["rule"],
             alert["src_ip"], alert["count"], alert["severity"])
        )

    # FIX: was full JSON rewrite — now O(1) append to JSONL file
    _append_jsonl(alert)

    logging.warning(
        f"[ALERT] {alert['severity']} | {alert['rule']} "
        f"| src={alert['src_ip']} | count={alert['count']} "
        f"| id={alert['event_id']}"
    )
    print(
        f"  ⚠  {alert['severity']} — {alert['rule']} "
        f"from {alert['src_ip']} (count={alert['count']})"
    )


# ---------------------------------------------------------------------------
# JSONL helpers
# ---------------------------------------------------------------------------

def _append_jsonl(alert: dict) -> None:
    """
    Append one JSON record as a single line to the JSONL file.
    O(1) — never reads existing data.
    """
    # FIX: was open() without 'with' (resource leak) + reading entire file
    os.makedirs("data", exist_ok=True)
    with open(JSONL_PATH, "a") as f:
        f.write(json.dumps(alert) + "\n")


def get_all_alerts_json() -> list:
    """Read all alerts from JSONL file (one JSON object per line)."""
    alerts = []
    if not os.path.exists(JSONL_PATH):
        return alerts
    with open(JSONL_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass   # skip corrupted lines
    return alerts


# ---------------------------------------------------------------------------
# SQLite query helpers
# ---------------------------------------------------------------------------

def get_all_alerts() -> list:
    """Return all alerts from SQLite, newest first."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_summary() -> dict:
    """Return aggregated alert counts by rule and severity."""
    alerts = get_all_alerts()
    from collections import Counter
    by_rule = dict(Counter(a["rule"]     for a in alerts))
    by_sev  = dict(Counter(a["severity"] for a in alerts))
    return {
        "total":    len(alerts),
        "by_rule":  by_rule,
        "by_sev":   by_sev,
        "first":    alerts[-1]["timestamp"] if alerts else None,
        "latest":   alerts[0]["timestamp"]  if alerts else None,
    }


# ---------------------------------------------------------------------------
# Module-level initialisation
# ---------------------------------------------------------------------------

init_db()
