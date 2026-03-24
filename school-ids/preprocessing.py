#!/usr/bin/env python3
# preprocessing.py — Packet Parsing Module
# Improvements:
#   - FIX: File opened/closed per packet → persistent handle (huge I/O reduction)
#   - FIX: No thread safety → threading.Lock() protects concurrent CSV access
#   - FIX: _stats set lost on crash → generate_summary() also reads CSV for accuracy
#   - NEW: close_handle() for clean shutdown

import csv
import json
import os
import threading
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP

CSV_PATH     = "data/packets.csv"
SUMMARY_PATH = "data/summary.json"

FIELDS = [
    "timestamp", "src_ip", "dst_ip",
    "src_port", "dst_port", "protocol", "flags", "packet_length"
]

_stats = {
    "total": 0, "tcp": 0, "udp": 0,
    "icmp":  0, "other": 0, "src_ips": set()
}

# FIX: Lock protects _csv_handle against concurrent access from
#      the capture thread (process_packet) and detection_loop (pd.read_csv)
_csv_lock   = threading.Lock()
_csv_handle = None


# ---------------------------------------------------------------------------
# Internal CSV helpers
# ---------------------------------------------------------------------------

def _get_handle():
    """Return (or create) the persistent CSV file handle."""
    global _csv_handle
    if _csv_handle is None:
        os.makedirs("data", exist_ok=True)
        write_header = not os.path.exists(CSV_PATH)
        # FIX: open once, keep open — avoids per-packet open/close overhead
        _csv_handle = open(CSV_PATH, "a", newline="")
        if write_header:
            csv.DictWriter(_csv_handle, fieldnames=FIELDS).writeheader()
            _csv_handle.flush()
    return _csv_handle


def _write_csv(record: dict) -> None:
    # FIX: Acquire lock before any file operation
    with _csv_lock:
        writer = csv.DictWriter(_get_handle(), fieldnames=FIELDS)
        writer.writerow(record)
        _get_handle().flush()   # flush so detection_loop sees data immediately


def close_handle() -> None:
    """Call this on clean shutdown to flush and close the CSV file."""
    global _csv_handle
    with _csv_lock:
        if _csv_handle is not None:
            _csv_handle.flush()
            _csv_handle.close()
            _csv_handle = None


# ---------------------------------------------------------------------------
# Packet callback (called by Scapy's sniff prn=)
# ---------------------------------------------------------------------------

def process_packet(pkt) -> None:
    if not pkt.haslayer(IP):
        return

    ip       = pkt[IP]
    protocol = "OTHER"
    src_port = "N/A"
    dst_port = "N/A"
    flags    = "N/A"

    if pkt.haslayer(TCP):
        protocol = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        flags    = str(pkt[TCP].flags)
        _stats["tcp"] += 1
    elif pkt.haslayer(UDP):
        protocol = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        _stats["udp"] += 1
    elif pkt.haslayer(ICMP):
        protocol = "ICMP"
        _stats["icmp"] += 1
    else:
        _stats["other"] += 1

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    record = {
        "timestamp":     timestamp,
        "src_ip":        ip.src,
        "dst_ip":        ip.dst,
        "src_port":      src_port,
        "dst_port":      dst_port,
        "protocol":      protocol,
        "flags":         flags,
        "packet_length": len(pkt)
    }

    _stats["total"] += 1
    _stats["src_ips"].add(ip.src)
    _write_csv(record)


# ---------------------------------------------------------------------------
# Summary generation
# ---------------------------------------------------------------------------

def generate_summary() -> dict:
    """
    Write session summary to data/summary.json.
    FIX: Falls back to re-reading the CSV if in-memory _stats are zero
         (handles crash/restart scenarios).
    """
    total      = _stats["total"]
    unique_ips = len(_stats["src_ips"])

    # Fallback: re-derive counts from CSV if in-memory stats were lost
    if total == 0 and os.path.exists(CSV_PATH):
        import pandas as pd
        try:
            df         = pd.read_csv(CSV_PATH)
            total      = len(df)
            unique_ips = df["src_ip"].nunique() if "src_ip" in df.columns else 0
            proto_col  = df["protocol"].value_counts().to_dict() if "protocol" in df.columns else {}
            summary = {
                "total_packets":   total,
                "unique_src_ips":  unique_ips,
                "protocol_counts": proto_col
            }
        except Exception:
            summary = {"total_packets": 0, "unique_src_ips": 0, "protocol_counts": {}}
    else:
        summary = {
            "total_packets":   total,
            "unique_src_ips":  unique_ips,
            "protocol_counts": {
                "TCP":   _stats["tcp"],
                "UDP":   _stats["udp"],
                "ICMP":  _stats["icmp"],
                "Other": _stats["other"]
            }
        }

    os.makedirs("data", exist_ok=True)
    with open(SUMMARY_PATH, "w") as f:
        json.dump(summary, f, indent=2)

    return summary
