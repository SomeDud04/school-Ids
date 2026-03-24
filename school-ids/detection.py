#!/usr/bin/env python3
# detection.py — Rule-Based Detection Engine
# Improvements:
#   - Added BRUTE_FORCE rule (was missing — core requirement)
#   - Added dst_ports filter for brute force detection
#   - Added per-call deduplication by (rule, src_ip) to reduce alert spam
#   - Improved subset filtering safety with .copy() to avoid SettingWithCopyWarning
#   - NEW: Added DNS_AMPLIFICATION rule — UDP flood targeting port 53
#   - NEW: Added HTTP_FLOOD rule — TCP flood targeting web ports 80/443
#   - NEW: Added NULL_SCAN rule — TCP packets with no flags set (stealth probe)

from datetime import datetime, timedelta
import pandas as pd

RULES = {
    "SYN_FLOOD": {
        "protocol":     "TCP",
        "flags":        "S",
        "window_secs":  5,
        "threshold":    50,
        "unique_ports": False,
        "severity":     "HIGH"
    },
    "PORT_SCAN": {
        "protocol":     "TCP",
        "window_secs":  10,
        "threshold":    15,
        "unique_ports": True,
        "severity":     "MEDIUM"
    },
    # FIX: Added BRUTE_FORCE — mandatory functional requirement (Report Sections 1.3, 1.7.1, 3.4.1d)
    "BRUTE_FORCE": {
        "protocol":     "TCP",
        "flags":        "S",
        "window_secs":  30,
        "threshold":    20,
        "unique_ports": False,
        "dst_ports":    [22, 23, 21, 3389, 5900, 110, 143, 80, 443, 8080],
        # Common service ports: SSH, Telnet, FTP, RDP, VNC, POP3, IMAP, HTTP, HTTPS
        "severity":     "HIGH"
    },
    "ICMP_FLOOD": {
        "protocol":     "ICMP",
        "window_secs":  5,
        "threshold":    30,
        "unique_ports": False,
        "severity":     "MEDIUM"
    },
    "UDP_FLOOD": {
        "protocol":     "UDP",
        "window_secs":  5,
        "threshold":    100,
        "unique_ports": False,
        "severity":     "HIGH"
    },

    # NEW: DNS Amplification Attack
    # Attacker sends a high volume of UDP packets to port 53 (DNS).
    # In a real amplification attack, spoofed source IPs are used to flood
    # a victim with large DNS responses. Here we detect the outbound query flood.
    # Threshold: 50 UDP packets to port 53 within 5 seconds from one source IP.
    "DNS_AMPLIFICATION": {
        "protocol":     "UDP",
        "window_secs":  5,
        "threshold":    50,
        "unique_ports": False,
        "dst_ports":    [53],
        "severity":     "HIGH"
    },

    # NEW: HTTP Flood Attack
    # Attacker overwhelms a web server with a large number of TCP SYN or
    # established connections to HTTP/HTTPS ports (80, 443, 8080, 8443).
    # This can exhaust server connection tables and cause denial of service.
    # Threshold: 80 TCP SYN packets to web ports within 10 seconds.
    "HTTP_FLOOD": {
        "protocol":     "TCP",
        "flags":        "S",
        "window_secs":  10,
        "threshold":    80,
        "unique_ports": False,
        "dst_ports":    [80, 443, 8080, 8443],
        "severity":     "HIGH"
    },

    # NEW: NULL Scan (Stealth Port Probe)
    # Attacker sends TCP packets with NO flags set (flags = "").
    # RFC 793 says systems should respond with RST if the port is closed,
    # or no response if open — making this a stealthy reconnaissance technique.
    # Normal traffic never has empty TCP flags, so any occurrence is suspicious.
    # Threshold: 10 null-flag packets within 10 seconds from one source IP.
    "NULL_SCAN": {
        "protocol":     "TCP",
        "flags":        "NULL",   # handled specially in analyse()
        "window_secs":  10,
        "threshold":    10,
        "unique_ports": False,
        "severity":     "MEDIUM"
    },
}


def analyse(df: pd.DataFrame) -> list:
    """
    Analyse a DataFrame of recent packets and return a list of alert dicts.
    Only the time window defined per rule is evaluated.
    Deduplication ensures the same (rule, src_ip) pair is not returned twice
    within a single call, even if it matches multiple thresholds.
    """
    alerts = []
    seen   = set()   # FIX: deduplicate (rule_name, src_ip) within this call
    now    = datetime.now()

    for rule_name, rule in RULES.items():
        window_start = now - timedelta(seconds=rule["window_secs"])

        # Filter by time window and protocol
        subset = df[
            (df["timestamp"] >= window_start) &
            (df["protocol"]  == rule["protocol"])
        ].copy()

        if subset.empty:
            continue

        # Filter by TCP flags if specified
        if "flags" in rule:
            flag_val = rule["flags"]

            if flag_val == "NULL":
                # NULL_SCAN: keep only packets where flags column is empty/zero
                # Scapy records empty TCP flags as "" or "0" or NaN
                subset = subset[
                    subset["flags"].fillna("").astype(str).isin(["", "0", "N/A"])
                    | (subset["flags"].fillna("").astype(str).str.strip() == "")
                ]
            else:
                subset = subset[
                    subset["flags"].str.contains(flag_val, na=False)
                ]

        # Filter by destination ports if specified (used by BRUTE_FORCE,
        # DNS_AMPLIFICATION, HTTP_FLOOD)
        if "dst_ports" in rule:
            subset = subset[
                pd.to_numeric(subset["dst_port"], errors="coerce")
                  .isin(rule["dst_ports"])
            ]

        if subset.empty:
            continue

        for src_ip, group in subset.groupby("src_ip"):
            count = (
                group["dst_port"].nunique()
                if rule["unique_ports"]
                else len(group)
            )

            if count >= rule["threshold"]:
                key = (rule_name, str(src_ip))
                # FIX: Skip if already added this (rule, ip) pair this tick
                if key in seen:
                    continue
                seen.add(key)

                alerts.append({
                    "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
                    "rule":      rule_name,
                    "src_ip":    str(src_ip),
                    "count":     int(count),
                    "severity":  rule["severity"]
                })

    return alerts
