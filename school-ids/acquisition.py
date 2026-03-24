#!/usr/bin/env python3
# acquisition.py — Packet Capture Module
# Improvements:
#   - FIX: No error handling → try/except for PermissionError and OSError
#   - FIX: Unhelpful crash messages → beginner-friendly error output
#   - NEW: Returns packet count for caller to use in logging

import logging
import os
from scapy.all import sniff, wrpcap
from preprocessing import process_packet

PROTO_FILTER = {
    "TCP":  "tcp",
    "UDP":  "udp",
    "ICMP": "icmp",
    "all":  ""
}


def start_capture(
    interface: str,
    protocol:  str,
    duration:  int,
    output_path: str
) -> int:
    """
    Capture packets on the given interface for `duration` seconds.
    Returns the number of packets captured.
    Raises SystemExit with a clear message on permission or interface errors.
    """
    bpf = PROTO_FILTER.get(protocol, "")
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    logging.info(f"[ACQ] iface={interface} | filter='{bpf}' | timeout={duration}s")
    print(f"[*] Capturing on '{interface}' | Protocol: {protocol} | Duration: {duration}s")
    print(f"[*] Dashboard → http://localhost:8050  (open in browser)")
    print(f"[*] Press Ctrl+C to stop early.\n")

    try:
        packets = sniff(
            iface=interface,
            filter=bpf,
            timeout=duration,
            prn=process_packet,
            store=True
        )
    except PermissionError:
        raise SystemExit(
            "\n[ERROR] Permission denied.\n"
            "Packet capture requires root privileges.\n"
            "Fix: Run with  sudo python3 main.py --start ...\n"
        )
    except OSError as exc:
        raise SystemExit(
            f"\n[ERROR] Cannot open interface '{interface}': {exc}\n"
            "Fix: Run  ip a  to list available interfaces.\n"
            "Common names: eth0, ens33, wlan0, enp0s3\n"
        )
    except Exception as exc:
        logging.error(f"[ACQ] Unexpected capture error: {exc}")
        raise SystemExit(f"\n[ERROR] Capture failed: {exc}\n")

    wrpcap(output_path, packets)
    n = len(packets)
    logging.info(f"[ACQ] {n} packets saved → {output_path}")
    print(f"\n[+] Done. {n} packets saved to {output_path}")
    return n
