#!/usr/bin/env python3
# main.py — IDS Entry Point
# Fixes:
#   - ROOT BUG: detection_loop now maintains a rolling packet buffer so
#     analyse() always sees ALL packets across the full rule window,
#     not just the packets captured in the last 1-second tick.
#   - FIX: explicit timestamp format in pd.to_datetime (no more UserWarning)
#   - FIX: drops NaT rows before passing to analyse() so bad timestamps
#     don't silently break threshold comparisons
#   - FIX: clean shutdown calls close_handle() and joins the thread

import argparse
import logging
import os
from datetime import datetime, timedelta

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename="logs/capture.log",
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(message)s"
)

parser = argparse.ArgumentParser(description="School IDS — Network Intrusion Detection System")
parser.add_argument("--interface", default=None,
                    help="Network interface (e.g. eth0, wlan0, ens33)")
parser.add_argument("--protocol",  default="all",
                    choices=["TCP", "UDP", "ICMP", "all"])
parser.add_argument("--duration",  type=int, default=120,
                    help="Capture duration in seconds (default: 120)")
parser.add_argument("--output",    default="captures/capture.pcap")
parser.add_argument("--start",     action="store_true",
                    help="Start packet capture and detection")
parser.add_argument("--dashboard", action="store_true",
                    help="Launch the live web dashboard")
parser.add_argument("--cli",       action="store_true",
                    help="Launch the interactive CLI shell")
parser.add_argument("--report",    action="store_true",
                    help="Generate HTML report from current data")
args = parser.parse_args()


# ---------------------------------------------------------------------------
# --start: capture + detection
# ---------------------------------------------------------------------------

if args.start:
    if not args.interface:
        raise SystemExit("[ERROR] --interface is required with --start. Run 'ip a' to find yours.")

    from scapy.all import get_if_list
    if args.interface not in get_if_list():
        raise SystemExit(
            f"[ERROR] Interface '{args.interface}' not found.\n"
            f"Run 'ip a' to find yours. Available: {get_if_list()}"
        )

    import threading
    import time
    import pandas as pd
    from io import StringIO

    from detection     import analyse, RULES
    from alert_logger  import log_alert
    from preprocessing import FIELDS

    capturing = True

    # ------------------------------------------------------------------
    # Rolling packet buffer
    # ------------------------------------------------------------------
    # ROOT BUG FIX: We keep a single growing DataFrame of recent packets.
    # Each tick we append NEW rows and expire rows older than MAX_WINDOW_SECS.
    # analyse() then sees ALL packets across the full rule window, not just
    # the packets that arrived in the last 1-second tick.
    #
    # Example: SYN_FLOOD threshold = 50 packets in 5 seconds.
    # Old code: tick reads 10 new packets → count=10 → no alert (WRONG)
    # New code: tick reads 10 new packets, buffer has 200 → count=200 → ALERT
    # ------------------------------------------------------------------

    # MAX_WINDOW_SECS must be >= the largest window_secs in any rule.
    # BRUTE_FORCE uses 30s so we use 35s to be safe.
    MAX_WINDOW_SECS = 35

    _buffer        = pd.DataFrame()   # rolling window of recent packets
    _csv_read_pos  = 0                 # byte offset — only read new CSV rows

    def detection_loop():
        global _csv_read_pos, _buffer

        while capturing:
            try:
                csv_path = "data/packets.csv"
                if not os.path.exists(csv_path):
                    time.sleep(1)
                    continue

                # Read only bytes written since the last tick
                with open(csv_path, "rb") as f:
                    f.seek(_csv_read_pos)
                    new_bytes = f.read()
                    _csv_read_pos = f.tell()

                if new_bytes.strip():
                    chunk = new_bytes.decode("utf-8", errors="replace")

                    # Skip any CSV header lines embedded in the chunk
                    # (happens on first read when position was 0)
                    lines = [
                        ln for ln in chunk.splitlines()
                        if ln and not ln.startswith("timestamp")
                    ]

                    if lines:
                        header = ",".join(FIELDS)
                        csv_text = header + "\n" + "\n".join(lines)

                        try:
                            new_df = pd.read_csv(StringIO(csv_text))

                            # FIX: explicit format — no UserWarning
                            new_df["timestamp"] = pd.to_datetime(
                                new_df["timestamp"],
                                format="%Y-%m-%d %H:%M:%S",
                                errors="coerce"
                            )

                            # Drop rows where timestamp failed to parse
                            new_df = new_df.dropna(subset=["timestamp"])

                            if not new_df.empty:
                                _buffer = pd.concat(
                                    [_buffer, new_df], ignore_index=True
                                )
                        except Exception as exc:
                            logging.error(f"[detection_loop] parse error: {exc}")

                # Expire rows older than the longest rule window
                if not _buffer.empty:
                    cutoff  = datetime.now() - timedelta(seconds=MAX_WINDOW_SECS)
                    _buffer = _buffer[_buffer["timestamp"] >= cutoff].copy()

                # Run detection against the full rolling window
                if not _buffer.empty:
                    for alert in analyse(_buffer):
                        log_alert(alert)

            except Exception as exc:
                logging.error(f"[detection_loop] {exc}")

            time.sleep(1)

    t = threading.Thread(target=detection_loop, daemon=True)
    t.start()

    from acquisition import start_capture
    logging.info(
        f"Session started | iface={args.interface} "
        f"| proto={args.protocol} | duration={args.duration}s"
    )

    try:
        start_capture(args.interface, args.protocol, args.duration, args.output)
    except KeyboardInterrupt:
        print("\n[!] Capture interrupted by user.")

    capturing = False
    t.join(timeout=3)

    from preprocessing import close_handle, generate_summary
    close_handle()
    generate_summary()

    logging.info("Session ended. Summary saved.")
    print("\n[+] Capture complete.")
    print("[+] Run:  python3 main.py --report    to generate an HTML report.")
    print("[+] Run:  python3 main.py --cli       to review alerts interactively.")


# ---------------------------------------------------------------------------
# --dashboard
# ---------------------------------------------------------------------------

if args.dashboard:
    from dashboard import app
    print("[*] Dashboard running at http://localhost:8050")
    app.run(debug=False, port=8050)


# ---------------------------------------------------------------------------
# --cli
# ---------------------------------------------------------------------------

if args.cli:
    from cli import IDSShell
    IDSShell().cmdloop()


# ---------------------------------------------------------------------------
# --report
# ---------------------------------------------------------------------------

if args.report:
    from reporter import generate_html_report, generate_pdf_report
    path = generate_html_report()
    print(f"[+] HTML report saved -> {path}")
    answer = input("[?] Also generate PDF? (y/n): ").strip().lower()
    if answer == "y":
        generate_pdf_report()