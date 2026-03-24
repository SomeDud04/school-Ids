#!/usr/bin/env python3
# cli.py — Interactive CLI Shell
# This module was MISSING from the original codebase.
# The design report (Sections 1.7.3, 2.4, 4.6.3) specifies commands:
#   start_detection, stop_detection, view_logs, summary, export_logs
# This implementation adds all of them plus help text for educational use.

import cmd
import json
import os
import sys
from collections import Counter
from datetime import datetime

BANNER = """
╔══════════════════════════════════════════════════════════╗
║        School Network IDS — Interactive CLI              ║
║        BMCS3413 Project II  |  TAR UMT                   ║
╠══════════════════════════════════════════════════════════╣
║  Commands: view_logs  summary  export_logs  help  quit   ║
╚══════════════════════════════════════════════════════════╝
"""

SEV_COLOUR = {
    "HIGH":   "\033[91m",   # red
    "MEDIUM": "\033[93m",   # yellow
    "LOW":    "\033[92m",   # green
}
RESET = "\033[0m"


def _colourise(severity: str) -> str:
    return SEV_COLOUR.get(severity, "") + severity + RESET


class IDSShell(cmd.Cmd):
    intro  = BANNER
    prompt = "(ids) "

    # ------------------------------------------------------------------
    # view_logs
    # ------------------------------------------------------------------

    def do_view_logs(self, arg: str) -> None:
        """
        view_logs [N]
        Print the N most recent alerts (default: 20).
        Example: view_logs 50
        """
        try:
            limit = int(arg.strip()) if arg.strip() else 20
        except ValueError:
            print("[!] Usage: view_logs [number]  e.g. view_logs 30")
            return

        from alert_logger import get_all_alerts
        alerts = get_all_alerts()

        if not alerts:
            print("[*] No alerts recorded yet.")
            return

        recent = alerts[:limit]
        print(f"\n  {'TIMESTAMP':<21} {'RULE':<14} {'SOURCE IP':<18} {'COUNT':<7} SEVERITY")
        print("  " + "─" * 75)
        for a in recent:
            sev = _colourise(a.get("severity", ""))
            print(
                f"  {a.get('timestamp',''):<21} "
                f"{a.get('rule',''):<14} "
                f"{a.get('src_ip',''):<18} "
                f"{str(a.get('count','')):<7} "
                f"{sev}"
            )
        print(f"\n  Showing {len(recent)} of {len(alerts)} total alerts.\n")

    # ------------------------------------------------------------------
    # summary
    # ------------------------------------------------------------------

    def do_summary(self, arg: str) -> None:
        """
        summary
        Print an aggregated report: total alerts, counts by attack type and severity,
        and the time range of recorded events.
        """
        from alert_logger import get_summary
        s = get_summary()

        if s["total"] == 0:
            print("[*] No alerts to summarise yet.")
            return

        print(f"""
  ┌─────────────────────────────┐
  │   IDS ALERT SUMMARY REPORT  │
  └─────────────────────────────┘

  Total Alerts : {s['total']}
  First Event  : {s['first'] or '—'}
  Latest Event : {s['latest'] or '—'}

  By Attack Type
  ──────────────""")
        for rule, count in sorted(s["by_rule"].items(), key=lambda x: -x[1]):
            bar = "█" * min(count, 40)
            print(f"  {rule:<16} {count:>4}  {bar}")

        print("""
  By Severity
  ───────────""")
        for sev, count in sorted(s["by_sev"].items()):
            print(f"  {_colourise(sev):<24} {count}")

        print()

    # ------------------------------------------------------------------
    # export_logs
    # ------------------------------------------------------------------

    def do_export_logs(self, arg: str) -> None:
        """
        export_logs [path]
        Export an HTML session report to the given path (default: reports/export.html).
        The report includes a traffic summary and full alert table.
        Example: export_logs reports/my_report.html
        """
        from reporter import generate_html_report
        path = arg.strip() or "reports/export.html"
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        generate_html_report(path=path)
        print(f"[+] Report exported → {path}")
        print(f"[+] Open with:  xdg-open {path}")

    # ------------------------------------------------------------------
    # export_pdf
    # ------------------------------------------------------------------

    def do_export_pdf(self, arg: str) -> None:
        """
        export_pdf [path]
        Export a PDF session report (requires weasyprint).
        Example: export_pdf reports/my_report.pdf
        """
        from reporter import generate_pdf_report
        path = arg.strip() or "reports/export.pdf"
        generate_pdf_report(path=path)

    # ------------------------------------------------------------------
    # clear_alerts
    # ------------------------------------------------------------------

    def do_clear_alerts(self, arg: str) -> None:
        """
        clear_alerts
        Delete all stored alerts from the database and JSONL file.
        Useful for resetting between classroom exercises.
        """
        confirm = input("  [!] This will delete ALL alerts. Are you sure? (yes/no): ").strip()
        if confirm.lower() != "yes":
            print("  Cancelled.")
            return

        import sqlite3
        from alert_logger import DB_PATH, JSONL_PATH
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM alerts")
        if os.path.exists(JSONL_PATH):
            os.remove(JSONL_PATH)
        print("  [+] All alerts cleared.")

    # ------------------------------------------------------------------
    # show_rules
    # ------------------------------------------------------------------

    def do_show_rules(self, arg: str) -> None:
        """
        show_rules
        Display all active detection rules and their thresholds.
        This lets students inspect exactly what conditions trigger each alert.
        """
        from detection import RULES
        print(f"\n  {'RULE':<16} {'PROTO':<8} {'WINDOW':<10} {'THRESHOLD':<12} {'SEVERITY'}")
        print("  " + "─" * 65)
        for name, rule in RULES.items():
            dst = f"  ports={rule['dst_ports']}" if "dst_ports" in rule else ""
            print(
                f"  {name:<16} {rule['protocol']:<8} "
                f"{str(rule['window_secs'])+'s':<10} "
                f"{rule['threshold']:<12} "
                f"{rule['severity']}{dst}"
            )
        print()

    # ------------------------------------------------------------------
    # show_packets
    # ------------------------------------------------------------------

    def do_show_packets(self, arg: str) -> None:
        """
        show_packets [N]
        Display the N most recent captured packets from data/packets.csv (default: 20).
        """
        try:
            limit = int(arg.strip()) if arg.strip() else 20
        except ValueError:
            print("[!] Usage: show_packets [number]")
            return

        csv_path = "data/packets.csv"
        if not os.path.exists(csv_path):
            print("[*] No packet data yet. Start capture first.")
            return

        import pandas as pd
        try:
            df = pd.read_csv(csv_path)
        except Exception as exc:
            print(f"[!] Could not read packets: {exc}")
            return

        rows = df.tail(limit).iloc[::-1]
        print(f"\n  {'TIMESTAMP':<21} {'PROTO':<7} {'SRC IP':<18} {'DST IP':<18} {'FLAGS'}")
        print("  " + "─" * 75)
        for _, row in rows.iterrows():
            print(
                f"  {str(row.get('timestamp','')):<21} "
                f"{str(row.get('protocol','')):<7} "
                f"{str(row.get('src_ip','')):<18} "
                f"{str(row.get('dst_ip','')):<18} "
                f"{str(row.get('flags',''))}"
            )
        print()

    # ------------------------------------------------------------------
    # help overrides
    # ------------------------------------------------------------------

    def do_quit(self, arg: str) -> bool:
        """quit\nExit the CLI."""
        print("Goodbye.")
        return True

    def do_exit(self, arg: str) -> bool:
        """exit\nExit the CLI."""
        return self.do_quit(arg)

    # Aliases
    do_EOF = do_quit

    def default(self, line: str) -> None:
        print(f"  [!] Unknown command: '{line}'. Type  help  for a list of commands.")


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    IDSShell().cmdloop()
