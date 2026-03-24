#!/usr/bin/env python3
# flood_test_windows.py -- Attack Simulator for Windows
#
# REQUIREMENTS (one-time setup):
#   1. Install Npcap: https://npcap.com/#download
#      (tick "WinPcap API-compatible mode" during install)
#   2. Install Python: https://python.org/downloads
#      (tick "Add Python to PATH" during install)
#   3. Open Command Prompt as Administrator and run:
#      pip install scapy
#
# USAGE (must run as Administrator):
#   python flood_test_windows.py --target <ubuntu-vm-ip>
#
# FIND YOUR UBUNTU VM IP:
#   On Ubuntu VM: run   ip a
#   Look for the IP on eth0/ens33 e.g. 192.168.0.105

import argparse
import socket
import sys
import time

try:
    from scapy.all import IP, TCP, ICMP, UDP, send, RandShort, conf, get_if_list
except ImportError:
    print("\n[ERROR] Scapy is not installed.")
    print("  Fix:  pip install scapy")
    print("  Also: Install Npcap from https://npcap.com/#download")
    sys.exit(1)

# Suppress MAC/ARP warnings
conf.verb = 0


# ---------------------------------------------------------------------------
# Windows interface detection
# ---------------------------------------------------------------------------

def _pick_interface() -> str:
    """
    Pick the best outbound interface on Windows.
    Scapy on Windows uses names like 'Ethernet', 'Wi-Fi', or a GUID.
    We match the interface whose IP equals the socket's outbound IP.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        from scapy.all import get_if_addr
        for iface in get_if_list():
            try:
                if get_if_addr(iface) == local_ip:
                    return iface
            except Exception:
                continue
    except Exception:
        pass

    # Fallback: first non-loopback interface
    for iface in get_if_list():
        if "loopback" not in iface.lower():
            return iface
    return get_if_list()[0]


def _my_lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(
    description="School IDS -- Windows Attack Simulator",
    formatter_class=argparse.RawTextHelpFormatter
)
parser.add_argument(
    "--target", "-t",
    required=True,
    help="IP of the Ubuntu VM running the IDS\nFind it on Ubuntu with: ip a"
)
parser.add_argument(
    "--interface", "-i",
    default=None,
    help="Network interface to send from (auto-detected if not set)\n"
         "List all: python -c \"from scapy.all import get_if_list; print(get_if_list())\""
)
parser.add_argument(
    "--count", "-c",
    type=int, default=200,
    help="Packets per attack type (default: 200)"
)
args = parser.parse_args()

TARGET    = args.target
COUNT     = args.count
INTERFACE = args.interface or _pick_interface()


# ---------------------------------------------------------------------------
# Attack functions
# ---------------------------------------------------------------------------

def syn_flood(count: int = COUNT) -> None:
    print(f"[*] SYN Flood -> {TARGET}:80  ({count} packets)")
    for _ in range(count):
        send(
            IP(dst=TARGET) / TCP(dport=80, flags="S", sport=RandShort()),
            iface=INTERFACE, verbose=False
        )
    print(f"[+] Done -- {count} SYN packets sent")


def port_scan(ports: int = 30) -> None:
    print(f"[*] Port Scan -> {TARGET}  ({ports} ports)")
    for port in range(1, ports + 1):
        send(
            IP(dst=TARGET) / TCP(dport=port, flags="S", sport=RandShort()),
            iface=INTERFACE, verbose=False
        )
    print(f"[+] Done -- scanned {ports} ports")


def icmp_flood(count: int = COUNT) -> None:
    print(f"[*] ICMP Flood -> {TARGET}  ({count} packets)")
    for _ in range(count):
        send(
            IP(dst=TARGET) / ICMP(),
            iface=INTERFACE, verbose=False
        )
    print(f"[+] Done -- {count} ICMP packets sent")


def udp_flood(count: int = COUNT) -> None:
    print(f"[*] UDP Flood -> {TARGET}:53  ({count} packets)")
    for _ in range(count):
        send(
            IP(dst=TARGET) / UDP(dport=53, sport=RandShort()),
            iface=INTERFACE, verbose=False
        )
    print(f"[+] Done -- {count} UDP packets sent")


def brute_force(count: int = COUNT) -> None:
    service_ports = [22, 21, 23, 3389]
    per_port      = max(1, count // len(service_ports))
    print(f"[*] Brute Force -> {TARGET}  (ports {service_ports}, {per_port} SYNs each)")
    for port in service_ports:
        for _ in range(per_port):
            send(
                IP(dst=TARGET) / TCP(dport=port, flags="S", sport=RandShort()),
                iface=INTERFACE, verbose=False
            )
    print(f"[+] Done -- Brute Force complete")


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------

def menu() -> None:
    print(f"""
========================================
  IDS Attack Simulator  (Windows)
  My IP     : {_my_lan_ip()}
  Target    : {TARGET}
  Interface : {INTERFACE}
  Count     : {COUNT} packets
========================================
  1. SYN Flood     (triggers SYN_FLOOD)
  2. Port Scan     (triggers PORT_SCAN)
  3. ICMP Flood    (triggers ICMP_FLOOD)
  4. UDP Flood     (triggers UDP_FLOOD)
  5. Brute Force   (triggers BRUTE_FORCE)
  6. Run ALL tests
  0. Exit
========================================""")

    choice = input("Choose: ").strip()

    if choice == "1":
        syn_flood()
    elif choice == "2":
        port_scan()
    elif choice == "3":
        icmp_flood()
    elif choice == "4":
        udp_flood()
    elif choice == "5":
        brute_force()
    elif choice == "6":
        for fn in [syn_flood, port_scan, icmp_flood, udp_flood, brute_force]:
            fn()
            time.sleep(2)
        print("\n[+] All tests done. Check the IDS dashboard for alerts.")
    elif choice == "0":
        print("Goodbye.")
        sys.exit(0)
    else:
        print("Invalid choice.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import ctypes

    # Enforce Administrator on Windows
    if sys.platform == "win32" and not ctypes.windll.shell32.IsUserAnAdmin():
        print("\n[ERROR] This script must be run as Administrator.")
        print("  Right-click Command Prompt -> 'Run as administrator'")
        print(f"  Then: python flood_test_windows.py --target {TARGET}")
        sys.exit(1)

    print(f"\n[*] My IP      : {_my_lan_ip()}")
    print(f"[*] Target     : {TARGET}")
    print(f"[*] Interface  : {INTERFACE}")
    print(f"\n[*] Make sure the IDS capture is running on the Ubuntu VM first.")
    print(f"[*] Override interface if wrong:")
    print(f"    python flood_test_windows.py --target {TARGET} --interface \"Ethernet\"\n")

    while True:
        menu()