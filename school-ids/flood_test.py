#!/usr/bin/env python3
# flood_test.py — Attack Simulator
# Fixes:
#   - FIX: conf.verb = 0 suppresses all Scapy MAC/ARP warnings
#   - FIX: iface= passed to every send() so packets go out the correct interface
#   - FIX: Auto-detect network interface so IDS sniffer actually sees the packets
#   - NEW: --interface CLI argument to override auto-detection
#   - NEW: brute_force() attack type
#   - NEW: dns_amplification() attack type
#   - NEW: http_flood() attack type
#   - NEW: null_scan() attack type

import argparse
import socket
import subprocess
import sys
import time

from scapy.all import IP, TCP, ICMP, UDP, send, RandShort, conf

# Suppress all Scapy warnings (MAC address not found, broadcast fallback, etc.)
conf.verb = 0


# ---------------------------------------------------------------------------
# Auto-detect helpers
# ---------------------------------------------------------------------------

def _default_target() -> str:
    """Return the machine's primary LAN IP (not 127.0.0.1)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())


def _default_iface() -> str:
    """Return the primary outbound network interface (e.g. eth0, ens33)."""
    try:
        result = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"],
            capture_output=True, text=True
        )
        # Output: "8.8.8.8 via 192.168.0.1 dev eth0 src 192.168.0.110 ..."
        tokens = result.stdout.split()
        if "dev" in tokens:
            return tokens[tokens.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(description="School IDS — Attack Simulator")
parser.add_argument(
    "--target", "-t",
    default=_default_target(),
    help="Target IP address (default: your LAN IP)"
)
parser.add_argument(
    "--interface", "-i",
    default=None,
    help="Network interface to send packets on (e.g. eth0, ens33). Auto-detected if not set."
)
parser.add_argument(
    "--count", "-c",
    type=int, default=200,
    help="Number of packets per attack type (default: 200)"
)
args = parser.parse_args()

TARGET    = args.target
COUNT     = args.count
INTERFACE = args.interface or _default_iface()


# ---------------------------------------------------------------------------
# Attack functions — all use iface=INTERFACE so packets go through the
# correct physical NIC and are visible to the IDS sniffer
# ---------------------------------------------------------------------------

def syn_flood(count: int = COUNT) -> None:
    print(f"[*] SYN Flood -> {TARGET}:80  ({count} packets)  via {INTERFACE}")
    for _ in range(count):
        send(
            IP(dst=TARGET) / TCP(dport=80, flags="S", sport=RandShort()),
            iface=INTERFACE,
            verbose=False
        )
    print(f"[+] Sent {count} SYN packets")


def port_scan(ports: int = 30) -> None:
    print(f"[*] Port Scan -> {TARGET}  ({ports} ports)  via {INTERFACE}")
    for port in range(1, ports + 1):
        send(
            IP(dst=TARGET) / TCP(dport=port, flags="S", sport=RandShort()),
            iface=INTERFACE,
            verbose=False
        )
    print(f"[+] Scanned {ports} ports")


def icmp_flood(count: int = COUNT) -> None:
    print(f"[*] ICMP Flood -> {TARGET}  ({count} packets)  via {INTERFACE}")
    for _ in range(count):
        send(
            IP(dst=TARGET) / ICMP(),
            iface=INTERFACE,
            verbose=False
        )
    print(f"[+] Sent {count} ICMP packets")


def udp_flood(count: int = COUNT) -> None:
    print(f"[*] UDP Flood -> {TARGET}:53  ({count} packets)  via {INTERFACE}")
    for _ in range(count):
        send(
            IP(dst=TARGET) / UDP(dport=53, sport=RandShort()),
            iface=INTERFACE,
            verbose=False
        )
    print(f"[+] Sent {count} UDP packets")


def brute_force(count: int = COUNT) -> None:
    """
    Simulates repeated login attempts against common service ports.
    Triggers the BRUTE_FORCE detection rule.
    """
    service_ports = [22, 21, 23, 3389]
    per_port      = max(1, count // len(service_ports))
    print(
        f"[*] Brute Force -> {TARGET}  "
        f"(ports {service_ports}, {per_port} SYNs each)  via {INTERFACE}"
    )
    for port in service_ports:
        for _ in range(per_port):
            send(
                IP(dst=TARGET) / TCP(dport=port, flags="S", sport=RandShort()),
                iface=INTERFACE,
                verbose=False
            )
    print(f"[+] Brute Force complete")


def dns_amplification(count: int = COUNT) -> None:
    """
    NEW: DNS Amplification Attack Simulation.
    Sends a high volume of UDP packets to port 53 (DNS server).
    In a real attack, the source IP would be spoofed so the large DNS
    responses flood the victim. Here we simulate the outbound query flood
    so the IDS DNS_AMPLIFICATION rule can detect the traffic pattern.
    Triggers: DNS_AMPLIFICATION rule (50 UDP packets to port 53 in 5s)
    """
    print(f"[*] DNS Amplification -> {TARGET}:53  ({count} packets)  via {INTERFACE}")
    for _ in range(count):
        send(
            IP(dst=TARGET) / UDP(dport=53, sport=RandShort()),
            iface=INTERFACE,
            verbose=False
        )
    print(f"[+] Sent {count} DNS query packets")


def http_flood(count: int = COUNT) -> None:
    """
    NEW: HTTP Flood Attack Simulation.
    Sends a large number of TCP SYN packets to web server ports (80, 443, 8080, 8443).
    This simulates an attacker trying to exhaust a web server's connection table,
    causing it to be unable to serve legitimate users (Denial of Service).
    Triggers: HTTP_FLOOD rule (80 TCP SYN packets to web ports in 10s)
    """
    web_ports = [80, 443, 8080, 8443]
    per_port  = max(1, count // len(web_ports))
    print(
        f"[*] HTTP Flood -> {TARGET}  "
        f"(ports {web_ports}, {per_port} SYNs each)  via {INTERFACE}"
    )
    for port in web_ports:
        for _ in range(per_port):
            send(
                IP(dst=TARGET) / TCP(dport=port, flags="S", sport=RandShort()),
                iface=INTERFACE,
                verbose=False
            )
    print(f"[+] HTTP Flood complete")


def null_scan(count: int = 30) -> None:
    """
    NEW: NULL Scan (Stealth Port Probe).
    Sends TCP packets with NO flags set (flags=0).
    This is a stealthy reconnaissance technique — RFC 793 specifies that
    a closed port should reply with RST, while an open port gives no response.
    Attackers use this to map open ports while evading basic firewalls that
    only block SYN packets.
    Normal traffic never has empty TCP flags, so this is always suspicious.
    Triggers: NULL_SCAN rule (10 null-flag packets in 10s)
    """
    print(f"[*] NULL Scan -> {TARGET}  ({count} packets, no TCP flags)  via {INTERFACE}")
    for port in range(1, count + 1):
        send(
            IP(dst=TARGET) / TCP(dport=port, flags=0, sport=RandShort()),
            iface=INTERFACE,
            verbose=False
        )
    print(f"[+] NULL Scan complete ({count} packets sent)")


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

def menu() -> None:
    print(f"""
========================================
  IDS Attack Simulator
  Target    : {TARGET}
  Interface : {INTERFACE}
  Count     : {COUNT} packets per test
========================================
  1. SYN Flood          (triggers SYN_FLOOD)
  2. Port Scan          (triggers PORT_SCAN)
  3. ICMP Flood         (triggers ICMP_FLOOD)
  4. UDP Flood          (triggers UDP_FLOOD)
  5. Brute Force        (triggers BRUTE_FORCE)
  6. DNS Amplification  (triggers DNS_AMPLIFICATION)
  7. HTTP Flood         (triggers HTTP_FLOOD)
  8. NULL Scan          (triggers NULL_SCAN)
  9. Run ALL tests
  0. Exit
========================================
NOTE: IDS capture must be running on
      interface: {INTERFACE}
      Run  ip a  to verify interface name.
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
        dns_amplification()
    elif choice == "7":
        http_flood()
    elif choice == "8":
        null_scan()
    elif choice == "9":
        for fn in [syn_flood, port_scan, icmp_flood, udp_flood,
                   brute_force, dns_amplification, http_flood, null_scan]:
            fn()
            time.sleep(2)
        print("\n[+] All tests complete. Check the dashboard or CLI for alerts.")
    elif choice == "0":
        sys.exit(0)
    else:
        print("Invalid choice -- try again.")


if __name__ == "__main__":
    print(f"\n[*] Target    : {TARGET}")
    print(f"[*] Interface : {INTERFACE}")
    print("[*] Override with:  sudo python3 flood_test.py --target <IP> --interface <iface>\n")
    while True:
        menu()
