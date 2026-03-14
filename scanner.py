#!/usr/bin/env python3
"""
Network Security Scanner
Author: Marhfour Mehdi
GitHub: github.com/mehdi0798
Version: 2.0
"""

import nmap
import socket
import argparse
import sys
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import Color, c, print_banner, assess_risk, RISK_COLOR
from report_generator import save_report


def resolve_host(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def grab_banner(host, port, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner[:100] if banner else "N/A"
    except Exception:
        return "N/A"


def scan(target, port_range="1-1024", grab_banners=True, threads=10):
    ip = resolve_host(target)
    if not ip:
        print(c(Color.RED, f"[!] Cannot resolve target: {target}"))
        sys.exit(1)

    print(c(Color.CYAN, f"\n[*] Target  : {target} ({ip})"))
    print(c(Color.CYAN, f"[*] Ports   : {port_range}"))
    print(c(Color.CYAN, f"[*] Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(c(Color.WHITE, "─" * 65))

    nm = nmap.PortScanner()
    nm.scan(ip, port_range, arguments="-sV --open -T4")

    results = []

    for host in nm.all_hosts():
        print(c(Color.GREEN, f"\n[+] Host {host} is {nm[host].state().upper()}"))
        print(f"  {'PORT':<8} {'SERVICE':<22} {'RISK':<9} {'NOTE'}")
        print(c(Color.WHITE, "  " + "─" * 60))

        for proto in nm[host].all_protocols():
            ports = sorted(nm[host][proto].keys())

            banners = {}
            if grab_banners:
                open_ports = [p for p in ports if nm[host][proto][p]["state"] == "open"]
                with ThreadPoolExecutor(max_workers=threads) as ex:
                    futures = {ex.submit(grab_banner, host, p): p for p in open_ports}
                    for future in as_completed(futures):
                        banners[futures[future]] = future.result()

            for port in ports:
                svc = nm[host][proto][port]
                if svc["state"] != "open":
                    continue

                service_name = svc.get("name", "unknown")
                product      = svc.get("product", "")
                version      = svc.get("version", "")
                label        = f"{product} {version}".strip() or service_name
                banner       = banners.get(port, "N/A")
                risk, note   = assess_risk(port, service_name)
                risk_col     = RISK_COLOR.get(risk, Color.WHITE)

                print(
                    f"  {c(Color.BOLD, str(port)+'/'+proto):<16}"
                    f"{label[:20]:<22}"
                    f"{c(risk_col, risk):<18}"
                    f"{c(Color.BLUE, note)}"
                )

                results.append({
                    "Host":            host,
                    "Port":            port,
                    "Protocol":        proto,
                    "State":           "open",
                    "Service":         service_name,
                    "Product/Version": label,
                    "Banner":          banner,
                    "Risk":            risk,
                    "Risk_Note":       note,
                    "Scan_Time":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                })

    return results


def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Security Scanner — by Marhfour Mehdi"
    )
    parser.add_argument("target", nargs="?", help="Target IP, hostname, or CIDR range")
    parser.add_argument("-p", "--ports",  default="1-1024", help="Port range (default: 1-1024)")
    parser.add_argument("--no-banner",    action="store_true", help="Skip banner grabbing")
    parser.add_argument("-o", "--output", default="reports", help="Output directory")
    parser.add_argument("--top-ports",    action="store_true", help="Scan top 100 ports only")
    return parser.parse_args()


def main():
    print_banner()
    args = parse_args()

    target = args.target
    if not target:
        print("Enter a target to scan:")
        print("  Single IP : 192.168.1.1")
        print("  Network   : 192.168.1.0/24")
        print("  Hostname  : scanme.nmap.org\n")
        target = input("Target: ").strip() or "127.0.0.1"

    port_range = "1-100" if args.top_ports else args.ports

    print(c(Color.YELLOW, f"\n[!] About to scan: {target} — ports {port_range}"))
    if input("[?] Continue? (y/n): ").lower() != "y":
        print("[!] Scan cancelled.")
        return

    try:
        results = scan(target, port_range, not args.no_banner)
        save_report(results, args.output)
        print(c(Color.GREEN, "\n[✓] Scan complete!\n"))
    except KeyboardInterrupt:
        print(c(Color.YELLOW, "\n[!] Interrupted by user."))
    except Exception as e:
        print(c(Color.RED, f"\n[!] Error: {e}"))
        print("[!] Make sure nmap is installed and you have the right permissions.")


if __name__ == "__main__":
    main()