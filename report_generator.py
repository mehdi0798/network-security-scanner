"""
report_generator.py — CSV & summary report generation
Author: Marhfour Mehdi
"""

import os
import pandas as pd
from datetime import datetime
from utils import Color, c, RISK_COLOR


def save_report(results, output_dir="reports"):
    if not results:
        print(c(Color.YELLOW, "\n[!] No open ports found — no report generated."))
        return None

    os.makedirs(output_dir, exist_ok=True)

    df = pd.DataFrame(results)

    col_order = ["Host", "Port", "Protocol", "Service", "Product/Version",
                 "Risk", "Risk_Note", "Banner", "State", "Scan_Time"]
    df = df[[col for col in col_order if col in df.columns]]

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath  = os.path.join(output_dir, f"scan_{timestamp}.csv")
    df.to_csv(filepath, index=False)

    print(f"\n[+] Report saved  → {filepath}")
    print(f"[+] Open ports    : {len(results)}")

    print("\n  RISK SUMMARY")
    print("  " + "─" * 35)

    for risk in ["HIGH", "MEDIUM", "LOW"]:
        items = [r for r in results if r["Risk"] == risk]
        if items:
            ports = ", ".join(str(r["Port"]) for r in items)
            print(f"  {risk:<8}  {len(items)} port(s)  →  {ports}")

    high_risk = [r for r in results if r["Risk"] == "HIGH"]
    if high_risk:
        print("\n  [!] ACTION REQUIRED — High-risk ports detected:")
        for r in high_risk:
            print(f"      Port {r['Port']} ({r['Service']}) — {r['Risk_Note']}")

    print("─" * 65)
    return filepath


def load_report(filepath):
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        return None
    return pd.read_csv(filepath)


def compare_reports(old_path, new_path):
    """Compare two scan reports and highlight newly opened/closed ports."""
    old = load_report(old_path)
    new = load_report(new_path)

    if old is None or new is None:
        return

    old_ports = set(zip(old["Host"], old["Port"]))
    new_ports = set(zip(new["Host"], new["Port"]))

    opened = new_ports - old_ports
    closed = old_ports - new_ports

    print("\n  REPORT COMPARISON")
    print("  " + "─" * 40)

    if opened:
        print(f"  [+] Newly OPENED ports ({len(opened)}):")
        for host, port in sorted(opened):
            print(f"      {host}:{port}")
    else:
        print("  [+] No new ports opened.")

    if closed:
        print(f"  [-] Ports now CLOSED ({len(closed)}):")
        for host, port in sorted(closed):
            print(f"      {host}:{port}")
    else:
        print("  [-] No ports closed since last scan.")