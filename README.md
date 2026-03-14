# Network Security Scanner

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

A Python-based CLI tool for network reconnaissance and vulnerability assessment. Performs port scanning, service detection, banner grabbing, and risk classification — then exports results to a timestamped CSV report.

Built during cybersecurity studies at Al Akhawayn University, inspired by real-world SOC workflows from internships at Fortinet and Palo Alto Networks.

## Features
- Port scanning via nmap with service and version detection
- Multithreaded banner grabbing for faster reconnaissance
- Risk classification — HIGH / MEDIUM / LOW with explanation per port
- CSV report generation with full scan metadata
- Report comparison — diff two scans to detect changes over time
- Color-coded terminal output for fast triage

## Project Structure
```
network-security-scanner/
├── scanner.py           # Main entry point
├── utils.py             # Colors, risk database, shared helpers
├── report_generator.py  # CSV export, risk summary, report diff
└── requirements.txt
```

## Installation

**1. Install Nmap**
- Windows: https://nmap.org/download.html
- Linux: `sudo apt-get install nmap`

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

## Usage
```bash
# Interactive mode
python scanner.py

# Scan a single host
python scanner.py 192.168.1.1

# Custom port range
python scanner.py 192.168.1.1 -p 1-65535

# Top 100 ports only
python scanner.py 192.168.1.1 --top-ports
```

## Disclaimer
For authorized security testing and educational use only.

## Author
**Marhfour Mehdi** — github.com/mehdi0798