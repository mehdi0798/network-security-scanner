"""
utils.py — Shared helpers for Network Security Scanner
Author: Marhfour Mehdi
"""


class Color:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    WHITE  = '\033[97m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'


def c(color, text):
    return f"{color}{text}{Color.RESET}"


RISK_DB = {
    21:   ("FTP",        "HIGH",   "Plaintext credentials — easily intercepted"),
    22:   ("SSH",        "MEDIUM", "Secure shell — ensure key-based auth only"),
    23:   ("Telnet",     "HIGH",   "Unencrypted remote access — replace with SSH"),
    25:   ("SMTP",       "MEDIUM", "Mail server — verify relay restrictions"),
    53:   ("DNS",        "MEDIUM", "DNS exposed — risk of amplification attacks"),
    80:   ("HTTP",       "MEDIUM", "Unencrypted web traffic — consider HTTPS"),
    110:  ("POP3",       "MEDIUM", "Plaintext mail retrieval"),
    143:  ("IMAP",       "MEDIUM", "Plaintext mail access"),
    443:  ("HTTPS",      "LOW",    "Encrypted — verify certificate validity"),
    445:  ("SMB",        "HIGH",   "Common ransomware vector (EternalBlue/WannaCry)"),
    993:  ("IMAPS",      "LOW",    "Encrypted IMAP"),
    995:  ("POP3S",      "LOW",    "Encrypted POP3"),
    1433: ("MSSQL",      "HIGH",   "Database exposed — restrict network access"),
    3306: ("MySQL",      "MEDIUM", "Database port — should not face public internet"),
    3389: ("RDP",        "HIGH",   "Remote Desktop — frequent brute-force target"),
    5432: ("PostgreSQL", "MEDIUM", "Database port — verify access controls"),
    6379: ("Redis",      "MEDIUM", "Often deployed without authentication"),
    8080: ("HTTP-Alt",   "MEDIUM", "Often used for dev/proxy — check configuration"),
    8443: ("HTTPS-Alt",  "LOW",    "Alternative HTTPS port"),
    27017:("MongoDB",    "HIGH",   "Database — frequently exposed with no auth"),
}

RISK_COLOR = {
    "HIGH":   Color.RED,
    "MEDIUM": Color.YELLOW,
    "LOW":    Color.GREEN,
}


def assess_risk(port, service_name=""):
    if port in RISK_DB:
        _, risk, note = RISK_DB[port]
        return risk, note
    service_name = service_name.lower()
    if service_name in ("ftp", "telnet"):
        return "HIGH", "Plaintext protocol — credentials at risk"
    if service_name in ("http", "smtp", "pop3", "imap"):
        return "MEDIUM", "Unencrypted protocol detected"
    if service_name in ("https", "ssh", "imaps"):
        return "LOW", "Encrypted protocol"
    return "LOW", "No specific risk profile identified"


BANNER = """
  Network Security Scanner v2.0
  Author : Marhfour Mehdi  |  github.com/mehdi0798
  For authorized testing and educational use only
"""


def print_banner():
    print(BANNER)