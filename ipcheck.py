import requests
import ipaddress
import csv
import os
import sys
import time
import socket
import threading
import concurrent.futures
from datetime import datetime
from colorama import Fore, Style, init
from dotenv import load_dotenv

# ─────────────────────────────────────────────
# INIT
# ─────────────────────────────────────────────

init(autoreset=True)
load_dotenv()

IPINFO_TOKEN  = os.getenv("IPINFO_TOKEN")  or "YOUR_IPINFO_TOKEN"
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY") or "YOUR_ABUSEIPDB_API_KEY"

# ─────────────────────────────────────────────
# THREAD LOCK & STATS
# ─────────────────────────────────────────────

_lock = threading.Lock()

stats = {
    "total_scanned":    0,
    "successful_scans": 0,
    "private_ips":      0,
    "failed_ips":       0,
    "invalid_ips":      0,
    "abusive_ips":      0,
}

# Buffer: stores (report_text, csv_row) tuples for saving later
_report_buffer: list[tuple[str, list]] = []

# ─────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"

# Rate limiter
_last_req = 0.0
_req_interval = 0.15

def _get(url: str, headers: dict = None, timeout: int = 10) -> requests.Response:
    global _last_req
    elapsed = time.time() - _last_req
    if elapsed < _req_interval:
        time.sleep(_req_interval - elapsed)
    resp = requests.get(url, headers=headers or {}, timeout=timeout)
    _last_req = time.time()
    return resp

# ─────────────────────────────────────────────
# ABUSEIPDB LOOKUP
# ─────────────────────────────────────────────

def check_abuse(ip: str) -> dict:
    if not ABUSEIPDB_KEY:
        return {}
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        params  = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code != 200:
            return {}
        return resp.json().get("data", {})
    except Exception:
        return {}

# ─────────────────────────────────────────────
# BUFFER HELPERS
# ─────────────────────────────────────────────

def buffer_result(report_text: str, csv_row: list) -> None:
    with _lock:
        _report_buffer.append((report_text, csv_row))

# ─────────────────────────────────────────────
# CORE: CHECK SINGLE IP
# ─────────────────────────────────────────────

def check_ip(ip: str) -> None:
    ip = ip.strip()
    if not ip:
        return

    # ── Validate ─────────────────────────────
    if not is_valid_ip(ip):
        with _lock:
            stats["failed_ips"]  += 1
            stats["invalid_ips"] += 1
        print(Fore.RED + f"  [INVALID]  {ip}")
        buffer_result(f"IP: {ip}  |  Status: INVALID", [ip, *["N/A"] * 14, "INVALID"])
        return

    ip_obj = ipaddress.ip_address(ip)

    # ── Private / Loopback / Link-local ──────
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        label = (
            "LOOPBACK"   if ip_obj.is_loopback   else
            "LINK-LOCAL" if ip_obj.is_link_local else
            "PRIVATE"
        )
        with _lock:
            stats["private_ips"]   += 1
            stats["total_scanned"] += 1
        print(Fore.CYAN + f"  [{label}]  {ip}  ← internal address")
        buffer_result(f"IP: {ip}  |  Status: {label}", [ip, *["N/A"] * 13, label])
        return

    # ── IPInfo lookup ─────────────────────────
    try:
        t0  = time.time()
        url = (
            f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}"
            if IPINFO_TOKEN else
            f"https://ipinfo.io/{ip}/json"
        )
        resp       = _get(url, timeout=10)
        latency_ms = round((time.time() - t0) * 1000)

        if resp.status_code == 429:
            raise Exception("IPInfo rate limit exceeded")
        if resp.status_code != 200:
            raise Exception(f"IPInfo HTTP {resp.status_code}")

        try:
            data = resp.json()
        except ValueError:
            raise Exception("IPInfo returned non-JSON body")

        hostname = data.get("hostname", "N/A")
        city     = data.get("city",     "N/A")
        region   = data.get("region",   "N/A")
        country  = data.get("country",  "N/A")
        postal   = data.get("postal",   "N/A")
        timezone = data.get("timezone", "N/A")
        org      = data.get("org",      "N/A")
        loc      = data.get("loc",      "N/A")
        rdns     = reverse_dns(ip)

    except Exception as exc:
        with _lock:
            stats["failed_ips"]    += 1
            stats["total_scanned"] += 1
        print(Fore.RED + f"  [ERROR]  {ip}  →  {exc}")
        buffer_result(f"IP: {ip}  |  Status: ERROR  |  {exc}", [ip, *["N/A"] * 14, "ERROR"])
        return

    # ── AbuseIPDB lookup ──────────────────────
    abuse_data     = check_abuse(ip)
    abuse_score    = abuse_data.get("abuseConfidenceScore", "N/A")
    abuse_reports  = abuse_data.get("totalReports",         "N/A")
    is_whitelisted = abuse_data.get("isWhitelisted",        "N/A")
    last_reported  = abuse_data.get("lastReportedAt",       "N/A") or "Never"

    if abuse_score not in ("N/A",) and int(abuse_score) > 0:
        with _lock:
            stats["abusive_ips"] += 1

    # ── Finalize ──────────────────────────────
    with _lock:
        stats["total_scanned"]    += 1
        stats["successful_scans"] += 1

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Colour-code abuse score
    if abuse_score == "N/A":
        abuse_color = Fore.WHITE
        abuse_label = "N/A (AbuseIPDB key not set)"
    elif int(abuse_score) >= 80:
        abuse_color = Fore.RED
        abuse_label = f"{abuse_score}%  ⚠ HIGH RISK"
    elif int(abuse_score) >= 30:
        abuse_color = Fore.YELLOW
        abuse_label = f"{abuse_score}%  ⚠ SUSPICIOUS"
    else:
        abuse_color = Fore.GREEN
        abuse_label = f"{abuse_score}%  ✔ CLEAN"

    report = (
        f"\n{'='*70}\n"
        f"  IP INFORMATION REPORT\n"
        f"{'='*70}\n\n"
        f"  Scan Time      : {scan_time}\n"
        f"  Response Time  : {latency_ms} ms\n\n"
        f"  IP Address     : {ip}\n"
        f"  Hostname       : {hostname}\n"
        f"  Reverse DNS    : {rdns}\n"
        f"  Organization   : {org}\n\n"
        f"  {'─'*30} GEOLOCATION {'─'*26}\n\n"
        f"  City           : {city}\n"
        f"  Region         : {region}\n"
        f"  Country        : {country}\n"
        f"  Postal Code    : {postal}\n"
        f"  Timezone       : {timezone}\n"
        f"  Coordinates    : {loc}\n\n"
        f"  {'─'*30} ABUSE REPORT {'─'*25}\n\n"
        f"  Abuse Score    : {abuse_label}\n"
        f"  Total Reports  : {abuse_reports}\n"
        f"  Whitelisted    : {is_whitelisted}\n"
        f"  Last Reported  : {last_reported}\n\n"
        f"  Status         : ACTIVE\n"
    )

    # Print result live
    abuse_section_start = report.find("ABUSE REPORT") - 4
    print(Fore.GREEN  + report[:abuse_section_start])
    print(abuse_color + report[abuse_section_start:])

    # Buffer for optional save
    csv_row = [
        ip, hostname, org, city, region, country,
        postal, timezone, loc, rdns, latency_ms,
        abuse_score, abuse_reports, is_whitelisted, last_reported,
        "ACTIVE",
    ]
    buffer_result(report, csv_row)

# ─────────────────────────────────────────────
# BULK CONCURRENT SCAN
# ─────────────────────────────────────────────

def scan_bulk_concurrent(ips: list, max_workers: int = 5) -> None:
    total = len(ips)
    print(Fore.CYAN + f"\n  Scanning {total} IPs with {max_workers} threads…\n")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(check_ip, ip): ip for ip in ips}
        for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            ip = futures[fut]
            try:
                fut.result()
            except Exception as exc:
                print(Fore.RED + f"  [THREAD-ERROR] {ip}: {exc}")
            pct = int((i / total) * 40)
            bar = Fore.GREEN + "█" * pct + Fore.WHITE + "░" * (40 - pct)
            print(f"\r  Progress: [{bar}{Fore.RESET}] {i}/{total}", end="", flush=True)
    print()

# ─────────────────────────────────────────────
# SAVE REPORTS
# ─────────────────────────────────────────────

def save_reports() -> None:
    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    TXT_REPORT = f"report_{timestamp}.txt"
    CSV_REPORT = f"report_{timestamp}.csv"

    # Write TXT
    with open(TXT_REPORT, "w", encoding="utf-8") as fh:
        for report_text, _ in _report_buffer:
            fh.write(report_text + "\n" + "=" * 70 + "\n")

    # Write CSV
    with open(CSV_REPORT, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "IP Address", "Hostname", "Organization",
            "City", "Region", "Country", "Postal",
            "Timezone", "Coordinates", "Reverse DNS",
            "Response Time (ms)",
            "Abuse Score", "Abuse Reports",
            "Is Whitelisted", "Last Reported",
            "Status",
        ])
        for _, csv_row in _report_buffer:
            writer.writerow(csv_row)

    print()
    print(Fore.GREEN + f"  ✔  TXT Report saved : {TXT_REPORT}")
    print(Fore.GREEN + f"  ✔  CSV Report saved : {CSV_REPORT}")

# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────

print(Fore.CYAN + r"""
╔══════════════════════════════════════════════════════════════╗
║          ADVANCED IP INFORMATION SCANNER                     ║
║                     Author: Raghavaraj                       ║
╚══════════════════════════════════════════════════════════════╝
""")

print(Fore.GREEN + f"  ✔  IPInfo token    : {'Loaded' if IPINFO_TOKEN  else Fore.YELLOW + 'Not set (tokenless mode)'}")
print(Fore.GREEN + f"  ✔  AbuseIPDB key   : {'Loaded' if ABUSEIPDB_KEY else Fore.YELLOW + 'Not set (abuse check disabled)'}")
print()

# ─────────────────────────────────────────────
# MENU
# ─────────────────────────────────────────────

print(Fore.WHITE + "  1.  Scan Single IP")
print(Fore.WHITE + "  2.  Scan Bulk IPs from File  (sequential)")
print(Fore.WHITE + "  3.  Scan Bulk IPs from File  (concurrent / faster)")
print(Fore.WHITE + "  4.  Exit")

choice = input(Fore.YELLOW + "\n  Select Option (1-4): " + Fore.RESET).strip()

# ─────────────────────────────────────────────
# HANDLERS
# ─────────────────────────────────────────────

if choice == "1":
    ip = input(Fore.YELLOW + "\n  Enter IP Address: " + Fore.RESET).strip()
    check_ip(ip)

elif choice in ("2", "3"):
    file_path = input(Fore.YELLOW + "\n  Enter file path: " + Fore.RESET).strip()

    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            ips = [line.strip() for line in fh if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"\n  File not found: {file_path}")
        sys.exit(1)
    except PermissionError:
        print(Fore.RED + f"\n  Permission denied: {file_path}")
        sys.exit(1)
    except UnicodeDecodeError:
        print(Fore.YELLOW + "  Warning: UTF-8 failed, retrying with latin-1…")
        with open(file_path, "r", encoding="latin-1") as fh:
            ips = [line.strip() for line in fh if line.strip()]

    # Deduplicate
    seen, unique_ips = set(), []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)
    if (dupes := len(ips) - len(unique_ips)):
        print(Fore.YELLOW + f"  Removed {dupes} duplicate IP(s).")

    if choice == "3":
        w = input(Fore.YELLOW + "  Workers (default 5): " + Fore.RESET).strip()
        workers = int(w) if w.isdigit() and int(w) > 0 else 5
        scan_bulk_concurrent(unique_ips, max_workers=workers)
    else:
        total = len(unique_ips)
        print(Fore.CYAN + f"\n  Loaded {total} unique IPs.\n")
        for count, ip in enumerate(unique_ips, 1):
            print(Fore.WHITE + f"  [{count}/{total}] Scanning {ip} …")
            check_ip(ip)

elif choice == "4":
    print(Fore.CYAN + "\n  Goodbye!\n")
    sys.exit(0)

else:
    print(Fore.RED + "\n  Invalid option.")
    sys.exit(1)

# ─────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────

print("\n")
print(Fore.WHITE + "  " + "=" * 58)
print(Fore.WHITE + "  SCAN SUMMARY")
print(Fore.WHITE + "  " + "=" * 58)
print(Fore.WHITE + f"  Total IPs Scanned   : {stats['total_scanned']}")
print(Fore.CYAN  + f"  Private / Internal  : {stats['private_ips']}")
print(Fore.GREEN + f"  Successful Scans    : {stats['successful_scans']}")
print(Fore.RED   + f"  Abusive IPs Found   : {stats['abusive_ips']}")
print(Fore.RED   + f"  Failed / Error      : {stats['failed_ips']}")
print(Fore.RED   + f"  Invalid IPs         : {stats['invalid_ips']}")
print(Fore.WHITE + "  " + "=" * 58)

# ─────────────────────────────────────────────
# SAVE PROMPT
# ─────────────────────────────────────────────

print()
save_choice = input(
    Fore.YELLOW + "  Do you want to save the report? (y/n): " + Fore.RESET
).strip().lower()

if save_choice in ("y", "yes"):
    save_reports()
else:
    print(Fore.CYAN + "\n  Reports not saved.")

print()
print(Fore.CYAN + "  Scan Completed Successfully.")
print(Style.RESET_ALL)
