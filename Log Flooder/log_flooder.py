#!/usr/bin/env python3
# Seonho Park, scp4941@rit.edu

import re
import os
import time
import argparse
import logging
import hashlib
from logging.handlers import SysLogHandler
from datetime import datetime, timezone

import subprocess
import sys

# Configurations
MAX_RATE = 50          # max messages/sec (DOS safeguard)
MAX_DURATION = 300     # seconds (5 min cap)
DEFAULT_LOGS = [
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/messages"
]
TAG = "RT"

# ---------------------------------------------------------------------------
# Pattern-based log analysis / info extraction
# ---------------------------------------------------------------------------

# Pre-compiled patterns — compile once, reuse for every line.
_IP_RE   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(r"user(?:name)?[=:\s]+([a-zA-Z0-9_@.-]+)", re.IGNORECASE)
_FAIL_RE = re.compile(
    r"(failed|failure|invalid|unauthorized|denied|error|refused|rejected)",
    re.IGNORECASE,
)
_PORT_RE = re.compile(r"\bport\s+(\d{1,5})\b", re.IGNORECASE)


#   Scan log files and return structured findings.
def extract_info(log_paths: list[str], keywords: list[str],) -> list[dict]:

    findings: list[dict] = []

    for path in log_paths:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", errors="ignore") as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line:
                        continue

                    matched_kw  = [kw for kw in keywords if kw.lower() in line.lower()]
                    ips         = _IP_RE.findall(line)
                    users       = _USER_RE.findall(line)
                    ports       = _PORT_RE.findall(line)
                    flags: list[str] = []

                    if _FAIL_RE.search(line):
                        flags.append("auth_failure_or_error")

                    # Only record lines that matched something of interest.
                    if matched_kw or ips or users or flags:
                        findings.append({
                            "source":    path,                                      # log file path
                            "line":      line,                                      # original log line
                            "timestamp": datetime.now(timezone.utc).isoformat(),    # time the line was processed
                            "ips":       ips,                                       # list of IP addresses found in the line
                            "users":     users,                                     # list of users found in the line
                            "ports":     ports,                                     # list of port numbers found in the line
                            "keywords":  matched_kw,                                # list of keywords to matched
                            "flags":     flags,                                     # list of detected flags
                            "hash":      hashlib.sha256(line.encode()).hexdigest(), # hash of the line
                        })
        except PermissionError:
            continue

    return findings

# Checks if user is privileged
def is_privileged():
    return os.geteuid() == 0

# Reads logs accessible to current users and returns raw log lines
def read_logs(log_paths):
    entries = []
    for path in log_paths:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", errors="ignore") as file:
                for line in file:
                    entries.append((path, line.strip()))
        except PermissionError:
            continue # Expected for unprivileged users
    return entries

# Controlled Log Flooder
def setup_syslog():
    logger = logging.getLogger("ctf_flooder")
    logger.setLevel(logging.INFO)

    handler = SysLogHandler(address="/dev/log")
    formatter = logging.Formatter(f"{TAG}: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger

# Floods logs with synthetic log entries
def flood_logs(rate, duration):
    rate = min(rate, MAX_RATE)
    duration = min(duration, MAX_DURATION)

    logger = setup_syslog()

    print(f"[+] Flooding logs at {rate} msg/sec for {duration}s")

    interval = 1.0 / rate
    end_time = time.time() + duration
    counter = 0

    while time.time() < end_time:
        msg = (
            f"simulation_event id={counter} "
            f"timestamp={datetime.utcnow().isoformat()} "
            f"status=ok"
        )

        logger.info(msg)
        counter += 1
        time.sleep(interval)

    print(f"[+] Flood complete ({counter} entries written)")

def create_cron_persistence(script_path):
    cron_job = f"*/5 * * * * /usr/bin/python3 {script_path}\n"
    
    try:
        # Get current crontab
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        current_cron = result.stdout if result.returncode == 0 else ""
        
        # Append new job
        new_cron = current_cron + cron_job
        
        # Write back
        process = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
        process.communicate(input=new_cron)
        
        print("[+] Cron persistence established (every 5 minutes)")
        return True
    except Exception as e:
        print(f"[-] Cron setup failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Log collection and flood tool"
    )

    parser.add_argument(
        "--logs",
        nargs="*",
        default=DEFAULT_LOGS,
        help="Log files to read"
    )

    parser.add_argument(
        "--enable-flood",
        action="store_true",
        help="Enable log flooding (requires root)"
    )

    parser.add_argument(
        "--rate",
        type=int,
        default=5,
        help=f"Messages per second (max {MAX_RATE})"
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help=f"Flood duration in seconds (max {MAX_DURATION})"
    )

    args = parser.parse_args()

    privileged = is_privileged()

    print(f"[+] Running as {'root' if privileged else 'unprivileged'} user")

    # Log collection
    print("[+] Reading logs...")
    entries = read_logs(args.logs)

    for path, line in entries[:100]:  # Display first 100 entries
        print(f"[{path}] {line}")

    print(f"[+] {len(entries)} total log entries read")

    # Log flooding
    if args.enable_flood:
        if not privileged:
            print("[-] Flooding requires root privileges.")
        else:
            flood_logs(args.rate, args.duration)


if __name__ == "__main__":
    main()
