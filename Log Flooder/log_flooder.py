#!/usr/bin/env python3
# Seonho Park, scp4941@rit.edu

import os, re, sys, json, time, socket, argparse, hashlib, threading, subprocess
from datetime import datetime
from pathlib import Path
from collections import defaultdict
import logging
from logging.handlers import SysLogHandler

# ---------------- CONFIG ----------------

MAX_RATE = 50          # max messages/sec as a DOS safeguard
MAX_DURATION = 300     # seconds; 300s = 5 min cap

DEFAULT_LOGS = [
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/messages"
    "/var/log/secure",
]
STORAGE_DIR = Path("./rt_logs")

# ---------------- ENV ----------------

def is_root():
    return os.geteuid() == 0

def readable_logs(paths):

    readable_files = []
    
    for path in paths:
        # Check if the path points to an actual file
        if not os.path.isfile(path):
            continue
            
        # Check if the file is readable by the current user
        if not os.access(path, os.R_OK):
            continue
            
        readable_files.append(path)
    
    return readable_files

# ---------------- LOG READING ----------------

def read_logs(paths):
    entries = []
    for p in readable_logs(paths):
        try:
            with open(p, errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append((p, line))
        except:
            continue
    return entries

# ---------------- ANALYSIS ----------------

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_RE = re.compile(r"user(?:name)?[=:\s]+([a-zA-Z0-9_@.-]+)", re.I)
FAIL_RE = re.compile(
    r"(failed|failure|invalid|unauthorized|denied|error|refused|rejected)",
    re.I,
)
PORT_RE = re.compile(r"\bport\s+(\d{1,5})\b", re.I)

def analyze(paths, keywords):
    findings = []

    for p, line in read_logs(paths):
        ips = IP_RE.findall(line)
        users = USER_RE.findall(line)
        ports = PORT_RE.findall(line)
        flags = []
        kws = [k for k in keywords if k.lower() in line.lower()]

        if FAIL_RE.search(line):
            flags.append("failure")

        if ips or users or kws or flags:
            findings.append({
                "source": p,
                "line": line,
                "time": datetime.utcnow().isoformat(),
                "ips": ips,
                "users": users,
                "ports": ports,
                "keywords": kws,
                "flags": flags,
                "hash": hashlib.sha256(line.encode()).hexdigest()
            })

    return findings


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


    print(f"[+] Running as {'root' if privileged else 'unprivileged'} user")

    # Log collection
    print("[+] Reading logs...")
    entries = read_logs(args.logs)

    for path, line in entries[:100]:  # Display first 100 entries
        print(f"[{path}] {line}")

    print(f"[+] {len(entries)} total log entries read")

    # Log flooding
    if args.flood:
        if not is_root():
            print("[-] Flooding requires root privileges.")
        else:
            flood_logs(args.rate, args.duration)

if __name__ == "__main__":
    main()
