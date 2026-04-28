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

# ---------------------------------------------------------------------------
# Structured local storage
# ---------------------------------------------------------------------------

def save_findings(findings: list[dict], storage_dir: Path) -> Path:
    """
    Persist findings to a timestamped JSON file in *storage_dir*.

    The directory is created if it does not already exist.
    Returns the path of the written file.
    """
    storage_dir.mkdir(parents=True, exist_ok=True)
    ts      = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outfile = storage_dir / f"findings_{ts}.json"

    with open(outfile, "w") as fh:
        json.dump(
            {
                "generated":  ts,
                "total":      len(findings),
                "findings":   findings,
            },
            fh,
            indent=2,
        )

    return outfile


def load_findings(storage_dir: Path) -> list[dict]:
    """
    Load and merge all previously saved finding files from *storage_dir*.

    Duplicates are removed based on the SHA-256 hash of each log line.
    """
    if not storage_dir.exists():
        return []

    seen:   set[str]   = set()
    merged: list[dict] = []

    for jf in sorted(storage_dir.glob("findings_*.json")):
        try:
            with open(jf) as fh:
                data = json.load(fh)
            for entry in data.get("findings", []):
                h = entry.get("hash", "")
                if h and h not in seen:
                    seen.add(h)
                    merged.append(entry)
        except (json.JSONDecodeError, KeyError):
            continue

    return merged

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
