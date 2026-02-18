#!/usr/bin/env python3
# Seonho Park, scp4941@rit.edu

import os
import time
import argparse
import logging
from logging.handlers import SysLogHandler
from datetime import datetime

# Configurations
MAX_RATE = 50          # max messages/sec (DOS safeguard)
MAX_DURATION = 300     # seconds (5 min cap)
DEFAULT_LOGS = [
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/messages"
]

CTF_TAG = "CTF_SIM"

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
    formatter = logging.Formatter(f"{CTF_TAG}: %(message)s")
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
