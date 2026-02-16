#!/usr/bin/env python3
"""
LogScan.py
Author: William Walker
Purpose: Collect log file artifacts from a compromised Linux box.

This module collects: Common system logs , Authentication logs , Cron logs ,Package manager logs ,Kernel and boot logs

Can be run by itself or imported by FullInfoScan.py
"""

import os
import json

try:
    from .utils import read_file
except ImportError:
    from utils import read_file


"""
Return a list of interesting log file paths.
Only includes files that exist.
"""
def get_log_paths():

    log_paths = [
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/auth.log",
        "/var/log/kern.log",
        "/var/log/secure",
        "/var/log/cron",
        "/var/log/cron.log",
        "/var/log/dmesg",
        "/var/log/apt/history.log",
    ]

    existing = []

    for p in log_paths:
        try:
            if os.path.exists(p):
                existing.append(p)
        except Exception:
            pass

    return existing


"""
Read all logs that exist.
Readable logs are split into lines for clean JSON formatting.
"""
def collect_logs():

    files = get_log_paths()
    collected = {}

    for path in files:
        raw = read_file(path)

        if isinstance(raw, str):
            collected[path] = raw.splitlines()
        else:
            collected[path] = raw  

    return collected


"""
Main function used by FullInfoScan.py
Returns a dict of log file data.
"""
def run():

    data = {
        "log_files": collect_logs()
    }

    return data


"""
Prints results to terminal.
"""
def alone():
    data = run()
    print(json.dumps(data, indent=4))


if __name__ == "__main__":
    alone()