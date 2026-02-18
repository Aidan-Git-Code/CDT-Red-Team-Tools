#!/usr/bin/env python3
"""
SystemScan.py
Author: William Walker
Purpose: Collect basic system metadata from compromised box

This module can be: Run by itself (prints results to terminal) or Imported by FullInfoScan.py (returns results as a dict)
"""

import platform
import socket
import subprocess
import json
import os


"""
Collect hostname of the system.
Returns the hostname or None on failure.
"""
def get_host():
    try:
        return socket.gethost()
    except Exception:
        return None


"""
Collect OS information using Python's platform module.
Returns a dict of system, release, version, machine, and processor.
"""
def get_os():
    try:
        return {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor()
        }
    except Exception:
        return None


"""
Collect kernel version using uname -r.
Returns a string or None on failure.
"""
def get_kernel():
    try:
        result = subprocess.check_output(["uname", "-r"], text=True).strip()
        return result
    except Exception:
        return None


"""
Collect system uptime in seconds from /proc/uptime.
Returns a float or None on failure.
"""
def get_uptime():
    try:
        with open("/proc/uptime", "r") as f:
            uptime_seconds = float(f.read().split()[0])
            return uptime_seconds
    except Exception:
        return None


"""
Collect list of system users from /etc/passwd.
Returns a list of usernames or None on failure.
"""
def get_users():
    try:
        with open("/etc/passwd", "r") as f:
            users = [line.split(":")[0] for line in f.readlines()]
            return users
    except Exception:
        return None


"""
Collect network interface information using `ip -o addr`.
Returns a list of interface lines or None on failure.
"""
def get_interfaces():
    try:
        result = subprocess.check_output(["ip", "-o", "addr"], text=True)
        return result.splitlines()
    except Exception:
        return None


"""
Main function used by FullInfoScan.py
Returns a dict of collected system information.
"""
def run():

    data = {
        "host": get_host(),
        "os": get_os(),
        "kernel": get_kernel(),
        "uptime_seconds": get_uptime(),
        "users": get_users(),
        "interfaces": get_interfaces()
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