#!/usr/bin/env python3
"""
ProcessScan.py
Author: William Walker
Purpose: Collect process-related artifacts from a compromised Linux box.

This module collects: Running processes (ps aux) , Per process command lines , Per process environment variables 

Can be run by itself or imported by FullInfoScan.py
"""

import os
import json
import subprocess

try:
    from .utils import read_file
except ImportError:
    from utils import read_file


"""
Collect a list of running processes using ps aux.
Returns a list of processes.
"""
def get_running_processes():
    try:

        result = subprocess.check_output(["ps", "aux"], text=True)
        return result.splitlines()
    
    except Exception:
        return None


"""
Collect command line for a given PID.
Returns a string or an error. 
"""
def get_cmdline(pid):

    path = f"/proc/{pid}/cmdline"
    raw = read_file(path)

    if isinstance(raw, str):

        return raw.replace("\x00", " ").strip()

    return raw 


"""
Collect environ vars for a given PID.
Returns a dict of key and value pairs or an error.
"""
def get_environ(pid):

    path = f"/proc/{pid}/environ"
    raw = read_file(path)

    if isinstance(raw, str):
        env_pairs = raw.split("\x00")
        env_dict = {}

        for pair in env_pairs:
            if "=" in pair:
                key, value = pair.split("=", 1)
                env_dict[key] = value

        return env_dict

    return raw  


"""
Collect info for each PID in /proc.
Returns a dict keyed by PID.
"""
def collect_process_details():

    processes = {}

    try:
        for pid in os.listdir("/proc"):
            
            if pid.isdigit():
                processes[pid] = {
                    "cmdline": get_cmdline(pid),
                    "environ": get_environ(pid)
                }

    except Exception:
        return None

    return processes


"""
Main function used by FullInfoScan.py
Returns a dict of process info
"""
def run():

    data = {
        "running_processes": get_running_processes(),
        "process_details": collect_process_details()
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