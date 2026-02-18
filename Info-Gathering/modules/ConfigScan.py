#!/usr/bin/env python3
"""
ConfigScan.py
Author: William Walker
Purpose: Collect configuration file artifacts from a compromised Linux box.

This module collects: Common system-wide config files, Common user-level config files ,Any readable config files in /etc

Can be run by itself or imported by FullInfoScan.py
"""

import os
import json

try:
    from .utils import read_file, get_user_home
except ImportError:
    from utils import read_file, get_user_home


"""
Collect a list of interesting config file paths.
Returns a list of file paths that exist.
"""
def get_config_file_paths():

    home = get_user_home()
    if not home:
        home = "/home"

    common_paths = [
        "/etc/ssh/sshd_config",
        "/etc/ssh/ssh_config",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/environment",
        "/etc/fstab",
        "/etc/crontab",
        "/etc/cron.allow",
        "/etc/cron.deny",
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/network/interfaces",
        "/etc/netplan/01-netcfg.yaml",
        "/etc/netplan/50-cloud-init.yaml",
        "/etc/apt/sources.list",
        "/etc/apt/sources.list.d/",
        "/etc/systemd/system/",
        "/etc/systemd/user/",
        "/etc/default/",
        os.path.join(home, ".bashrc"),
        os.path.join(home, ".bash_profile"),
        os.path.join(home, ".profile"),
        os.path.join(home, ".ssh/authorized_keys"),
        os.path.join(home, ".ssh/known_hosts"),
        os.path.join(home, ".ssh/config"),
        os.path.join(home, ".gitconfig"),
    ]

    existing = []

    for p in common_paths:
        try:

            if os.path.exists(p):
                existing.append(p)

        except Exception:
            pass    

    return existing


"""
Read all config files that exist.
Returns a dict: with file path and the contents inside that file 
"""
def collect_config_files():

    files = get_config_file_paths()
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
Returns a dict of config file data.
"""
def run():

    data = {
        "config_files": collect_config_files()
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