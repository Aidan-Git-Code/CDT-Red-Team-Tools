#!/usr/bin/env python3
"""
JSONScan.py
Author: William Walker
Purpose: Analyze FullInfoScan JSON output and extract any secrets or creds found!

This script:
1. Loads a FullInfoScan JSON file
2. Searches for secrets, credentials, tokens, keys, and misconfigurations
3. Produces a json of findings

"""

import json
import re
import sys
import os


""" KEYWORDS TO SEARCH FOR """
KEYWORDS = ["password", 
"passwd",
"pwd",
"token", 
"secret", 
"apikey", 
"api_key",
"bearer", 
"auth", 
"authorization",
"key=", 
"private", 
"ssh-rsa", 
"ssh-ed25519",
"passphrase",
"login",
"user=",
"session",
"sessionid",
"cookie",
"db_pass",
"db_password",
"db_user",
"connection_string",
"config",
"credential",
"jwt",
"csrf",]


""" load the json output """
def load_scan(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"ERROR: Couldnt load scan file: {e}")
        sys.exit(1)


""" load config.json for naming """
def load_config():
    try:
        with open("config.json", "r") as f:
            return json.load(f)
        

    except Exception as e:
        print(f"ERROR: Could not load config, using DEFAULTS: {e}")
        return {"output_filename": "full_scan_output","anaylze_filename": "output_scanned","output_number": 1,"anaylze_number": 1,"always_print": False}


""" save updated config.json """
def save_config(cfg):
    try:

        with open("config.json", "w") as f:
            json.dump(cfg, f, indent=4)

    except Exception as e:
        print(f"ERROR: Could not update config.json: {e}")


""" Search a string or list for keywords. """
def search_value(value, findings, location):

    if isinstance(value, str):
        lower = value.lower()
        for kw in KEYWORDS:
            if kw in lower:
                findings.append({"keyword": kw,"location": location,"snippet": value[:200]})

    elif isinstance(value, list):
        for line in value:
            search_value(line, findings, location)

    elif isinstance(value, dict):
        for k, v in value.items():
            search_value(v, findings, f"{location}.{k}")


def analyze(scan):
    findings = []

    for section, content in scan.items():
        if section.startswith("_"):
            continue

        search_value(content, findings, section)

    return findings


def save_report(findings, output_path):
    try:

        with open(output_path, "w") as f:
            json.dump(findings, f, indent=4)

        print(f"Findings saved to {output_path}")

    except Exception as e:
        print(f"ERROR saving report: {e}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 JSONScan.py <scan_output.json>")
        sys.exit(1)

    scan_path = sys.argv[1]
    scan = load_scan(scan_path)

    cfg = load_config()

    print("Analyzing Output JSON...")
    findings = analyze(scan)


    filename = cfg.get("anaylze_filename", "output_scanned")
    num = cfg.get("anaylze_number", 1)

    output_file = f"{filename}_{num}.json"

    save_report(findings, output_file)

    cfg["anaylze_number"] = num + 1
    save_config(cfg)

    print(f"Total findings: {len(findings)}")


if __name__ == "__main__":
    main()