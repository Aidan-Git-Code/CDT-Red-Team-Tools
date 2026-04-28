#!/usr/bin/env python3
# Seonho Park, scp4941@rit.edu

import os, re, sys, json, time, socket, argparse, hashlib, threading, subprocess, pwd, grp
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
SYSLOG_SOCKET = "/dev/log"

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

def current_user_info() -> dict:
    """
    Return the current process's user/group info via pwd/grp (Linux stdlib).
    """
    uid = os.geteuid()
    gid = os.getegid()
    try:
        uname = pwd.getpwuid(uid).pw_name
    except KeyError:
        uname = str(uid)
    try:
        gname = grp.getgrgid(gid).gr_name
    except KeyError:
        gname = str(gid)
    return {"uid": uid, "gid": gid, "user": uname, "group": gname}

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

    for path, line in read_logs(paths):
        ips = IP_RE.findall(line)
        users = USER_RE.findall(line)
        ports = PORT_RE.findall(line)
        flags = []
        kws = [k for k in keywords if k.lower() in line.lower()]

        if FAIL_RE.search(line):
            flags.append("failure")

        if ips or users or kws or flags:
            findings.append({
                "source": path,
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

# ---------------- STORAGE ----------------

def save_findings(data, folder):
    folder.mkdir(exist_ok=True)
    name = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    file = folder / f"findings_{name}.json"

    with open(file, "w") as f:
        json.dump(data, f, indent=2)

    return file

def load_findings(folder):
    results, seen = [], set()

    if not folder.exists():
        return results

    for f in folder.glob("findings_*.json"):
        try:
            data = json.load(open(f))
            for item in data:
                if item["hash"] not in seen:
                    seen.add(item["hash"])
                    results.append(item)
        except:
            continue

    return results

# ---------------- FLOOD ----------------

def flood_logs(rate, duration):
    rate = min(rate, MAX_RATE)
    duration = min(duration, MAX_DURATION)

    logger = logging.getLogger("flood")
    logger.setLevel(logging.INFO)
    logger.addHandler(SysLogHandler(address=SYSLOG_SOCKET))

    end = time.time() + duration

    print(f"[+] Flooding {rate}/sec for {duration}s")

    while time.time() < end:
        logger.info("test event noise")
        time.sleep(1 / rate)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog = "log_flooder.py",
        description="Log collection and flooding tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="TODO: bleh >w<"
    )
    
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    storage_dir = Path(args.storage_dir)
    ui = current_user_info()

    print(f"[+] log_tool.py | user={ui['user']} uid={ui['uid']} | Linux")

    if args.raw:
        print("[+] Reading raw log entries …")
        entries = read_logs(args.logs)
        for path, line in entries[:100]:
            print(f"  [{path}] {line}")
        print(f"[+] {len(entries)} total raw entries")

    findings = []
    if args.collect:
        print(f"[+] Analysing logs — keywords: {args.keywords}")
        findings = analyze(args.logs, args.keywords)
        print(f"[+] {len(findings)} findings extracted")
        for f in findings[:50]:
            tags    = f["keywords"] + f["flags"]
            svc     = f["service"]
            svc_str = f"{svc[0]}[{svc[1]}]" if svc else "?"
            print(f"  [{f['source']}] {svc_str} [{', '.join(tags) or '—'}] {f['line'][:110]}")


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
