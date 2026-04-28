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
| Flood privilege | `root` required for `--flood` only |
| All other features | Unprivileged user |

---


Unprivileged Mode:
- Reads and prints accessible system logs.

Privileged Mode:
- Generates synthetic log entries through syslog.
- Creates noise without damaging system stability.

Category: Destructive/Distracting Tool (Category 3)

## Technical Approach

- Python-based implementation
- Log flooding and log harvesting functions
- Rate-limited log generation safeguards

## Requirements

OS: Linux (systemd or rsyslog environments)

Python Version: Python 3.8+

Privilege: Root not required, but variable functionality

## Installation

```bash
# Clone or extract the repository
cd redteam-tool

# Verify script runs
python3 log_flooder.py --help
```

## Expected Output:
```bash
usage: log_flooder.py [-h] [--logs [LOGS ...]] [--enable-flood] [--rate RATE] [--duration DURATION]

Log collection and flood tool

options:
  -h, --help           show this help message and exit
  --logs [LOGS ...]    Log files to read
  --enable-flood       Enable log flooding (requires root)
  --rate RATE          Messages per second (max 50)
  --duration DURATION  Flood duration in seconds (max 300)
```

## Operational Notes
Given that there is no direct file modification, and is rate limited to prevent system damage, this tool can be deployed during competition during intelligence gathering to understand Blue Team infrastructure, services, and other activities. 

Due to its nature as a log flooder, there will be increase in log volume which may raise suspicisions and be investigated to lead to repeated structured events. 

## Cleanup
Filter entries using:
```Bash
grep -v CTF_SIM /var/log/syslog
```

# Limitations
- Requires readable log access
- Does not bypass centralized logging
- Does not write logs to files
- Limited pathing and log parsing, only following hardcoded paths
- Lack of security features to protect sensitive logs

## Future implementation
- Persistent logging for later analysis
- Implement credential harvesting
- Log filtering to specify log types, keywords, and date ranges for better research
- More configurations to flooding
- Navigate system files to autoomate finding logs 

# Credits & References
## Logging and Syslog Handling:
- Python Logging Documentation: https://docs.python.org/3/library/logging.html
- SysLogHandler Documentation: https://docs.python.org/3/library/logging.handlers.html#sysloghandler

## Datetime Handling:
- Python Datetime Documentation: https://docs.python.org/3/library/datetime.html

## OS Operations:
- Python OS Module Documentation: https://docs.python.org/3/library/os.html