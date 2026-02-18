# CTF Log Manipulation & Intelligence Tool

Author: Seonho Park

Course: CSEC473 - Cyber Defence Techniques

## Overview

This tool is for Red Team, designed to disrupt logs in order to gain time advantages during cyber defense competitions.

Blue Teams rely on logs to detect and investigate intrusions. By harvesting and generating log noise, Red Team pulls ahead with an intelligence difference while also increasing defender workload.

It operates in two modes depending on the level of privilege:

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