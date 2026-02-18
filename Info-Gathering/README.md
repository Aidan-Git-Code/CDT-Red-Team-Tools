# FullInfoScan and JSONscan: Linux Information Gathering

## Overview
FullInfoScan is a modular Linux information gathering framework designed for Red Team Recon, to learn as much as we can in a fast ammount of time. Its purpose is to quickly collect and consolidate secrets and important artifacts from a compromised Linux host, and optionally after analyze that report with JSONScan for potential secrets, credentials, and misconfigurations. FullInfoScan generates a unified, comprehensive JSON report that centralizes system, process, network, log, and configuration data. It automatically performs wide‑scope secret and configuration harvesting, giving you a single place to review all critical information for Red Team Recon. 

This tool fits **Category 5: Information Gathering / Credential & Secret Collection**.  
It does not exploit systems or modify them; instead, it gathers the exact artifacts where credentials and sensitive data commonly reside. With  the included JSONScan.py module the tool can pick out potential important artifacts. 

FullInfoScan is built from multiple small, focused modules in modules/:
- System metadata collection  
- SSH key and config harvesting  
- Reconnaissance (services, ports, packages)  
- Process inspection (cmdline + environment variables)  
- Log collection  
- Environment variable collection  
- Config file harvesting  
- Bash history extraction  

JSONScan processes the JSON produced by FullInfoScan and performs targeted keyword‑based analysis, essentially acting as an automated grep engine for secrets, credentials, and other sensitive indicators.

Each module outputs structured JSON data. FullInfoScan aggregates these results into a unified report, and JSONScan performs deeper inspection to identify secrets, credentials, misconfigurations, and other high‑value indicators

## Requirements & Dependencies
Target OS:
- Linux (tested on Ubuntu 22.04)

Dependencies:
- Python 3.x (no external libraries required)
- Access to standard Linux utilities:
  - systemctl
  - ss
  - dpkg
  - ip
  - uname

Privileges:
- User‑level access works for most modules
- Some files require elevated privileges to read. If the tool cannot access them, the JSON output will clearly indicate that the file was unreadable rather than failing silently.

Prerequisites:
- Python 3 installed
- Ability to transfer the tool to the target system

## Installation
1. Transfer the repository to the target Linux machine.
2. Ensure Python 3 is available.
3. Review config.json to confirm naming and incrementor preferences.
4. Run FullInfoScan.py to generate a full system report, Cd into modules to run a Single scan by itself. 
5. Optionally, Run JSONScan.py on the generated JSON for easier secret finding.

Verification:
- A JSON file named according to config.json (e.g., full_scan_output_1.json) should appear in the working directory.
- Terminal should print that a output file was made to confirm the run
- Config.json incremented

## Usage

### Basic Usage
Run the full scanner:
```bash
python3 FullInfoScan.py
```

This will:
- Execute all modules in modules/
- Aggregate results
- Produce <CONFIG_CHOSEN_NAME>_<n>.json

Even though JSONScan is available, it’s important to note that running it is completely optional. FullInfoScan’s output alone already contains a massive amount of valuable information. Secrets, configs, SSH keys, logs, environment variables, process details, and more. A knowledgeable user can easily navigate the JSON using grep or even just Ctrl‑F to quickly locate interesting artifacts. The output is neatly organized by module (e.g., SystemScanResults, SSHScanResults, ProcessScanResults), making it straightforward to jump directly to the section you want to inspect.

### Analyzing Output
After generating a scan file:
```bash
python3 JSONScan.py <Path to FullInfoScan Output JSON>.json
```

This will:
- Search for secrets, credentials, tokens, and sensitive strings
- Produce <CONFIG_CHOSEN_NAME>_<n>.json


### Running Individual Modules
Each scan module can also be executed on its own. This is useful for quick checks, debugging, or when you only need a specific type of information.

To run a module individually:
1. cd into the modules/ directory
2. Run the desired scan file with Python (e.g., python3 SystemScan.py)

Each module prints its results directly to the terminal when ran by itself.

### Configuration File Format (config.json)
{
    "output_filename": "full_scan_output",
    "anaylze_filename": "output_scanned",
    "output_number": 1,
    "anaylze_number": 1,
    "always_print": false
}

Fields:
- output_filename: Base name for scan output files
- anaylze_filename: Base name for analyzer output files
- output_number: Auto‑incrementing scan counter
- anaylze_number: Auto‑incrementing analyzer counter
- always_print: If true, prints full JSON to terminal aswell as making the report

### Example Output
- System metadata (kernel, uptime, users) (SystemScanResults)
- SSH private keys, config, and known_hosts entries (SSHScanResults)
- Running services, open ports, installed packages (ReconScanResults)
- Process command lines and environment variables (ProcessScanResults)
- Config files from /etc and user home directories (ConfigScanResults)
- Log files such as auth.log, syslog, and cron logs (LogScanResults)
- Bash history (BashScanResults)
- Environment variables for the current process (EnvironScanResults)

## Operational Notes

### Competition Use
FullInfoScan is ideal for:
- Quickly understanding a newly compromised machine
- Identifying pivot opportunities
- Extracting SSH keys for lateral movement
- Finding credentials in config files, logs, and environment variables
- Reviewing user activity via bash history
- Detecting misconfigurations that enable privilege escalation

### OpSec Considerations
- The tool only reads files; it does not modify the system.
- It may create:
  - JSON output files
  - Updates to config.json
- It does NOT write logs or spawn suspicious network traffic.
- Running JSONScan.py does not touch the target system at all.

### Detection Risks
This tool is fairly easy to spot if a defender is actively watching the system. It runs a large number of commands and Python modules in rapid succession, which creates a noticeable burst of activity. However, this also works in Red Team’s favor: the volume of commands and the speed at which they execute can overwhelm logs and make it harder to pinpoint exactly what the operator was doing. The tool completes extremely quickly, generating a dense cluster of system queries that blend together in logs.

Mitigation:
- Delete the tool directory and output files once finished
- Move JSONS to other directories/boxes

### Cleanup
- Delete the tool directory
- Delete generated JSON files
- Clear shell history if possible. 

## Limitations
- Cannot read files without permissions
- Does not exploit or escalate privileges
- Does not parse binary logs
- Output can be SUPER large on systems with many processes or logs
- JSONScan uses keyword matching for simple scanning but not complex. 

## Future Improvements
- Add regex‑based secret detection
- Add severity scoring for findings
- Add optional stealth mode (obfuscated execution)

## Credits & References
Author:
- William Walker

Testing & Feedback:
- Red Team members during development

References Consulted (Module‑Specific):

### SystemScan
- Python `platform` module documentation  
- Linux manual pages: `uname(1)`, `/proc/uptime`, `/etc/passwd`  
- General Linux system enumeration practices

### SSHScan
- OpenSSH documentation (ssh_config, sshd_config, key formats)  
- Linux filesystem standards for ~/.ssh directory structure  
- Common Red Team SSH key harvesting techniques

### ReconScan
- Linux manual pages: `systemctl(1)`, `ss(8)`, `dpkg(1)`  
- Standard Linux service enumeration and package auditing methods

### ProcessScan
- Linux manual pages: `ps(1)`, `/proc/<pid>/cmdline`, `/proc/<pid>/environ`  
- Python `os` and `subprocess` documentation

### LogScan
- Linux logging structure: `/var/log/auth.log`, `/var/log/syslog`, `/var/log/cron`  
- Syslog format references  
- Standard incident response log review techniques

### EnvironScan
- Python `os.environ` documentation  
- Linux environment variable behavior and inheritance  
- Common credential leakage patterns in environment variables

### ConfigScan
- Linux configuration file locations: `/etc/`, `/home/*/.config/`  
- FHS (Filesystem Hierarchy Standard)  
- Red Team config‑file credential discovery techniques

### BashScan
- Bash documentation for `.bash_history`  
- Linux shell behavior and history logging  
- Red Team user‑activity enumeration practices

### FullInfoScan & JSONScan (Aggregation + Analysis)
- Python `json` module documentation  
- Keyword‑based secret detection patterns  

General References:
- Linux man pages for systemctl, ss, dpkg, ip, uname  
- Python standard library documentation  
- MITRE ATT&CK techniques related to discovery (T1082, T1083, T1087, T1057, T1005)
