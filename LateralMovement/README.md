# Enhanced Lateral Movement Tool

A comprehensive Python-based penetration testing tool for automated lateral movement in Active Directory environments. Built on the Impacket framework with enhanced features for CTF competitions and authorized security assessments.

## ⚠️ Legal Notice

**THIS TOOL IS FOR AUTHORIZED USE ONLY**

This tool is designed exclusively for:
- Authorized penetration testing with written permission
- Sanctioned CTF competitions and security challenges
- Educational lab environments

**Unauthorized access to computer systems is illegal.** Users are solely responsible for ensuring they have proper authorization before using this tool.

## 🚀 Features

### Core Capabilities
- **Automated Lateral Movement**: Recursive pivoting with configurable depth
- **Credential Management**: Advanced credential storage and validation tracking
- **Pass-the-Hash Support**: NTLM authentication without plaintext passwords
- **Network Discovery**: Multi-threaded host and DC identification
- **Secret Dumping**: SAM and LSA secrets extraction
- **Credential Spraying**: Efficient credential testing across multiple hosts
- **Comprehensive Reporting**: JSON-formatted reports with full attack chain documentation

### Enhanced Functionality Beyond Base Impacket
1. **Automated Pivot Engine**: Orchestrates entire attack chains automatically
2. **Credential Pool Management**: Tracks and reuses discovered credentials
3. **Domain Controller Prioritization**: Automatically identifies and targets high-value systems
4. **Multi-threaded Operations**: Fast network scanning and credential spraying
5. **Logged-on User Enumeration**: Identifies high-value targets via active sessions
6. **Share Enumeration**: Discovers accessible network shares
7. **Comprehensive Logging**: Detailed activity logs for documentation

## 📋 Prerequisites

- **Python 3.7+**
- **Impacket library** (automatically installed via setup)
- **Linux/macOS** (tested on Kali, Ubuntu, Parrot)
- **Network access** to target systems
- **Valid credentials** for at least one domain/local account

## 🔧 Installation

### Quick Install

```bash
# Clone or download the repository
cd lateral_movement_tool

# Run the automated setup script
./setup.sh

# Or manual installation:
pip3 install -r requirements.txt
chmod +x lateral_movement_tool.py
```

### Verify Installation

```bash
python3 lateral_movement_tool.py --help
```

## 📖 Quick Start

### Basic Authentication Test
```bash
./lateral_movement_tool.py \
    -t 192.168.1.100 \
    -u administrator \
    -p "Password123!" \
    -d CORP \
    -v
```

### Automated Lateral Movement
```bash
./lateral_movement_tool.py \
    -t 192.168.1.100 \
    -u administrator \
    -p "Password123!" \
    -d CORP \
    --subnet 192.168.1.0/24 \
    --auto-pivot \
    --max-depth 3 \
    -o report.json
```

### Pass-the-Hash
```bash
./lateral_movement_tool.py \
    -t 192.168.1.100 \
    -u administrator \
    -H ":31d6cfe0d16ae931b73c59d7e0c089c0" \
    -d CORP
```

### Credential Spraying
```bash
./lateral_movement_tool.py \
    --targets targets.txt \
    --creds-file creds.json \
    --spray
```

## 📚 Documentation

- **[Full Documentation](DOCUMENTATION.md)**: Comprehensive guide covering all features
- **[Quick Reference](QUICK_REFERENCE.md)**: Command cheat sheet and common workflows
- **Example Files**: Pre-configured examples in the repository

## 🎯 Competition Workflow

### Phase 1: Initial Foothold
```bash
# Test your initial credentials
./lateral_movement_tool.py -t <TARGET> -u <USER> -p <PASS> -d <DOMAIN> -v
```

### Phase 2: Automated Expansion
```bash
# Launch automated lateral movement
./lateral_movement_tool.py \
    -t <TARGET> \
    -u <USER> \
    -p <PASS> \
    -d <DOMAIN> \
    --subnet <NETWORK>/24 \
    --auto-pivot \
    --max-depth 3 \
    -o phase2_report.json
```

### Phase 3: Credential Harvesting
```bash
# Discovered credentials are saved to:
cat discovered_creds.json

# Use them for further attacks
./lateral_movement_tool.py --spray --creds-file discovered_creds.json --targets targets.txt
```

## 🛠️ Technical Details

### How It Works

1. **Initial Authentication**: Establishes SMB connection with provided credentials
2. **Enumeration**: Discovers shares, logged-on users, and system information
3. **Credential Harvesting**: Dumps SAM/LSA secrets using RPC calls
4. **Credential Spraying**: Tests all credentials against all discovered hosts
5. **Recursive Pivoting**: Repeats process on newly compromised systems
6. **Reporting**: Generates comprehensive JSON reports

### Lateral Movement Techniques Used

- **Pass-the-Hash (PtH)**: NTLM authentication without password
- **Credential Spraying**: One password across many accounts
- **SMB Authentication**: Direct SMB login testing
- **RPC Secret Dumping**: SAM/LSA extraction via remote registry
- **Share Enumeration**: Network share discovery
- **User Enumeration**: Active session identification

### Protocols and Ports

- **TCP 445**: SMB (primary)
- **TCP 139**: NetBIOS/SMB
- **TCP 135**: RPC Endpoint Mapper
- **TCP 389**: LDAP (DC identification)

## 🔍 Example Output

```
╔═══════════════════════════════════════════════════════════╗
║  Enhanced Lateral Movement Tool v1.0                      ║
║  Based on Impacket Framework                              ║
║  For Authorized Penetration Testing Only                  ║
╚═══════════════════════════════════════════════════════════╝

[*] Starting automated lateral movement...
[*] Scanning 192.168.1.0/24 for active hosts...
[+] Found active host: 192.168.1.100
[+] Found active host: 192.168.1.101
[+] Potential DC found: 192.168.1.10
[*] Discovered 15 potential targets
[*] === Pivot Level 1 ===
[*] Spraying 1 credentials across 15 targets
[+] Valid credentials on 192.168.1.100: CORP\administrator
[+] Share found on 192.168.1.100: ADMIN$
[+] Logged-on user on 192.168.1.100: john.doe
[+] SAM secrets dumped from 192.168.1.100
[+] Added credential: CORP\john.doe
[*] === Pivot Level 2 ===
[+] Compromised 3 new hosts, pivoting deeper...
[+] Report generated: pivot_report.json
[+] Compromised 5 hosts
[+] Discovered 8 credentials
```

## 📊 Output Files

| File | Description |
|------|-------------|
| `pivot_report.json` | Main report with compromised hosts and pivot chain |
| `discovered_creds.json` | All harvested credentials |
| `spray_results.json` | Credential spraying results |

## 🔐 Security Considerations

### Operational Security (OPSEC)

This tool generates **significant network noise**:
- Multiple SMB connections
- RPC calls to remote systems
- Authentication attempts (may trigger alerts)
- Windows Event Logs on target systems

### Detection Indicators

Defenders can detect this tool through:
- Event ID 4625 (Failed logons)
- Event ID 4624 (Successful logons from unusual sources)
- Multiple SMB connections from single IP
- SAMR/LSA RPC queries
- Share enumeration activity

### Best Practices

✅ **DO:**
- Get written authorization before testing
- Stay within defined scope
- Document all activities
- Use strong operational security
- Report findings professionally

❌ **DON'T:**
- Use against systems you don't own/have permission to test
- Exceed defined scope or testing windows
- Leave backdoors or persistence mechanisms
- Cause denial of service
- Access or modify data without authorization

## 🐛 Troubleshooting

### Common Issues

**Connection Refused**
```bash
# Check target is up and SMB is accessible
nmap -p445 <TARGET>
```

**Authentication Failed**
```bash
# Verify credentials manually
smbclient -L //<TARGET> -U '<DOMAIN>\<USER>%<PASS>'
```

**Import Errors**
```bash
# Reinstall impacket
pip3 install --upgrade impacket
```

See [DOCUMENTATION.md](DOCUMENTATION.md) for detailed troubleshooting.

## 🤝 Contributing

This tool is designed for educational and competition use. If you have improvements:

1. Test thoroughly in lab environment
2. Document changes clearly
3. Ensure code follows existing patterns
4. Add examples for new features

## 📄 License

**Educational/Competition Use Only**

This tool is provided for educational purposes and authorized security testing only. The authors are not responsible for misuse or damage caused by this tool.

## 🙏 Acknowledgments

- **Impacket Project**: Core SMB/RPC functionality
- **SecureAuth Corporation**: Impacket development
- **Security Research Community**: Testing and feedback

## 📞 Support

For issues or questions:
1. Check [DOCUMENTATION.md](DOCUMENTATION.md)
2. Review [QUICK_REFERENCE.md](QUICK_REFERENCE.md)
3. Verify your Impacket installation
4. Test in isolated lab environment first

## ⚖️ Disclaimer

This tool is provided "as is" without warranty of any kind. Users must ensure compliance with all applicable laws and regulations. The creators and contributors assume no liability for misuse or damage caused by this tool.

**Remember**: With great power comes great responsibility. Use this tool ethically and legally.

---

**Version**: 1.0  
**Last Updated**: 2024  
**Requires**: Python 3.7+, Impacket 0.11.0+
