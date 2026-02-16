#!/bin/bash

# Enhanced Lateral Movement Tool - Setup Script
# This script automates the installation and configuration process

# Author: Andrew Xie
# Date: 02/13/2026

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Banner
echo -e "${GREEN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║  Enhanced Lateral Movement Tool - Setup Script           ║
║  Installing dependencies and configuring environment      ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root (optional, but helpful for some operations)
if [ "$EUID" -eq 0 ]; then 
    echo -e "${YELLOW}[!] Running as root. This is not required but may help with some operations.${NC}"
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check Python 3
echo -e "${GREEN}[*] Checking Python installation...${NC}"
if command_exists python3; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}[+] Python 3 found: $PYTHON_VERSION${NC}"
else
    echo -e "${RED}[-] Python 3 not found. Please install Python 3.7 or higher.${NC}"
    exit 1
fi

# Check pip3
echo -e "${GREEN}[*] Checking pip3 installation...${NC}"
if command_exists pip3; then
    echo -e "${GREEN}[+] pip3 found${NC}"
else
    echo -e "${YELLOW}[!] pip3 not found. Attempting to install...${NC}"
    if command_exists apt-get; then
        sudo apt-get update
        sudo apt-get install -y python3-pip
    elif command_exists yum; then
        sudo yum install -y python3-pip
    else
        echo -e "${RED}[-] Could not install pip3. Please install manually.${NC}"
        exit 1
    fi
fi

# Create virtual environment (optional but recommended)
echo -e "${GREEN}[*] Creating virtual environment...${NC}"
read -p "Create a virtual environment? (recommended) [Y/n]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
    python3 -m venv lateral_movement_env
    source lateral_movement_env/bin/activate
    echo -e "${GREEN}[+] Virtual environment created and activated${NC}"
    echo -e "${YELLOW}[!] Remember to activate it before using the tool: source lateral_movement_env/bin/activate${NC}"
fi

# Install Impacket
echo -e "${GREEN}[*] Installing Impacket...${NC}"
read -p "Install from PyPI (stable) or GitHub (latest)? [P/g]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Gg]$ ]]; then
    echo -e "${GREEN}[*] Installing from GitHub (latest development version)...${NC}"
    
    # Check if git is installed
    if ! command_exists git; then
        echo -e "${YELLOW}[!] Git not found. Installing...${NC}"
        if command_exists apt-get; then
            sudo apt-get install -y git
        elif command_exists yum; then
            sudo yum install -y git
        fi
    fi
    
    # Clone and install
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    git clone https://github.com/fortra/impacket.git
    cd impacket
    pip3 install .
    cd -
    rm -rf "$TEMP_DIR"
else
    echo -e "${GREEN}[*] Installing from PyPI (stable version)...${NC}"
    pip3 install impacket
fi

# Verify Impacket installation
echo -e "${GREEN}[*] Verifying Impacket installation...${NC}"
if python3 -c "import impacket" 2>/dev/null; then
    IMPACKET_VERSION=$(python3 -c "import impacket; print(impacket.__version__)" 2>/dev/null || echo "unknown")
    echo -e "${GREEN}[+] Impacket successfully installed (version: $IMPACKET_VERSION)${NC}"
else
    echo -e "${RED}[-] Impacket installation verification failed${NC}"
    exit 1
fi

# Install additional useful tools
echo -e "${GREEN}[*] Installing additional dependencies...${NC}"
pip3 install colorama  # For better terminal colors (optional)

# Make the main script executable
echo -e "${GREEN}[*] Making lateral_movement_tool.py executable...${NC}"
if [ -f "lateral_movement_tool.py" ]; then
    chmod +x lateral_movement_tool.py
    echo -e "${GREEN}[+] Script is now executable${NC}"
else
    echo -e "${YELLOW}[!] lateral_movement_tool.py not found in current directory${NC}"
fi

# Create example files
echo -e "${GREEN}[*] Creating example configuration files...${NC}"

# Example credentials file
cat > example_creds.json << 'EOF'
[
  {
    "username": "administrator",
    "password": "Password123!",
    "domain": "CORP"
  },
  {
    "username": "admin",
    "ntlm_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
    "domain": "CORP"
  }
]
EOF
echo -e "${GREEN}[+] Created example_creds.json${NC}"

# Example targets file
cat > example_targets.txt << 'EOF'
192.168.1.100
192.168.1.101
192.168.1.102
EOF
echo -e "${GREEN}[+] Created example_targets.txt${NC}"

# Create a sample competition script
cat > competition_script.sh << 'EOF'
#!/bin/bash

# Competition Quick Start Script
# Edit these variables with your initial credentials

TARGET="192.168.1.100"
USERNAME="administrator"
PASSWORD="Password123!"
DOMAIN="CORP"
SUBNET="192.168.1.0/24"

echo "[*] Starting automated lateral movement..."
python3 lateral_movement_tool.py \
    -t "$TARGET" \
    -u "$USERNAME" \
    -p "$PASSWORD" \
    -d "$DOMAIN" \
    --subnet "$SUBNET" \
    --auto-pivot \
    --max-depth 3 \
    -v \
    -o competition_report.json \
    2>&1 | tee competition.log

echo "[+] Attack complete. Check competition_report.json and discovered_creds.json"
EOF
chmod +x competition_script.sh
echo -e "${GREEN}[+] Created competition_script.sh${NC}"

# Test the installation
echo -e "${GREEN}[*] Testing installation...${NC}"
if python3 lateral_movement_tool.py --help >/dev/null 2>&1; then
    echo -e "${GREEN}[+] Tool is working correctly!${NC}"
else
    echo -e "${YELLOW}[!] Tool test failed. Manual verification may be needed.${NC}"
fi

# Check for optional tools
echo -e "${GREEN}[*] Checking for optional tools...${NC}"

if command_exists nmap; then
    echo -e "${GREEN}[+] nmap found (useful for reconnaissance)${NC}"
else
    echo -e "${YELLOW}[!] nmap not found (optional but recommended)${NC}"
    echo -e "    Install with: sudo apt-get install nmap (Debian/Ubuntu)"
fi

if command_exists crackmapexec; then
    echo -e "${GREEN}[+] crackmapexec found (complementary tool)${NC}"
else
    echo -e "${YELLOW}[!] crackmapexec not found (optional)${NC}"
fi

# Final summary
echo -e "${GREEN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║  Setup Complete!                                          ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${GREEN}Next steps:${NC}"
echo -e "  1. Review the DOCUMENTATION.md for detailed usage"
echo -e "  2. Check QUICK_REFERENCE.md for common commands"
echo -e "  3. Test the tool: ./lateral_movement_tool.py --help"
echo -e "  4. Edit competition_script.sh with your credentials"
echo -e ""
echo -e "${GREEN}Example usage:${NC}"
echo -e "  ./lateral_movement_tool.py -t 192.168.1.100 -u admin -p 'Pass123' -d CORP -v"
echo -e ""
echo -e "${YELLOW}Remember:${NC}"
echo -e "  - Only use this tool in authorized environments"
echo -e "  - Always have written permission before testing"
echo -e "  - Document all your activities"
echo -e ""
echo -e "${GREEN}Happy (ethical) hacking!${NC}"
