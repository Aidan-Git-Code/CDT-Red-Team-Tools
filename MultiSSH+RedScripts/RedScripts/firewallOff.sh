#!/bin/bash
# Blue team indicators: ufw/iptables disabled, rules flushed

# Disable UFW (Ubuntu/Debian)
if command -v ufw &>/dev/null; then
    ufw disable
fi

# Disable firewalld (RHEL/CentOS)
if command -v firewall-cmd &>/dev/null; then
    systemctl stop firewalld
    systemctl disable firewalld
fi

# Flush all iptables rules
iptables -F          # Flush all chains
iptables -X          # Delete user chains
iptables -t nat -F
iptables -t mangle -F
iptables -P INPUT ACCEPT    # Set default policies to ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

echo "[RED TEAM] iptables flushed and set to ACCEPT all"