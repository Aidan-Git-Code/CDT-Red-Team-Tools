#!/bin/bash
# Generates a configurable list of users with known weak passwords
# Blue team indicator: unexpected user accounts, weak passwords


# ── Configuration ────────────────────────────────────────
PASSWORD="redteam123"       # Default password for all generated users
SUDO_GROUP="sudo"           # Change to 'wheel' on RHEL/CentOS
SHELL="/bin/bash"

# ── User list ────────────────────────────────────────────
# Format: "username:group:sudo(yes/no)"
USERS=(
    "rtuser1:redteam:no"
    "rtuser2:redteam:no"
    "rtuser3:redteam:yes"   # this one gets sudo
    "svcaccount:service:no"
    "dbadmin:service:yes"
    "backupuser:service:no"
    "monitoring:service:no"
    "deployuser:redteam:yes"
)

# ── Create groups first ──────────────────────────────────
for group in redteam service; do
    if ! getent group "${group}" &>/dev/null; then
        groupadd "${group}"
        echo "  ✅ Created group: ${group}"
    fi
done

# ── Create users ─────────────────────────────────────────
for entry in "${USERS[@]}"; do
    USERNAME=$(echo "$entry" | cut -d: -f1)
    GROUP=$(echo "$entry"    | cut -d: -f2)
    SUDO=$(echo "$entry"     | cut -d: -f3)

    # Skip if user already exists
    if id "${USERNAME}" &>/dev/null; then
        echo "  ⚠️  User ${USERNAME} already exists, skipping"
        continue
    fi

    # Create user
    useradd \
        -m \
        -s "${SHELL}" \
        -g "${GROUP}" \
        "${USERNAME}"

    # Set password
    echo "${USERNAME}:${PASSWORD}" | chpasswd

    # Optionally add to sudo group
    if [ "${SUDO}" = "yes" ]; then
        usermod -aG "${SUDO_GROUP}" "${USERNAME}"
        echo "  ✅ Created ${USERNAME} (${GROUP}) [SUDO]"
    else
        echo "  ✅ Created ${USERNAME} (${GROUP})"
    fi

done

# ── Print summary ─────────────────────────────────────────
echo ""
echo "========================================"
echo "  Users created with password: ${PASSWORD}"
echo "  Sudo users:"
grep -Po '^[^:]+(?=:[^:]+:[^:]+:yes)' <<< "$(printf '%s\n' "${USERS[@]}")" | \
    sed 's/^/    - /'
echo "========================================"