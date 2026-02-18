#!/bin/bash

# ── Check if SELinux is present ──────────────────────────
if ! command -v getenforce &>/dev/null; then
    echo "  SELinux not present on this system, skipping"
    exit 0
fi

CURRENT=$(getenforce)
echo "  Current SELinux state: ${CURRENT}"

# ── Disable for current session immediately ──────────────
setenforce 0
echo "  ✅ SELinux set to Permissive (runtime)"

# ── Disable persistently across reboots ─────────────────
SELINUX_CONFIG="/etc/selinux/config"
if [ -f "${SELINUX_CONFIG}" ]; then
    cp "${SELINUX_CONFIG}" "${SELINUX_CONFIG}.bak.redteam"
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' "${SELINUX_CONFIG}"
    echo "  ✅ SELinux set to disabled in ${SELINUX_CONFIG} (persistent)"
fi
