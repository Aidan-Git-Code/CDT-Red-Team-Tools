#!/bin/bash
set -e 

# Deploying Jack's SystemdTimer persistence
./deploy_tool.sh passwordAuth.yaml ../CDT-Red-Team-Tools/SystemdTimer-LinuxPersistenceStash/ "/opt/SystemdTimer-LinuxPersistenceStash/SystemdTimer-LinuxPersistenceStash/install.sh --purge-source"

./deploy_tool.sh passwordAuth.yaml "../CDT-Red-Team-Tools/Info-Gathering/" "sudo python3 /opt/Info-Gathering/Info-Gathering/FullInfoScan.py"