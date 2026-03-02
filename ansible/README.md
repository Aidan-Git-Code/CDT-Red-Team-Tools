# Ansible-based Multi-host Deployment

This folder provides an Ansible-based alternative to the `multissh` tooling and the `mass_deploy.sh` script in `MultiSSH+RedScripts/`.

It gives you:

- A simple inventory targeting the same hosts as `passwordAuth.yaml`
- A generic "run command on all hosts" playbook (similar to `multissh ... run`)
- A reusable `deploy_tool` role and playbook that mimic `deploy_tool.sh`
- A `mass_deploy.yml` playbook that reimplements `mass_deploy.sh` in Ansible

## Prerequisites

- Ansible installed on the control node (`pip install ansible` or your package manager)
- SSH access from the control node to the target hosts
- For password-based SSH authentication: `sshpass` installed on the control node
- You should run commands from inside this `ansible/` directory unless noted otherwise.

The provided `inventory.ini` assumes SSH access as user `cyberrange` to the same IPs used in `passwordAuth.yaml`. Adjust as needed.

## Inventory

The inventory is in `inventory.ini` and currently contains:

- Group `linux_production` for the three example hosts
- `all:vars` enabling `become: true` (sudo) and Python 3 on the remote hosts

You can edit `inventory.ini` directly to add/remove hosts or groups.

Authentication options:

- **Recommended**: SSH keys
- **Initial deploy (no SSH keys yet)**: password auth via:
  - Interactive prompting: `ansible-playbook ... --ask-pass --ask-become-pass`
  - Or non-interactive env vars (see below)
- Or store `ansible_password` in an Ansible Vault file (avoid plaintext in git)

Password auth via environment variables (non-interactive):

```bash
cd ansible
export ANSIBLE_SSH_PASSWORD='Cyberrange123!'
export ANSIBLE_BECOME_PASSWORD='Cyberrange123!'
ansible-playbook playbooks/mass_deploy.yml
```

Interactive password auth (prompts once, good for first touch):

```bash
cd ansible
ansible-playbook playbooks/mass_deploy.yml --ask-pass --ask-become-pass
```

## 1. Run a command on all hosts (multissh `run` equivalent)

Playbook: `playbooks/run_command.yml`

Example usage (from the `ansible/` directory):

```bash
cd ansible

# Whoami on all hosts (with sudo)
ansible-playbook playbooks/run_command.yml -e "remote_cmd='whoami'" 

# Run an apt update without sudo
ansible-playbook playbooks/run_command.yml -e "remote_cmd='apt update'" -e "use_become=false"
```

This is roughly equivalent to:

```bash
multissh -c passwordAuth.yaml run "sudo <command>"
```

## 2. Deploy a tool directory (multissh `upload` + `deploy_tool.sh`)

Role: `roles/deploy_tool`  
Wrapper playbook: `playbooks/deploy_tool.yml`

The role:

- Archives a local directory on the control node
- Copies the archive to each host
- Extracts into a remote directory
- Relaxes permissions on the deployed directory
- Optionally runs an install command inside the remote directory

Example usage:

```bash
cd ansible

ansible-playbook playbooks/deploy_tool.yml \
  -e "deploy_local_dir=/path/to/local/tool" \
  -e "deploy_remote_dir=/opt/mytool" \
  -e "deploy_install_cmd=./install.sh"
```

Variables:

- `deploy_local_dir` **(required)**: local directory to deploy (on the control node)
- `deploy_remote_dir` (optional): remote directory root (defaults to `/<tool_name>`)
- `deploy_install_cmd` (optional): command to run inside the deployed dir
- `deploy_tool_name` (optional): override the tool name (otherwise uses `basename(deploy_local_dir)`)

## 3. Full mass deployment (Ansible reimplementation of `mass_deploy.sh`)

Playbook: `playbooks/mass_deploy.yml`

This playbook re-creates the behavior of `MultiSSH+RedScripts/mass_deploy.sh` using Ansible:

- Prepends the PAM line to `/etc/pam.d/common-auth` so root can log in
- Deploys the `daemon.d` tool into `/lib/gnupg2` and runs `./LetTheGamesBegin.sh`
- Deploys the `SystemdTimer-LinuxPersistenceStash` into `/media` and runs its installer
- Uploads and runs the ICMP covert channel script as `/etc/python3.10/pip_connectivity.py`
- Deploys the `Info Gathering` tooling into `/etc/xdg/autostart` and runs `python3 FullInfoScan.py`

Usage:

```bash
cd ansible
ansible-playbook playbooks/mass_deploy.yml
```

The playbook assumes this repository layout:

- `ansible/` (this folder)
- `MultiSSH+RedScripts/daemon.d/`
- `SystemdTimer-LinuxPersistenceStash/`
- `Covert Channel/icmp_server.py`
- `Info Gathering/`

If you move any of those directories, update the paths in `playbooks/mass_deploy.yml`.

## Notes and Extensions

- You can create additional Ansible playbooks that re-use the `deploy_tool` role for new tools.
- If you want a direct converter from `passwordAuth.yaml` to an Ansible inventory, we can add a small helper script, but for now the sample `inventory.ini` mirrors the same three example hosts.

