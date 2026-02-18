#!/bin/bash
# Blue team indicator: suspicious cron entries

CALLBACK_SCRIPT="/tmp/.tmp_cleaner.sh"

# Create a very obvious keepalive script
cat > "$CALLBACK_SCRIPT" << 'EOF'
#!/bin/bash
# RED TEAM PERSISTENCE - competition artifact
echo "Red team persistence check $(date)" >> /tmp/.redteam_beacon.log
EOF

chmod +x "$CALLBACK_SCRIPT"

# Add to root crontab - runs every minute (very noisy/detectable)
(crontab -l 2>/dev/null; echo "* * * * * $CALLBACK_SCRIPT") | crontab -

# Also drop in /etc/cron.d for visibility
cat > /etc/cron.d/cronos << EOF
* * * * * root $CALLBACK_SCRIPT
EOF

echo "[RED TEAM] Cron persistence installed"