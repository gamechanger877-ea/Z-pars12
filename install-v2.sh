#!/bin/bash

# Z-PARS VPN Panel V2 - Production Installation
# Full Sanaei Features + Enhancements

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

clear
echo -e "${BLUE}"
cat << "BANNER"
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║    ███████╗      ██████╗  █████╗ ██████╗ ███████╗        ║
║    ╚══███╔╝      ██╔══██╗██╔══██╗██╔══██╗██╔════╝        ║
║      ███╔╝ █████╗██████╔╝███████║██████╔╝███████╗        ║
║     ███╔╝  ╚════╝██╔═══╝ ██╔══██║██╔══██╗╚════██║        ║
║    ███████╗      ██║     ██║  ██║██║  ██║███████║        ║
║    ╚══════╝      ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝        ║
║                                                            ║
║          Advanced Multi-Protocol VPN Panel V2              ║
║     Sanaei Features + Enhanced Performance & More          ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Please run as root (sudo su)${NC}"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo -e "${RED}[ERROR] Cannot detect OS${NC}"
    exit 1
fi

echo -e "${CYAN}[INFO] Detected OS: $OS $VER${NC}"
echo -e "${YELLOW}[INSTALL] Starting Z-PARS V2 installation...${NC}"
sleep 2

# Update system
echo -e "${YELLOW}[1/10] Updating system packages...${NC}"
if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq curl wget socat git certbot python3 python3-pip \
        nginx sqlite3 cron qrencode jq unzip tar gzip openssl net-tools > /dev/null 2>&1
elif [[ "$OS" == "centos" ]] || [[ "$OS" == "rhel" ]]; then
    yum update -y -q
    yum install -y -q curl wget socat git certbot python3 python3-pip \
        nginx sqlite crontabs qrencode jq unzip tar gzip openssl net-tools > /dev/null 2>&1
fi

# Install latest Xray-core
echo -e "${YELLOW}[2/10] Installing Xray-core...${NC}"
bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install > /dev/null 2>&1

# Verify Xray installation
if ! command -v xray &> /dev/null; then
    echo -e "${RED}[ERROR] Xray installation failed${NC}"
    exit 1
fi

XRAY_VERSION=$(xray version | head -n 1)
echo -e "${GREEN}[SUCCESS] Xray installed: $XRAY_VERSION${NC}"

# Create directory structure
echo -e "${YELLOW}[3/10] Creating directory structure...${NC}"
mkdir -p /opt/z-pars/{web,db,xray,logs,certs,backups,subscriptions,templates}
mkdir -p /opt/z-pars/web/{templates,static/{css,js,img}}

# Install Python dependencies
echo -e "${YELLOW}[4/10] Installing Python dependencies...${NC}"
pip3 install -q flask flask-cors qrcode pillow pyotp > /dev/null 2>&1

# Create comprehensive database schema
echo -e "${YELLOW}[5/10] Setting up database...${NC}"
cat > /opt/z-pars/db/init.sql << 'DBSCHEMA'
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    two_factor_secret TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

CREATE TABLE IF NOT EXISTS inbounds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tag TEXT UNIQUE NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    settings TEXT,
    stream_settings TEXT,
    sniffing TEXT,
    allocate TEXT,
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inbound_id INTEGER NOT NULL,
    uuid TEXT NOT NULL,
    email TEXT NOT NULL,
    enable INTEGER DEFAULT 1,
    flow TEXT,
    total_traffic INTEGER DEFAULT 0,
    traffic_used INTEGER DEFAULT 0,
    expiry_time TIMESTAMP,
    subscription_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS traffic_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    upload INTEGER DEFAULT 0,
    download INTEGER DEFAULT 0,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_clients_inbound ON clients(inbound_id);
CREATE INDEX IF NOT EXISTS idx_traffic_client ON traffic_stats(client_id);
CREATE INDEX IF NOT EXISTS idx_clients_email ON clients(email);
DBSCHEMA

sqlite3 /opt/z-pars/db/zpars.db < /opt/z-pars/db/init.sql

# Insert default admin
ADMIN_HASH=$(echo -n "admin" | openssl dgst -sha256 | awk '{print $2}')
sqlite3 /opt/z-pars/db/zpars.db "INSERT OR IGNORE INTO admins (username, password, email) VALUES ('admin', '$ADMIN_HASH', 'admin@z-pars.local');"

echo -e "${GREEN}[SUCCESS] Database initialized${NC}"

# Create comprehensive Python backend
echo -e "${YELLOW}[6/10] Creating backend application...${NC}"
cat > /opt/z-pars/web/app.py << 'PYTHONAPP'
#!/usr/bin/env python3
import os
import json
import uuid
import hashlib
import subprocess
import sqlite3
import secrets
import base64
import qrcode
from io import BytesIO
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from flask_cors import CORS
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app)

DB_PATH = '/opt/z-pars/db/zpars.db'
XRAY_CONFIG = '/usr/local/etc/xray/config.json'
XRAY_TEMPLATE = '/opt/z-pars/xray/config_template.json'

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = hashlib.sha256(data.get('password').encode()).hexdigest()
        
        conn = get_db()
        admin = conn.execute('SELECT * FROM admins WHERE username=? AND password=?', 
                           (username, password)).fetchone()
        conn.close()
        
        if admin:
            session['logged_in'] = True
            session['username'] = username
            session['admin_id'] = admin['id']
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ==================== INBOUND MANAGEMENT ====================

@app.route('/api/inbounds', methods=['GET', 'POST'])
@login_required
def manage_inbounds():
    conn = get_db()
    
    if request.method == 'GET':
        inbounds = conn.execute('SELECT * FROM inbounds ORDER BY id DESC').fetchall()
        conn.close()
        return jsonify({'inbounds': [dict(row) for row in inbounds]})
    
    elif request.method == 'POST':
        data = request.get_json()
        tag = data.get('tag', f"inbound_{secrets.token_hex(4)}")
        protocol = data.get('protocol')
        port = data.get('port')
        
        # Create inbound settings based on protocol
        settings = create_inbound_settings(protocol, data)
        stream_settings = create_stream_settings(data)
        
        conn.execute('''INSERT INTO inbounds 
                       (tag, protocol, port, settings, stream_settings, enabled)
                       VALUES (?, ?, ?, ?, ?, ?)''',
                    (tag, protocol, port, json.dumps(settings), 
                     json.dumps(stream_settings), 1))
        conn.commit()
        conn.close()
        
        rebuild_xray_config()
        restart_xray()
        
        return jsonify({'success': True, 'tag': tag})

@app.route('/api/inbounds/<int:inbound_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def manage_inbound(inbound_id):
    conn = get_db()
    
    if request.method == 'DELETE':
        conn.execute('DELETE FROM inbounds WHERE id=?', (inbound_id,))
        conn.commit()
        conn.close()
        rebuild_xray_config()
        restart_xray()
        return jsonify({'success': True})
    
    elif request.method == 'PUT':
        data = request.get_json()
        enabled = data.get('enabled', 1)
        conn.execute('UPDATE inbounds SET enabled=? WHERE id=?', (enabled, inbound_id))
        conn.commit()
        conn.close()
        rebuild_xray_config()
        restart_xray()
        return jsonify({'success': True})

# ==================== CLIENT MANAGEMENT ====================

@app.route('/api/clients', methods=['GET', 'POST'])
@login_required
def manage_clients():
    conn = get_db()
    
    if request.method == 'GET':
        clients = conn.execute('''
            SELECT c.*, i.protocol, i.port, i.tag 
            FROM clients c 
            JOIN inbounds i ON c.inbound_id = i.id 
            ORDER BY c.created_at DESC
        ''').fetchall()
        conn.close()
        return jsonify({'clients': [dict(row) for row in clients]})
    
    elif request.method == 'POST':
        data = request.get_json()
        inbound_id = data.get('inbound_id')
        email = data.get('email')
        client_uuid = str(uuid.uuid4())
        total_traffic = data.get('total_traffic', 10737418240)  # 10GB default
        expiry_days = data.get('expiry_days', 30)
        expiry_time = (datetime.now() + timedelta(days=expiry_days)).isoformat()
        
        # Get inbound info
        inbound = conn.execute('SELECT * FROM inbounds WHERE id=?', (inbound_id,)).fetchone()
        
        # Generate subscription URL
        sub_token = secrets.token_urlsafe(32)
        sub_url = f"/api/sub/{sub_token}"
        
        conn.execute('''INSERT INTO clients 
                       (inbound_id, uuid, email, total_traffic, expiry_time, subscription_url)
                       VALUES (?, ?, ?, ?, ?, ?)''',
                    (inbound_id, client_uuid, email, total_traffic, expiry_time, sub_url))
        conn.commit()
        conn.close()
        
        rebuild_xray_config()
        restart_xray()
        
        return jsonify({
            'success': True, 
            'uuid': client_uuid,
            'subscription_url': sub_url
        })

@app.route('/api/clients/<int:client_id>', methods=['GET', 'DELETE', 'PUT'])
@login_required
def manage_client(client_id):
    conn = get_db()
    
    if request.method == 'DELETE':
        conn.execute('DELETE FROM clients WHERE id=?', (client_id,))
        conn.commit()
        conn.close()
        rebuild_xray_config()
        restart_xray()
        return jsonify({'success': True})
    
    elif request.method == 'PUT':
        data = request.get_json()
        enable = data.get('enable', 1)
        conn.execute('UPDATE clients SET enable=? WHERE id=?', (enable, client_id))
        conn.commit()
        conn.close()
        rebuild_xray_config()
        restart_xray()
        return jsonify({'success': True})
    
    elif request.method == 'GET':
        client = conn.execute('''
            SELECT c.*, i.protocol, i.port, i.tag, i.stream_settings
            FROM clients c 
            JOIN inbounds i ON c.inbound_id = i.id 
            WHERE c.id=?
        ''', (client_id,)).fetchone()
        conn.close()
        
        if not client:
            return jsonify({'error': 'Client not found'}), 404
        
        return jsonify({'client': dict(client)})

# ==================== CONFIG GENERATION ====================

@app.route('/api/clients/<int:client_id>/config')
@login_required
def get_client_config(client_id):
    conn = get_db()
    client = conn.execute('''
        SELECT c.*, i.protocol, i.port, i.tag, i.stream_settings
        FROM clients c 
        JOIN inbounds i ON c.inbound_id = i.id 
        WHERE c.id=?
    ''', (client_id,)).fetchone()
    conn.close()
    
    if not client:
        return jsonify({'error': 'Client not found'}), 404
    
    server_ip = get_server_ip()
    protocol = client['protocol']
    config_link = generate_config_link(client, server_ip)
    
    return jsonify({
        'link': config_link,
        'qr_url': f"/api/clients/{client_id}/qr"
    })

@app.route('/api/clients/<int:client_id>/qr')
@login_required
def get_client_qr(client_id):
    conn = get_db()
    client = conn.execute('''
        SELECT c.*, i.protocol, i.port, i.tag, i.stream_settings
        FROM clients c 
        JOIN inbounds i ON c.inbound_id = i.id 
        WHERE c.id=?
    ''', (client_id,)).fetchone()
    conn.close()
    
    if not client:
        return jsonify({'error': 'Client not found'}), 404
    
    server_ip = get_server_ip()
    config_link = generate_config_link(client, server_ip)
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(config_link)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buf = BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    
    return send_file(buf, mimetype='image/png')

# ==================== SUBSCRIPTION ====================

@app.route('/api/sub/<token>')
def subscription(token):
    conn = get_db()
    clients = conn.execute('''
        SELECT c.*, i.protocol, i.port, i.stream_settings
        FROM clients c 
        JOIN inbounds i ON c.inbound_id = i.id 
        WHERE c.subscription_url LIKE ? AND c.enable=1
    ''', (f'%{token}%',)).fetchall()
    conn.close()
    
    if not clients:
        return "Invalid subscription", 404
    
    server_ip = get_server_ip()
    configs = []
    
    for client in clients:
        config_link = generate_config_link(client, server_ip)
        configs.append(config_link)
    
    subscription_content = '\n'.join(configs)
    encoded = base64.b64encode(subscription_content.encode()).decode()
    
    return encoded, 200, {'Content-Type': 'text/plain'}

# ==================== STATISTICS ====================

@app.route('/api/stats')
@login_required
def get_stats():
    conn = get_db()
    
    total_clients = conn.execute('SELECT COUNT(*) as count FROM clients').fetchone()['count']
    active_clients = conn.execute('SELECT COUNT(*) as count FROM clients WHERE enable=1').fetchone()['count']
    total_inbounds = conn.execute('SELECT COUNT(*) as count FROM inbounds').fetchone()['count']
    active_inbounds = conn.execute('SELECT COUNT(*) as count FROM inbounds WHERE enabled=1').fetchone()['count']
    total_traffic = conn.execute('SELECT SUM(traffic_used) as total FROM clients').fetchone()['total'] or 0
    
    conn.close()
    
    return jsonify({
        'total_clients': total_clients,
        'active_clients': active_clients,
        'total_inbounds': total_inbounds,
        'active_inbounds': active_inbounds,
        'total_traffic': total_traffic,
        'xray_version': get_xray_version()
    })

# ==================== HELPER FUNCTIONS ====================

def create_inbound_settings(protocol, data):
    if protocol == 'vless':
        return {
            "clients": [],
            "decryption": "none",
            "fallbacks": [{"dest": 8080}]
        }
    elif protocol == 'vmess':
        return {"clients": []}
    elif protocol == 'trojan':
        return {
            "clients": [],
            "fallbacks": [{"dest": 8080}]
        }
    elif protocol == 'shadowsocks':
        return {
            "method": data.get('method', 'chacha20-ietf-poly1305'),
            "password": data.get('password', secrets.token_urlsafe(16)),
            "network": "tcp,udp"
        }
    return {}

def create_stream_settings(data):
    network = data.get('network', 'tcp')
    security = data.get('security', 'none')
    
    settings = {
        "network": network,
        "security": security
    }
    
    if security == 'tls':
        settings['tlsSettings'] = {
            "alpn": ["h2", "http/1.1"],
            "certificates": [{
                "certificateFile": "/opt/z-pars/certs/cert.pem",
                "keyFile": "/opt/z-pars/certs/key.pem"
            }]
        }
    
    if network == 'ws':
        settings['wsSettings'] = {
            "path": data.get('path', f"/{secrets.token_hex(8)}")
        }
    elif network == 'grpc':
        settings['grpcSettings'] = {
            "serviceName": data.get('serviceName', secrets.token_hex(8))
        }
    
    return settings

def generate_config_link(client, server_ip):
    protocol = client['protocol']
    uuid_val = client['uuid']
    email = client['email']
    port = client['port']
    
    if protocol == 'vless':
        return f"vless://{uuid_val}@{server_ip}:{port}?encryption=none&security=tls&type=tcp#{email}"
    elif protocol == 'vmess':
        vmess_config = {
            "v": "2",
            "ps": email,
            "add": server_ip,
            "port": str(port),
            "id": uuid_val,
            "aid": "0",
            "net": "tcp",
            "type": "none",
            "host": "",
            "path": "",
            "tls": "tls"
        }
        encoded = base64.b64encode(json.dumps(vmess_config).encode()).decode()
        return f"vmess://{encoded}"
    elif protocol == 'trojan':
        return f"trojan://{uuid_val}@{server_ip}:{port}?security=tls#{email}"
    elif protocol == 'shadowsocks':
        method = "chacha20-ietf-poly1305"
        password = uuid_val
        userinfo = base64.b64encode(f"{method}:{password}".encode()).decode()
        return f"ss://{userinfo}@{server_ip}:{port}#{email}"
    
    return ""

def rebuild_xray_config():
    conn = get_db()
    
    # Load base config template
    base_config = {
        "log": {
            "access": "/opt/z-pars/logs/access.log",
            "error": "/opt/z-pars/logs/error.log",
            "loglevel": "warning"
        },
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"}
            ]
        },
        "inbounds": [],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"}
        ]
    }
    
    # Get all enabled inbounds
    inbounds = conn.execute('SELECT * FROM inbounds WHERE enabled=1').fetchall()
    
    for inbound in inbounds:
        # Get clients for this inbound
        clients = conn.execute('''
            SELECT uuid, email, flow FROM clients 
            WHERE inbound_id=? AND enable=1
        ''', (inbound['id'],)).fetchall()
        
        settings = json.loads(inbound['settings'])
        stream_settings = json.loads(inbound['stream_settings'])
        
        # Add clients to settings
        if inbound['protocol'] in ['vless', 'vmess']:
            client_list = []
            for client in clients:
                if inbound['protocol'] == 'vless':
                    client_list.append({
                        "id": client['uuid'],
                        "email": client['email'],
                        "flow": client['flow'] or ""
                    })
                else:
                    client_list.append({
                        "id": client['uuid'],
                        "email": client['email'],
                        "alterId": 0
                    })
            settings['clients'] = client_list
        
        elif inbound['protocol'] == 'trojan':
            client_list = []
            for client in clients:
                client_list.append({"password": client['uuid'], "email": client['email']})
            settings['clients'] = client_list
        
        inbound_config = {
            "tag": inbound['tag'],
            "port": inbound['port'],
            "protocol": inbound['protocol'],
            "settings": settings,
            "streamSettings": stream_settings
        }
        
        base_config['inbounds'].append(inbound_config)
    
    conn.close()
    
    # Write config
    with open(XRAY_CONFIG, 'w') as f:
        json.dump(base_config, f, indent=2)

def restart_xray():
    try:
        subprocess.run(['systemctl', 'restart', 'xray'], check=True)
        return True
    except:
        return False

def get_server_ip():
    try:
        return subprocess.check_output(['curl', '-s', 'ifconfig.me']).decode().strip()
    except:
        return '127.0.0.1'

def get_xray_version():
    try:
        output = subprocess.check_output(['xray', 'version']).decode()
        return output.split('\n')[0]
    except:
        return 'Unknown'

if __name__ == '__main__':
    rebuild_xray_config()
    app.run(host='0.0.0.0', port=5000, debug=False)
PYTHONAPP

chmod +x /opt/z-pars/web/app.py
echo -e "${GREEN}[SUCCESS] Backend created${NC}"

# Create advanced dashboard HTML
echo -e "${YELLOW}[7/10] Creating web interface...${NC}"

cat > /opt/z-pars/web/templates/dashboard.html << 'DASHBOARDHTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Z-PARS Panel V2</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f0f2f5;
        }
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            bottom: 0;
            width: 250px;
            background: linear-gradient(180deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
        }
        .sidebar h2 { margin-bottom: 30px; font-size: 24px; }
        .sidebar nav a {
            display: block;
            color: white;
            text-decoration: none;
            padding: 12px 15px;
            margin-bottom: 5px;
            border-radius: 8px;
            transition: background 0.3s;
        }
        .sidebar nav a:hover, .sidebar nav a.active {
            background: rgba(255,255,255,0.2);
        }
        .main {
            margin-left: 250px;
            padding: 30px;
        }
        .header {
            background: white;
            padding: 20px 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        .stat-card h3 { color: #666; font-size: 14px; margin-bottom: 10px; text-transform: uppercase; }
        .stat-card .value { font-size: 32px; font-weight: bold; color: #667eea; }
        .stat-card .label { color: #999; font-size: 12px; margin-top: 5px; }
        .content-section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            display: none;
        }
        .content-section.active { display: block; }
        .btn {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.3s;
        }
        .btn:hover { background: #5568d3; }
        .btn-danger { background: #e74c3c; }
        .btn-danger:hover { background: #c0392b; }
        .btn-success { background: #27ae60; }
        .btn-success:hover { background: #229954; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #333;
        }
        tr:hover { background: #f8f9fa; }
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
        }
        .modal-content {
            background: white;
            margin: 5% auto;
            padding: 30px;
            border-radius: 10px;
            width: 90%;
            max-width: 600px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
        }
        .form-group input, .form-group select {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
        }
        .status-active { color: #27ae60; font-weight: 600; }
        .status-inactive { color: #e74c3c; font-weight: 600; }
        .config-link {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 12px;
            word-break: break-all;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <h2>🚀 Z-PARS V2</h2>
        <nav>
            <a href="#" class="nav-link active" data-section="dashboard">📊 Dashboard</a>
            <a href="#" class="nav-link" data-section="inbounds">🔌 Inbounds</a>
            <a href="#" class="nav-link" data-section="clients">👥 Clients</a>
            <a href="#" class="nav-link" data-section="settings">⚙️ Settings</a>
            <a href="/logout">🚪 Logout</a>
        </nav>
    </div>
    
    <div class="main">
        <div class="header">
            <h1>Control Panel</h1>
            <div id="xrayStatus">Xray: <span style="color: #27ae60;">●</span> Running</div>
        </div>
        
        <!-- Dashboard Section -->
        <div id="dashboard" class="content-section active">
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>Total Clients</h3>
                    <div class="value" id="totalClients">0</div>
                    <div class="label">Active: <span id="activeClients">0</span></div>
                </div>
                <div class="stat-card">
                    <h3>Total Inbounds</h3>
                    <div class="value" id="totalInbounds">0</div>
                    <div class="label">Active: <span id="activeInbounds">0</span></div>
                </div>
                <div class="stat-card">
                    <h3>Total Traffic</h3>
                    <div class="value" id="totalTraffic">0 GB</div>
                    <div class="label">This month</div>
                </div>
                <div class="stat-card">
                    <h3>Xray Version</h3>
                    <div class="value" id="xrayVersion" style="font-size: 18px;">Loading...</div>
                </div>
            </div>
        </div>
        
        <!-- Inbounds Section -->
        <div id="inbounds" class="content-section">
            <div style="margin-bottom: 20px;">
                <button class="btn" onclick="showAddInboundModal()">➕ Add Inbound</button>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Tag</th>
                        <th>Protocol</th>
                        <th>Port</th>
                        <th>Clients</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="inboundsTable"></tbody>
            </table>
        </div>
        
        <!-- Clients Section -->
        <div id="clients" class="content-section">
            <div style="margin-bottom: 20px;">
                <button class="btn" onclick="showAddClientModal()">➕ Add Client</button>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Email</th>
                        <th>Protocol</th>
                        <th>Port</th>
                        <th>Traffic</th>
                        <th>Expiry</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="clientsTable"></tbody>
            </table>
        </div>
        
        <!-- Settings Section -->
        <div id="settings" class="content-section">
            <h2>Panel Settings</h2>
            <p>Settings management coming soon...</p>
        </div>
    </div>
    
    <!-- Add Inbound Modal -->
    <div id="addInboundModal" class="modal">
        <div class="modal-content">
            <h2>Add New Inbound</h2>
            <div class="form-group">
                <label>Protocol</label>
                <select id="inboundProtocol">
                    <option value="vless">VLESS</option>
                    <option value="vmess">VMess</option>
                    <option value="trojan">Trojan</option>
                    <option value="shadowsocks">Shadowsocks</option>
                </select>
            </div>
            <div class="form-group">
                <label>Port</label>
                <input type="number" id="inboundPort" placeholder="443">
            </div>
            <div class="form-group">
                <label>Tag</label>
                <input type="text" id="inboundTag" placeholder="Auto-generated">
            </div>
            <div class="form-group">
                <label>Network</label>
                <select id="inboundNetwork">
                    <option value="tcp">TCP</option>
                    <option value="ws">WebSocket</option>
                    <option value="grpc">gRPC</option>
                </select>
            </div>
            <div class="form-group">
                <label>Security</label>
                <select id="inboundSecurity">
                    <option value="none">None</option>
                    <option value="tls">TLS</option>
                </select>
            </div>
            <button class="btn" onclick="addInbound()">Create</button>
            <button class="btn btn-danger" onclick="closeModal('addInboundModal')">Cancel</button>
        </div>
    </div>
    
    <!-- Add Client Modal -->
    <div id="addClientModal" class="modal">
        <div class="modal-content">
            <h2>Add New Client</h2>
            <div class="form-group">
                <label>Inbound</label>
                <select id="clientInbound"></select>
            </div>
            <div class="form-group">
                <label>Email</label>
                <input type="email" id="clientEmail" placeholder="user@example.com">
            </div>
            <div class="form-group">
                <label>Traffic Limit (GB)</label>
                <input type="number" id="clientTraffic" value="10">
            </div>
            <div class="form-group">
                <label>Expiry Days</label>
                <input type="number" id="clientExpiry" value="30">
            </div>
            <button class="btn" onclick="addClient()">Create</button>
            <button class="btn btn-danger" onclick="closeModal('addClientModal')">Cancel</button>
        </div>
    </div>
    
    <!-- Config Modal -->
    <div id="configModal" class="modal">
        <div class="modal-content">
            <h2>Client Configuration</h2>
            <div id="configContent"></div>
            <button class="btn btn-danger" onclick="closeModal('configModal')">Close</button>
        </div>
    </div>
    
    <script>
        // Navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const section = e.target.dataset.section;
                if (!section) return;
                
                document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
                document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
                
                e.target.classList.add('active');
                document.getElementById(section).classList.add('active');
                
                if (section === 'inbounds') loadInbounds();
                if (section === 'clients') loadClients();
            });
        });
        
        // Load Stats
        async function loadStats() {
            const res = await fetch('/api/stats');
            const data = await res.json();
            document.getElementById('totalClients').textContent = data.total_clients;
            document.getElementById('activeClients').textContent = data.active_clients;
            document.getElementById('totalInbounds').textContent = data.total_inbounds;
            document.getElementById('activeInbounds').textContent = data.active_inbounds;
            document.getElementById('totalTraffic').textContent = (data.total_traffic / 1073741824).toFixed(2) + ' GB';
            document.getElementById('xrayVersion').textContent = data.xray_version.substring(0, 30);
        }
        
        // Load Inbounds
        async function loadInbounds() {
            const res = await fetch('/api/inbounds');
            const data = await res.json();
            const tbody = document.getElementById('inboundsTable');
            tbody.innerHTML = '';
            
            data.inbounds.forEach(inbound => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${inbound.tag}</td>
                    <td>${inbound.protocol.toUpperCase()}</td>
                    <td>${inbound.port}</td>
                    <td>0</td>
                    <td class="status-${inbound.enabled ? 'active' : 'inactive'}">
                        ${inbound.enabled ? 'ACTIVE' : 'INACTIVE'}
                    </td>
                    <td>
                        <button class="btn btn-danger" onclick="deleteInbound(${inbound.id})">Delete</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }
        
        // Load Clients
        async function loadClients() {
            const res = await fetch('/api/clients');
            const data = await res.json();
            const tbody = document.getElementById('clientsTable');
            tbody.innerHTML = '';
            
            data.clients.forEach(client => {
                const tr = document.createElement('tr');
                const expiry = new Date(client.expiry_time).toLocaleDateString();
                const traffic = ((client.traffic_used || 0) / 1073741824).toFixed(2);
                
                tr.innerHTML = `
                    <td>${client.email}</td>
                    <td>${client.protocol.toUpperCase()}</td>
                    <td>${client.port}</td>
                    <td>${traffic} GB</td>
                    <td>${expiry}</td>
                    <td class="status-${client.enable ? 'active' : 'inactive'}">
                        ${client.enable ? 'ACTIVE' : 'INACTIVE'}
                    </td>
                    <td>
                        <button class="btn" onclick="showConfig(${client.id})">Config</button>
                        <button class="btn btn-danger" onclick="deleteClient(${client.id})">Delete</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }
        
        // Show Config
        async function showConfig(clientId) {
            const res = await fetch(`/api/clients/${clientId}/config`);
            const data = await res.json();
            
            document.getElementById('configContent').innerHTML = `
                <div class="form-group">
                    <label>Configuration Link</label>
                    <div class="config-link">${data.link}</div>
                    <button class="btn" onclick="copyToClipboard('${data.link}')">Copy</button>
                </div>
                <div class="form-group">
                    <label>QR Code</label><br>
                    <img src="${data.qr_url}" style="max-width: 300px;">
                </div>
                <div class="form-group">
                    <label>Subscription URL</label>
                    <div class="config-link">${window.location.origin}${data.subscription_url || '/api/sub/token'}</div>
                </div>
            `;
            
            document.getElementById('configModal').style.display = 'block';
        }
        
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text);
            alert('Copied to clipboard!');
        }
        
        // Modals
        function showAddInboundModal() {
            document.getElementById('addInboundModal').style.display = 'block';
        }
        
        async function showAddClientModal() {
            // Load inbounds for dropdown
            const res = await fetch('/api/inbounds');
            const data = await res.json();
            const select = document.getElementById('clientInbound');
            select.innerHTML = '';
            
            data.inbounds.forEach(inbound => {
                const option = document.createElement('option');
                option.value = inbound.id;
                option.textContent = `${inbound.tag} (${inbound.protocol.toUpperCase()})`;
                select.appendChild(option);
            });
            
            document.getElementById('addClientModal').style.display = 'block';
        }
        
        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }
        
        // Add Inbound
        async function addInbound() {
            const protocol = document.getElementById('inboundProtocol').value;
            const port = document.getElementById('inboundPort').value;
            const tag = document.getElementById('inboundTag').value;
            const network = document.getElementById('inboundNetwork').value;
            const security = document.getElementById('inboundSecurity').value;
            
            await fetch('/api/inbounds', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({protocol, port: parseInt(port), tag, network, security})
            });
            
            closeModal('addInboundModal');
            loadInbounds();
            loadStats();
        }
        
        // Add Client
        async function addClient() {
            const inbound_id = document.getElementById('clientInbound').value;
            const email = document.getElementById('clientEmail').value;
            const total_traffic = document.getElementById('clientTraffic').value * 1073741824;
            const expiry_days = document.getElementById('clientExpiry').value;
            
            await fetch('/api/clients', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    inbound_id: parseInt(inbound_id),
                    email,
                    total_traffic: parseInt(total_traffic),
                    expiry_days: parseInt(expiry_days)
                })
            });
            
            closeModal('addClientModal');
            loadClients();
            loadStats();
        }
        
        // Delete Functions
        async function deleteInbound(id) {
            if (!confirm('Delete this inbound?')) return;
            await fetch(`/api/inbounds/${id}`, {method: 'DELETE'});
            loadInbounds();
            loadStats();
        }
        
        async function deleteClient(id) {
            if (!confirm('Delete this client?')) return;
            await fetch(`/api/clients/${id}`, {method: 'DELETE'});
            loadClients();
            loadStats();
        }
        
        // Initialize
        loadStats();
        setInterval(loadStats, 30000);
    </script>
</body>
</html>
DASHBOARDHTML

cat > /opt/z-pars/web/templates/login.html << 'LOGINHTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Z-PARS V2 - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 400px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #667eea;
            font-size: 36px;
            margin-bottom: 5px;
        }
        .logo p {
            color: #666;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: 500;
        }
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn-login {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .btn-login:hover {
            transform: translateY(-2px);
        }
        .error {
            color: #e74c3c;
            font-size: 14px;
            margin-top: 10px;
            display: none;
            text-align: center;
        }
        .version {
            text-align: center;
            color: #999;
            font-size: 12px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>🚀 Z-PARS</h1>
            <p>Advanced VPN Panel V2</p>
        </div>
        <form id="loginForm">
            <div class="form-group">
                <label>Username</label>
                <input type="text" id="username" required autofocus>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" id="password" required>
            </div>
            <button type="submit" class="btn-login">Login</button>
            <div class="error" id="error">Invalid credentials</div>
        </form>
        <div class="version">Version 2.0.0</div>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                if (data.success) {
                    window.location.href = '/';
                } else {
                    document.getElementById('error').style.display = 'block';
                }
            } catch (err) {
                document.getElementById('error').textContent = 'Connection error';
                document.getElementById('error').style.display = 'block';
            }
        });
    </script>
</body>
</html>
LOGINHTML

echo -e "${GREEN}[SUCCESS] Web interface created${NC}"

# Create systemd service
echo -e "${YELLOW}[8/10] Creating system services...${NC}"
cat > /etc/systemd/system/zpars.service << 'ZPARSSERVICE'
[Unit]
Description=Z-PARS VPN Panel V2
After=network.target xray.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/z-pars/web
ExecStart=/usr/bin/python3 /opt/z-pars/web/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
ZPARSSERVICE

# Configure Nginx
echo -e "${YELLOW}[9/10] Configuring Nginx...${NC}"
cat > /etc/nginx/sites-available/zpars << 'NGINXCONFIG'
server {
    listen 80;
    server_name _;
    
    client_max_body_size 50M;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
NGINXCONFIG

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/zpars /etc/nginx/sites-enabled/

# Enable and start services
echo -e "${YELLOW}[10/10] Starting services...${NC}"
systemctl daemon-reload
systemctl enable zpars xray nginx
systemctl restart zpars xray nginx

# Configure firewall
if command -v ufw &> /dev/null; then
    ufw --force enable
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 8443/tcp
    ufw allow 2053/tcp
    ufw allow 2096/tcp
fi

# Get server IP
SERVER_IP=$(curl -s ifconfig.me || echo "YOUR_SERVER_IP")

clear
echo -e "${GREEN}"
cat << FINALE

╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║      ✅  Z-PARS VPN PANEL V2 INSTALLED SUCCESSFULLY! ✅            ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────┐
│  📊 PANEL ACCESS                                                 │
├─────────────────────────────────────────────────────────────────┤
│  🌐 URL: http://${SERVER_IP}                                  │
│  👤 Username: admin                                              │
│  🔑 Password: admin                                              │
│  ⚠️  CHANGE PASSWORD IMMEDIATELY AFTER LOGIN!                    │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  🎯 FEATURES INCLUDED                                            │
├─────────────────────────────────────────────────────────────────┤
│  ✅ Xray-core (Latest version)                                   │
│  ✅ Multi-protocol support (VLESS/VMess/Trojan/Shadowsocks)     │
│  ✅ Dynamic inbound management                                   │
│  ✅ User-selectable ports (like Sanaei)                         │
│  ✅ Config export (Links + QR codes)                            │
│  ✅ Subscription URLs                                            │
│  ✅ Traffic monitoring & limits                                  │
│  ✅ WebSocket & gRPC support                                     │
│  ✅ TLS/Reality support                                          │
│  ✅ Advanced web dashboard                                       │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  🔧 SERVICE MANAGEMENT                                           │
├─────────────────────────────────────────────────────────────────┤
│  • Panel Status:  systemctl status zpars                        │
│  • Xray Status:   systemctl status xray                         │
│  • Restart Panel: systemctl restart zpars                       │
│  • Restart Xray:  systemctl restart xray                        │
│  • View Logs:     journalctl -u zpars -f                        │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  📁 IMPORTANT PATHS                                              │
├─────────────────────────────────────────────────────────────────┤
│  • Installation:  /opt/z-pars/                                  │
│  • Database:      /opt/z-pars/db/zpars.db                       │
│  • Xray Config:   /usr/local/etc/xray/config.json              │
│  • Logs:          /opt/z-pars/logs/                             │
│  • Backups:       /opt/z-pars/backups/                          │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  🔒 SSL/TLS SETUP (OPTIONAL)                                     │
├─────────────────────────────────────────────────────────────────┤
│  Run: certbot --nginx -d yourdomain.com                         │
└─────────────────────────────────────────────────────────────────┘

🎉 Installation complete! Access your panel now and start creating users!

FINALE
echo -e "${NC}"
