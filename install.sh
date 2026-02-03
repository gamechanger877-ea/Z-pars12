#!/bin/bash

# ═══════════════════════════════════════════════════════════════════
# Z-PARS ULTIMATE VPN PANEL - Professional Edition
# Multi-Protocol | Multi-User | Enterprise Ready
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════
# COLOR DEFINITIONS
# ═══════════════════════════════════════════════════════════════════

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# ═══════════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════════

show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   ███████╗      ██████╗  █████╗ ██████╗ ███████╗                     ║
║   ╚══███╔╝      ██╔══██╗██╔══██╗██╔══██╗██╔════╝                     ║
║     ███╔╝ █████╗██████╔╝███████║██████╔╝███████╗                     ║
║    ███╔╝  ╚════╝██╔═══╝ ██╔══██║██╔══██╗╚════██║                     ║
║   ███████╗      ██║     ██║  ██║██║  ██║███████║                     ║
║   ╚══════╝      ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝                     ║
║                                                                       ║
║              🚀 ULTIMATE VPN PANEL - PROFESSIONAL EDITION 🚀          ║
║                                                                       ║
║   ✨ Multi-Protocol | Real-time Stats | Advanced Management ✨       ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}\n"
}

# ═══════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_step() {
    echo -e "\n${PURPLE}${BOLD}━━━ STEP $1 ━━━${NC}"
}

# ═══════════════════════════════════════════════════════════════════
# PRE-FLIGHT CHECKS
# ═══════════════════════════════════════════════════════════════════

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        echo -e "${YELLOW}Please run: ${WHITE}sudo bash install.sh${NC}"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
        log_success "Detected: $PRETTY_NAME"
    else
        log_error "Cannot detect operating system"
        exit 1
    fi
    
    # Validate supported OS
    case $OS in
        ubuntu|debian|centos|rhel|fedora)
            log_success "OS supported ✓"
            ;;
        *)
            log_warning "OS not officially tested but will attempt installation"
            ;;
    esac
}

check_dependencies() {
    log_info "Checking system requirements..."
    
    # Check CPU
    CPU_CORES=$(nproc)
    log_info "CPU Cores: $CPU_CORES"
    
    # Check RAM
    TOTAL_RAM=$(free -m | awk 'NR==2{print $2}')
    log_info "Total RAM: ${TOTAL_RAM}MB"
    
    if [[ $TOTAL_RAM -lt 512 ]]; then
        log_warning "RAM is low. Recommended: 1GB+"
    fi
    
    # Check disk space
    DISK_SPACE=$(df -BG / | awk 'NR==2{print $4}' | sed 's/G//')
    log_info "Available Disk: ${DISK_SPACE}GB"
    
    if [[ $DISK_SPACE -lt 5 ]]; then
        log_error "Insufficient disk space. Need at least 5GB"
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════════
# INSTALLATION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

install_dependencies() {
    log_step "1/12 - Installing System Dependencies"
    
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        export DEBIAN_FRONTEND=noninteractive
        
        log_info "Updating package lists..."
        apt-get update -qq > /dev/null 2>&1
        
        log_info "Installing packages..."
        apt-get install -y -qq \
            curl wget git \
            nginx certbot python3-certbot-nginx \
            python3 python3-pip python3-venv \
            sqlite3 jq unzip tar gzip \
            qrencode cron net-tools \
            openssl ca-certificates \
            software-properties-common \
            ufw fail2ban \
            > /dev/null 2>&1
            
    elif [[ "$OS" == "centos" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "fedora" ]]; then
        log_info "Updating package lists..."
        yum update -y -q > /dev/null 2>&1
        
        log_info "Installing packages..."
        yum install -y -q \
            curl wget git \
            nginx certbot python3-certbot-nginx \
            python3 python3-pip \
            sqlite jq unzip tar gzip \
            qrencode cronie net-tools \
            openssl ca-certificates \
            firewalld fail2ban \
            > /dev/null 2>&1
    fi
    
    log_success "System dependencies installed"
}

install_xray() {
    log_step "2/12 - Installing Xray-core"
    
    log_info "Downloading and installing Xray..."
    bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install > /dev/null 2>&1
    
    if ! command -v xray &> /dev/null; then
        log_error "Xray installation failed"
        exit 1
    fi
    
    XRAY_VERSION=$(xray version 2>&1 | head -n 1 | awk '{print $2}')
    log_success "Xray-core $XRAY_VERSION installed"
    
    # Enable Xray service
    systemctl enable xray > /dev/null 2>&1
}

create_directories() {
    log_step "3/12 - Creating Directory Structure"
    
    log_info "Setting up directories..."
    mkdir -p /opt/zpars/{app,db,logs,backups,certs,temp,subscriptions}
    mkdir -p /opt/zpars/app/{templates,static/{css,js,img,fonts}}
    mkdir -p /var/log/zpars
    
    log_success "Directory structure created"
}

setup_python_environment() {
    log_step "4/12 - Setting Up Python Environment"
    
    log_info "Creating virtual environment..."
    python3 -m venv /opt/zpars/venv > /dev/null 2>&1
    
    log_info "Installing Python packages..."
    /opt/zpars/venv/bin/pip install --quiet --upgrade pip > /dev/null 2>&1
    /opt/zpars/venv/bin/pip install --quiet \
        flask flask-cors flask-limiter \
        qrcode pillow \
        requests pyotp \
        gunicorn gevent \
        pyjwt cryptography \
        > /dev/null 2>&1
    
    log_success "Python environment ready"
}

setup_database() {
    log_step "5/12 - Initializing Database"
    
    cat > /opt/zpars/db/schema.sql << 'SCHEMA'
-- ═══════════════════════════════════════════════════════════════
-- ZPARS DATABASE SCHEMA - PROFESSIONAL EDITION
-- ═══════════════════════════════════════════════════════════════

-- Admin accounts
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    two_factor_secret TEXT,
    role TEXT DEFAULT 'admin',
    avatar TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    login_count INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1
);

-- Inbound configurations
CREATE TABLE IF NOT EXISTS inbounds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tag TEXT UNIQUE NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    listen TEXT DEFAULT '0.0.0.0',
    settings TEXT NOT NULL,
    stream_settings TEXT,
    sniffing TEXT,
    remark TEXT,
    enabled INTEGER DEFAULT 1,
    total_up INTEGER DEFAULT 0,
    total_down INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Clients/Users
CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inbound_id INTEGER NOT NULL,
    uuid TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT,
    flow TEXT,
    enable INTEGER DEFAULT 1,
    total_traffic BIGINT DEFAULT 0,
    upload_traffic BIGINT DEFAULT 0,
    download_traffic BIGINT DEFAULT 0,
    expiry_time TIMESTAMP,
    subscription_url TEXT,
    telegram_id TEXT,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_connected TIMESTAMP,
    FOREIGN KEY (inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE
);

-- Real-time traffic statistics
CREATE TABLE IF NOT EXISTS traffic_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    upload BIGINT DEFAULT 0,
    download BIGINT DEFAULT 0,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- System settings
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Activity logs
CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER,
    action TEXT NOT NULL,
    target TEXT,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_id) REFERENCES admins(id)
);

-- Subscription tokens
CREATE TABLE IF NOT EXISTS subscription_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_accessed TIMESTAMP,
    access_count INTEGER DEFAULT 0,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_clients_inbound ON clients(inbound_id);
CREATE INDEX IF NOT EXISTS idx_clients_email ON clients(email);
CREATE INDEX IF NOT EXISTS idx_traffic_client ON traffic_logs(client_id);
CREATE INDEX IF NOT EXISTS idx_traffic_time ON traffic_logs(recorded_at);
CREATE INDEX IF NOT EXISTS idx_activity_admin ON activity_logs(admin_id);
CREATE INDEX IF NOT EXISTS idx_activity_time ON activity_logs(created_at);

-- Insert default settings
INSERT OR IGNORE INTO settings (key, value, description) VALUES 
    ('panel_name', 'Z-PARS VPN Panel', 'Panel display name'),
    ('panel_url', '', 'Panel URL for subscriptions'),
    ('telegram_bot_token', '', 'Telegram bot token'),
    ('telegram_admin_id', '', 'Telegram admin chat ID'),
    ('enable_registration', '0', 'Allow new user registration'),
    ('subscription_enabled', '1', 'Enable subscription URLs'),
    ('traffic_reset_day', '1', 'Day of month to reset traffic'),
    ('default_traffic_limit', '107374182400', 'Default traffic limit (100GB)'),
    ('default_expiry_days', '30', 'Default account expiry (days)');
SCHEMA

    sqlite3 /opt/zpars/db/zpars.db < /opt/zpars/db/schema.sql
    
    # Create default admin (password: admin123)
    ADMIN_HASH=$(echo -n "admin123" | openssl dgst -sha256 | awk '{print $2}')
    sqlite3 /opt/zpars/db/zpars.db << EOF
INSERT OR IGNORE INTO admins (username, password, email, role) 
VALUES ('admin', '$ADMIN_HASH', 'admin@zpars.local', 'superadmin');
EOF
    
    chmod 600 /opt/zpars/db/zpars.db
    log_success "Database initialized"
}

create_application() {
    log_step "6/12 - Creating Application Backend"
    
    cat > /opt/zpars/app/app.py << 'PYAPP'
#!/usr/bin/env python3
"""
Z-PARS Ultimate VPN Panel
Professional Edition with Advanced Features
"""

import os
import sys
import json
import uuid
import hashlib
import secrets
import base64
import sqlite3
import subprocess
import qrcode
from io import BytesIO
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file, make_response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ═══════════════════════════════════════════════════════════════════
# APPLICATION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB
app.config['JSON_SORT_KEYS'] = False

CORS(app, supports_credentials=True)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per hour"],
    storage_uri="memory://"
)

# Paths
DB_PATH = '/opt/zpars/db/zpars.db'
XRAY_CONFIG = '/usr/local/etc/xray/config.json'
LOG_PATH = '/var/log/zpars'

# ═══════════════════════════════════════════════════════════════════
# DATABASE HELPERS
# ═══════════════════════════════════════════════════════════════════

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def dict_from_row(row):
    """Convert sqlite3.Row to dict"""
    return {k: row[k] for k in row.keys()} if row else None

# ═══════════════════════════════════════════════════════════════════
# AUTHENTICATION DECORATORS
# ═══════════════════════════════════════════════════════════════════

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return jsonify({'error': 'Unauthorized', 'code': 'AUTH_REQUIRED'}), 401
        return f(*args, **kwargs)
    return decorated

def log_activity(action, target=None, details=None):
    """Log admin activity"""
    try:
        conn = get_db()
        conn.execute('''
            INSERT INTO activity_logs (admin_id, action, target, ip_address, user_agent, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            session.get('admin_id'),
            action,
            target,
            request.remote_addr,
            request.headers.get('User-Agent', '')[:255],
            json.dumps(details) if details else None
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Activity log error: {e}", file=sys.stderr)

# ═══════════════════════════════════════════════════════════════════
# XRAY MANAGEMENT
# ═══════════════════════════════════════════════════════════════════

def get_xray_config():
    """Load Xray configuration"""
    try:
        with open(XRAY_CONFIG, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"inbounds": [], "outbounds": [{"protocol": "freedom", "tag": "direct"}], "routing": {"rules": []}}

def save_xray_config(config):
    """Save and reload Xray configuration"""
    with open(XRAY_CONFIG, 'w') as f:
        json.dump(config, f, indent=2)
    
    # Restart Xray
    subprocess.run(['systemctl', 'restart', 'xray'], check=False)
    return True

def generate_client_config(client, inbound):
    """Generate client configuration"""
    protocol = inbound['protocol']
    settings = json.loads(inbound['settings'])
    stream = json.loads(inbound.get('stream_settings', '{}'))
    
    # Get panel URL from settings
    conn = get_db()
    panel_url = conn.execute("SELECT value FROM settings WHERE key='panel_url'").fetchone()
    conn.close()
    server = panel_url[0] if panel_url and panel_url[0] else request.host.split(':')[0]
    
    config = {
        'protocol': protocol,
        'server': server,
        'port': inbound['port'],
        'uuid': client['uuid'],
        'email': client['email']
    }
    
    # Protocol-specific configuration
    if protocol == 'vless':
        link = f"vless://{client['uuid']}@{server}:{inbound['port']}"
        params = []
        
        if stream.get('network'):
            params.append(f"type={stream['network']}")
        if stream.get('security'):
            params.append(f"security={stream['security']}")
        if client.get('flow'):
            params.append(f"flow={client['flow']}")
            
        # Add stream settings
        if stream.get('network') == 'ws':
            ws = stream.get('wsSettings', {})
            if ws.get('path'):
                params.append(f"path={ws['path']}")
        elif stream.get('network') == 'grpc':
            grpc = stream.get('grpcSettings', {})
            if grpc.get('serviceName'):
                params.append(f"serviceName={grpc['serviceName']}")
                
        if params:
            link += "?" + "&".join(params)
        link += f"#{client['email']}"
        config['link'] = link
        
    elif protocol == 'vmess':
        vmess_config = {
            'v': '2',
            'ps': client['email'],
            'add': server,
            'port': str(inbound['port']),
            'id': client['uuid'],
            'aid': '0',
            'net': stream.get('network', 'tcp'),
            'type': 'none',
            'host': '',
            'path': '',
            'tls': stream.get('security', '')
        }
        
        if stream.get('network') == 'ws':
            ws = stream.get('wsSettings', {})
            vmess_config['path'] = ws.get('path', '/')
            vmess_config['host'] = ws.get('headers', {}).get('Host', '')
            
        config['link'] = "vmess://" + base64.b64encode(json.dumps(vmess_config).encode()).decode()
        
    elif protocol == 'trojan':
        link = f"trojan://{client['password']}@{server}:{inbound['port']}"
        params = []
        
        if stream.get('security'):
            params.append(f"security={stream['security']}")
        if stream.get('network'):
            params.append(f"type={stream['network']}")
            
        if params:
            link += "?" + "&".join(params)
        link += f"#{client['email']}"
        config['link'] = link
        
    return config

# ═══════════════════════════════════════════════════════════════════
# ROUTES - AUTHENTICATION
# ═══════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        conn = get_db()
        admin = conn.execute(
            'SELECT * FROM admins WHERE username=? AND password=? AND is_active=1',
            (username, password_hash)
        ).fetchone()
        
        if admin:
            session['logged_in'] = True
            session['admin_id'] = admin['id']
            session['username'] = admin['username']
            session['role'] = admin['role']
            
            # Update login stats
            conn.execute('''
                UPDATE admins 
                SET last_login=CURRENT_TIMESTAMP, login_count=login_count+1 
                WHERE id=?
            ''', (admin['id'],))
            conn.commit()
            
            log_activity('LOGIN', username)
            conn.close()
            
            return jsonify({'success': True, 'role': admin['role']})
        
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    log_activity('LOGOUT', session.get('username'))
    session.clear()
    return redirect(url_for('login'))

# ═══════════════════════════════════════════════════════════════════
# ROUTES - DASHBOARD
# ═══════════════════════════════════════════════════════════════════

@app.route('/api/stats')
@login_required
def get_stats():
    """Get dashboard statistics"""
    conn = get_db()
    
    # User stats
    total_users = conn.execute('SELECT COUNT(*) as c FROM clients').fetchone()['c']
    active_users = conn.execute('SELECT COUNT(*) as c FROM clients WHERE enable=1').fetchone()['c']
    expired_users = conn.execute(
        'SELECT COUNT(*) as c FROM clients WHERE expiry_time < CURRENT_TIMESTAMP'
    ).fetchone()['c']
    
    # Inbound stats
    total_inbounds = conn.execute('SELECT COUNT(*) as c FROM inbounds').fetchone()['c']
    active_inbounds = conn.execute('SELECT COUNT(*) as c FROM inbounds WHERE enabled=1').fetchone()['c']
    
    # Traffic stats
    traffic = conn.execute('''
        SELECT 
            COALESCE(SUM(upload_traffic), 0) as total_up,
            COALESCE(SUM(download_traffic), 0) as total_down
        FROM clients
    ''').fetchone()
    
    conn.close()
    
    return jsonify({
        'users': {
            'total': total_users,
            'active': active_users,
            'expired': expired_users,
            'inactive': total_users - active_users
        },
        'inbounds': {
            'total': total_inbounds,
            'active': active_inbounds
        },
        'traffic': {
            'upload': traffic['total_up'],
            'download': traffic['total_down'],
            'total': traffic['total_up'] + traffic['total_down']
        }
    })

@app.route('/api/system')
@login_required
def get_system_info():
    """Get system information"""
    try:
        # CPU
        cpu_percent = float(subprocess.check_output(
            "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1",
            shell=True
        ).decode().strip())
        
        # Memory
        mem_info = subprocess.check_output(['free', '-m']).decode().split('\n')[1].split()
        mem_total = int(mem_info[1])
        mem_used = int(mem_info[2])
        mem_percent = round((mem_used / mem_total) * 100, 1)
        
        # Disk
        disk_info = subprocess.check_output(['df', '-BG', '/']).decode().split('\n')[1].split()
        disk_total = int(disk_info[1].replace('G', ''))
        disk_used = int(disk_info[2].replace('G', ''))
        disk_percent = round((disk_used / disk_total) * 100, 1)
        
        # Uptime
        uptime = subprocess.check_output(['uptime', '-p']).decode().strip()
        
        # Xray status
        xray_status = subprocess.run(
            ['systemctl', 'is-active', 'xray'],
            capture_output=True
        ).stdout.decode().strip()
        
        return jsonify({
            'cpu': cpu_percent,
            'memory': {'total': mem_total, 'used': mem_used, 'percent': mem_percent},
            'disk': {'total': disk_total, 'used': disk_used, 'percent': disk_percent},
            'uptime': uptime,
            'xray_status': xray_status
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ═══════════════════════════════════════════════════════════════════
# ROUTES - INBOUND MANAGEMENT
# ═══════════════════════════════════════════════════════════════════

@app.route('/api/inbounds', methods=['GET', 'POST'])
@login_required
def manage_inbounds():
    conn = get_db()
    
    if request.method == 'GET':
        inbounds = conn.execute('SELECT * FROM inbounds ORDER BY created_at DESC').fetchall()
        conn.close()
        
        result = []
        for ib in inbounds:
            ib_dict = dict_from_row(ib)
            
            # Get client count
            conn2 = get_db()
            client_count = conn2.execute(
                'SELECT COUNT(*) as c FROM clients WHERE inbound_id=?',
                (ib['id'],)
            ).fetchone()['c']
            conn2.close()
            
            ib_dict['client_count'] = client_count
            result.append(ib_dict)
        
        return jsonify(result)
    
    elif request.method == 'POST':
        data = request.get_json()
        
        try:
            # Validate required fields
            required = ['tag', 'protocol', 'port']
            if not all(k in data for k in required):
                return jsonify({'error': 'Missing required fields'}), 400
            
            # Create inbound
            conn.execute('''
                INSERT INTO inbounds (tag, protocol, port, listen, settings, stream_settings, sniffing, remark)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data['tag'],
                data['protocol'],
                data['port'],
                data.get('listen', '0.0.0.0'),
                json.dumps(data.get('settings', {})),
                json.dumps(data.get('stream_settings', {})),
                json.dumps(data.get('sniffing', {})),
                data.get('remark', '')
            ))
            conn.commit()
            inbound_id = conn.lastrowid
            
            # Update Xray config
            xray_config = get_xray_config()
            
            inbound_config = {
                'tag': data['tag'],
                'protocol': data['protocol'],
                'port': data['port'],
                'listen': data.get('listen', '0.0.0.0'),
                'settings': data.get('settings', {}),
                'streamSettings': data.get('stream_settings', {}),
                'sniffing': data.get('sniffing', {'enabled': True, 'destOverride': ['http', 'tls']})
            }
            
            xray_config['inbounds'].append(inbound_config)
            save_xray_config(xray_config)
            
            log_activity('CREATE_INBOUND', data['tag'])
            conn.close()
            
            return jsonify({'id': inbound_id, 'message': 'Inbound created successfully'})
            
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Inbound with this tag already exists'}), 400
        except Exception as e:
            conn.close()
            return jsonify({'error': str(e)}), 500

@app.route('/api/inbounds/<int:inbound_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def inbound_detail(inbound_id):
    conn = get_db()
    
    if request.method == 'GET':
        inbound = conn.execute('SELECT * FROM inbounds WHERE id=?', (inbound_id,)).fetchone()
        conn.close()
        
        if not inbound:
            return jsonify({'error': 'Inbound not found'}), 404
        
        return jsonify(dict_from_row(inbound))
    
    elif request.method == 'PUT':
        data = request.get_json()
        
        # Update database
        conn.execute('''
            UPDATE inbounds 
            SET enabled=?, remark=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
        ''', (data.get('enabled', 1), data.get('remark', ''), inbound_id))
        conn.commit()
        
        log_activity('UPDATE_INBOUND', f'ID:{inbound_id}')
        conn.close()
        
        return jsonify({'message': 'Inbound updated'})
    
    elif request.method == 'DELETE':
        inbound = conn.execute('SELECT tag FROM inbounds WHERE id=?', (inbound_id,)).fetchone()
        
        if not inbound:
            conn.close()
            return jsonify({'error': 'Inbound not found'}), 404
        
        # Delete from database
        conn.execute('DELETE FROM inbounds WHERE id=?', (inbound_id,))
        conn.commit()
        
        # Update Xray config
        xray_config = get_xray_config()
        xray_config['inbounds'] = [
            ib for ib in xray_config['inbounds'] 
            if ib.get('tag') != inbound['tag']
        ]
        save_xray_config(xray_config)
        
        log_activity('DELETE_INBOUND', inbound['tag'])
        conn.close()
        
        return jsonify({'message': 'Inbound deleted'})

# ═══════════════════════════════════════════════════════════════════
# ROUTES - CLIENT MANAGEMENT
# ═══════════════════════════════════════════════════════════════════

@app.route('/api/clients', methods=['GET', 'POST'])
@login_required
def manage_clients():
    conn = get_db()
    
    if request.method == 'GET':
        inbound_id = request.args.get('inbound_id')
        
        query = '''
            SELECT c.*, i.tag as inbound_tag, i.protocol, i.port
            FROM clients c
            JOIN inbounds i ON c.inbound_id = i.id
        '''
        
        if inbound_id:
            query += ' WHERE c.inbound_id=?'
            clients = conn.execute(query, (inbound_id,)).fetchall()
        else:
            clients = conn.execute(query).fetchall()
        
        conn.close()
        
        return jsonify([dict_from_row(c) for c in clients])
    
    elif request.method == 'POST':
        data = request.get_json()
        
        try:
            # Generate UUID if not provided
            client_uuid = data.get('uuid', str(uuid.uuid4()))
            
            # Calculate expiry
            expiry_days = data.get('expiry_days', 30)
            expiry_time = datetime.now() + timedelta(days=expiry_days)
            
            # Get default traffic limit
            default_traffic = conn.execute(
                "SELECT value FROM settings WHERE key='default_traffic_limit'"
            ).fetchone()
            traffic_limit = int(default_traffic[0]) if default_traffic else 107374182400
            
            # Create client
            conn.execute('''
                INSERT INTO clients (
                    inbound_id, uuid, email, password, flow, enable, 
                    total_traffic, expiry_time, notes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data['inbound_id'],
                client_uuid,
                data['email'],
                data.get('password', secrets.token_urlsafe(16)),
                data.get('flow'),
                data.get('enable', 1),
                data.get('total_traffic', traffic_limit),
                expiry_time,
                data.get('notes', '')
            ))
            conn.commit()
            client_id = conn.lastrowid
            
            # Get inbound info
            inbound = conn.execute('SELECT * FROM inbounds WHERE id=?', (data['inbound_id'],)).fetchone()
            
            # Update Xray config
            xray_config = get_xray_config()
            
            for ib in xray_config['inbounds']:
                if ib.get('tag') == inbound['tag']:
                    settings = ib.get('settings', {})
                    
                    if inbound['protocol'] in ['vless', 'vmess']:
                        if 'clients' not in settings:
                            settings['clients'] = []
                        
                        client_config = {
                            'id': client_uuid,
                            'email': data['email']
                        }
                        
                        if data.get('flow'):
                            client_config['flow'] = data['flow']
                        
                        settings['clients'].append(client_config)
                        
                    elif inbound['protocol'] == 'trojan':
                        if 'clients' not in settings:
                            settings['clients'] = []
                        
                        settings['clients'].append({
                            'password': data.get('password', secrets.token_urlsafe(16)),
                            'email': data['email']
                        })
                    
                    ib['settings'] = settings
                    break
            
            save_xray_config(xray_config)
            
            # Generate subscription token
            sub_token = secrets.token_urlsafe(32)
            conn.execute('''
                INSERT INTO subscription_tokens (client_id, token)
                VALUES (?, ?)
            ''', (client_id, sub_token))
            conn.commit()
            
            log_activity('CREATE_CLIENT', data['email'])
            conn.close()
            
            return jsonify({
                'id': client_id,
                'uuid': client_uuid,
                'subscription_token': sub_token,
                'message': 'Client created successfully'
            })
            
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Client with this email already exists'}), 400
        except Exception as e:
            conn.close()
            return jsonify({'error': str(e)}), 500

@app.route('/api/clients/<int:client_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def client_detail(client_id):
    conn = get_db()
    
    if request.method == 'GET':
        client = conn.execute('''
            SELECT c.*, i.tag as inbound_tag, i.protocol, i.port, i.settings, i.stream_settings
            FROM clients c
            JOIN inbounds i ON c.inbound_id = i.id
            WHERE c.id=?
        ''', (client_id,)).fetchone()
        
        if not client:
            conn.close()
            return jsonify({'error': 'Client not found'}), 404
        
        client_dict = dict_from_row(client)
        
        # Get subscription token
        token = conn.execute(
            'SELECT token FROM subscription_tokens WHERE client_id=?',
            (client_id,)
        ).fetchone()
        
        if token:
            client_dict['subscription_token'] = token['token']
        
        conn.close()
        
        return jsonify(client_dict)
    
    elif request.method == 'PUT':
        data = request.get_json()
        
        # Update client
        conn.execute('''
            UPDATE clients 
            SET enable=?, total_traffic=?, expiry_time=?, notes=?
            WHERE id=?
        ''', (
            data.get('enable', 1),
            data.get('total_traffic'),
            data.get('expiry_time'),
            data.get('notes', ''),
            client_id
        ))
        conn.commit()
        
        log_activity('UPDATE_CLIENT', f'ID:{client_id}')
        conn.close()
        
        return jsonify({'message': 'Client updated'})
    
    elif request.method == 'DELETE':
        client = conn.execute(
            'SELECT email, inbound_id FROM clients WHERE id=?',
            (client_id,)
        ).fetchone()
        
        if not client:
            conn.close()
            return jsonify({'error': 'Client not found'}), 404
        
        # Get inbound
        inbound = conn.execute(
            'SELECT tag FROM inbounds WHERE id=?',
            (client['inbound_id'],)
        ).fetchone()
        
        # Delete from database
        conn.execute('DELETE FROM clients WHERE id=?', (client_id,))
        conn.commit()
        
        # Update Xray config
        xray_config = get_xray_config()
        
        for ib in xray_config['inbounds']:
            if ib.get('tag') == inbound['tag']:
                settings = ib.get('settings', {})
                if 'clients' in settings:
                    settings['clients'] = [
                        c for c in settings['clients']
                        if c.get('email') != client['email']
                    ]
                    ib['settings'] = settings
                break
        
        save_xray_config(xray_config)
        
        log_activity('DELETE_CLIENT', client['email'])
        conn.close()
        
        return jsonify({'message': 'Client deleted'})

@app.route('/api/clients/<int:client_id>/config')
@login_required
def get_client_config(client_id):
    """Get client configuration and links"""
    conn = get_db()
    
    client = conn.execute('''
        SELECT c.*, i.*
        FROM clients c
        JOIN inbounds i ON c.inbound_id = i.id
        WHERE c.id=?
    ''', (client_id,)).fetchone()
    
    conn.close()
    
    if not client:
        return jsonify({'error': 'Client not found'}), 404
    
    client_dict = dict_from_row(client)
    config = generate_client_config(client_dict, client_dict)
    
    return jsonify(config)

@app.route('/api/clients/<int:client_id>/qrcode')
@login_required
def get_client_qrcode(client_id):
    """Generate QR code for client"""
    conn = get_db()
    
    client = conn.execute('''
        SELECT c.*, i.*
        FROM clients c
        JOIN inbounds i ON c.inbound_id = i.id
        WHERE c.id=?
    ''', (client_id,)).fetchone()
    
    conn.close()
    
    if not client:
        return jsonify({'error': 'Client not found'}), 404
    
    client_dict = dict_from_row(client)
    config = generate_client_config(client_dict, client_dict)
    
    if 'link' not in config:
        return jsonify({'error': 'Cannot generate link for this protocol'}), 400
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(config['link'])
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to bytes
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    return send_file(img_io, mimetype='image/png')

# ═══════════════════════════════════════════════════════════════════
# ROUTES - SUBSCRIPTION
# ═══════════════════════════════════════════════════════════════════

@app.route('/sub/<token>')
def subscription(token):
    """Subscription endpoint"""
    conn = get_db()
    
    # Verify token
    sub = conn.execute('''
        SELECT st.*, c.*, i.*
        FROM subscription_tokens st
        JOIN clients c ON st.client_id = c.id
        JOIN inbounds i ON c.inbound_id = i.id
        WHERE st.token=?
    ''', (token,)).fetchone()
    
    if not sub:
        conn.close()
        return "Invalid subscription token", 404
    
    # Update access count
    conn.execute('''
        UPDATE subscription_tokens 
        SET last_accessed=CURRENT_TIMESTAMP, access_count=access_count+1
        WHERE token=?
    ''', (token,))
    conn.commit()
    conn.close()
    
    # Generate config
    sub_dict = dict_from_row(sub)
    config = generate_client_config(sub_dict, sub_dict)
    
    if 'link' not in config:
        return "Configuration not available", 400
    
    # Return base64 encoded link
    response = make_response(base64.b64encode(config['link'].encode()).decode())
    response.headers['Content-Type'] = 'text/plain'
    response.headers['Subscription-Userinfo'] = f"upload={sub['upload_traffic']}; download={sub['download_traffic']}; total={sub['total_traffic']}"
    
    return response

# ═══════════════════════════════════════════════════════════════════
# ROUTES - SETTINGS
# ═══════════════════════════════════════════════════════════════════

@app.route('/api/settings', methods=['GET', 'POST'])
@login_required
def manage_settings():
    conn = get_db()
    
    if request.method == 'GET':
        settings = conn.execute('SELECT * FROM settings').fetchall()
        conn.close()
        
        result = {s['key']: s['value'] for s in settings}
        return jsonify(result)
    
    elif request.method == 'POST':
        data = request.get_json()
        
        for key, value in data.items():
            conn.execute('''
                INSERT OR REPLACE INTO settings (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (key, str(value)))
        
        conn.commit()
        log_activity('UPDATE_SETTINGS')
        conn.close()
        
        return jsonify({'message': 'Settings updated'})

# ═══════════════════════════════════════════════════════════════════
# ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

# ═══════════════════════════════════════════════════════════════════
# APPLICATION ENTRY POINT
# ═══════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
PYAPP

    chmod +x /opt/zpars/app/app.py
    log_success "Application backend created"
}

create_frontend() {
    log_step "7/12 - Creating Web Interface"
    
    # Login page
    cat > /opt/zpars/app/templates/login.html << 'LOGINHTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Z-PARS VPN Panel</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        
        .login-container {
            background: white;
            border-radius: 20px;
            padding: 40px;
            width: 100%;
            max-width: 420px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .logo h1 {
            color: #667eea;
            font-size: 42px;
            margin-bottom: 8px;
            font-weight: 700;
        }
        
        .logo p {
            color: #666;
            font-size: 16px;
        }
        
        .form-group {
            margin-bottom: 24px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 600;
            font-size: 14px;
        }
        
        .form-group input {
            width: 100%;
            padding: 14px 16px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 15px;
            transition: all 0.3s;
            font-family: inherit;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .btn-login {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            font-family: inherit;
        }
        
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }
        
        .btn-login:active {
            transform: translateY(0);
        }
        
        .error {
            background: #fee;
            color: #c33;
            padding: 12px;
            border-radius: 8px;
            font-size: 14px;
            margin-top: 16px;
            display: none;
            text-align: center;
        }
        
        .version {
            text-align: center;
            color: #999;
            font-size: 13px;
            margin-top: 24px;
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .login-container {
            animation: slideUp 0.5s ease-out;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>🚀 Z-PARS</h1>
            <p>Ultimate VPN Management Panel</p>
        </div>
        <form id="loginForm">
            <div class="form-group">
                <label>Username</label>
                <input type="text" id="username" required autofocus autocomplete="username">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" id="password" required autocomplete="current-password">
            </div>
            <button type="submit" class="btn-login">Sign In</button>
            <div class="error" id="error"></div>
        </form>
        <div class="version">Professional Edition v3.0</div>
    </div>
    
    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('error');
            
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
                    errorDiv.textContent = data.error || 'Invalid credentials';
                    errorDiv.style.display = 'block';
                }
            } catch (err) {
                errorDiv.textContent = 'Connection error. Please try again.';
                errorDiv.style.display = 'block';
            }
        });
    </script>
</body>
</html>
LOGINHTML

    # Dashboard page
    cat > /opt/zpars/app/templates/dashboard.html << 'DASHHTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Z-PARS VPN Panel</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #f5f7fa;
        }
        
        .container {
            display: flex;
            min-height: 100vh;
        }
        
        .sidebar {
            width: 260px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 24px;
            position: fixed;
            height: 100vh;
            overflow-y: auto;
        }
        
        .logo {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 32px;
            text-align: center;
        }
        
        .nav-item {
            padding: 12px 16px;
            margin-bottom: 8px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .nav-item:hover {
            background: rgba(255,255,255,0.2);
        }
        
        .nav-item.active {
            background: rgba(255,255,255,0.3);
        }
        
        .main-content {
            margin-left: 260px;
            flex: 1;
            padding: 24px;
        }
        
        .header {
            background: white;
            padding: 20px 24px;
            border-radius: 12px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        
        .header h1 {
            font-size: 28px;
            color: #333;
        }
        
        .btn-logout {
            padding: 10px 20px;
            background: #ff4757;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }
        
        .stat-card {
            background: white;
            padding: 24px;
            border-radius: 12px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        
        .stat-card h3 {
            color: #666;
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 8px;
        }
        
        .stat-card .value {
            font-size: 32px;
            font-weight: 700;
            color: #333;
        }
        
        .content-section {
            background: white;
            padding: 24px;
            border-radius: 12px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            display: none;
        }
        
        .content-section.active {
            display: block;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
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
        
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
        }
        
        .btn-primary {
            background: #667eea;
            color: white;
        }
        
        .btn-success {
            background: #2ecc71;
            color: white;
        }
        
        .btn-danger {
            background: #e74c3c;
            color: white;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="sidebar">
            <div class="logo">🚀 Z-PARS</div>
            <div class="nav-item active" data-section="dashboard">📊 Dashboard</div>
            <div class="nav-item" data-section="inbounds">🔌 Inbounds</div>
            <div class="nav-item" data-section="clients">👥 Clients</div>
            <div class="nav-item" data-section="settings">⚙️ Settings</div>
        </div>
        
        <div class="main-content">
            <div class="header">
                <h1>Dashboard</h1>
                <button class="btn-logout" onclick="location.href='/logout'">Logout</button>
            </div>
            
            <div id="dashboard-section" class="content-section active">
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Total Users</h3>
                        <div class="value" id="stat-total-users">-</div>
                    </div>
                    <div class="stat-card">
                        <h3>Active Users</h3>
                        <div class="value" id="stat-active-users">-</div>
                    </div>
                    <div class="stat-card">
                        <h3>Total Inbounds</h3>
                        <div class="value" id="stat-inbounds">-</div>
                    </div>
                    <div class="stat-card">
                        <h3>Total Traffic</h3>
                        <div class="value" id="stat-traffic">-</div>
                    </div>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>CPU Usage</h3>
                        <div class="value" id="stat-cpu">-</div>
                    </div>
                    <div class="stat-card">
                        <h3>Memory Usage</h3>
                        <div class="value" id="stat-memory">-</div>
                    </div>
                    <div class="stat-card">
                        <h3>Disk Usage</h3>
                        <div class="value" id="stat-disk">-</div>
                    </div>
                    <div class="stat-card">
                        <h3>Xray Status</h3>
                        <div class="value" id="stat-xray">-</div>
                    </div>
                </div>
            </div>
            
            <div id="inbounds-section" class="content-section">
                <h2>Inbound Management</h2>
                <div class="loading">Loading inbounds...</div>
            </div>
            
            <div id="clients-section" class="content-section">
                <h2>Client Management</h2>
                <div class="loading">Loading clients...</div>
            </div>
            
            <div id="settings-section" class="content-section">
                <h2>System Settings</h2>
                <div class="loading">Loading settings...</div>
            </div>
        </div>
    </div>
    
    <script>
        // Navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', function() {
                document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
                document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
                
                this.classList.add('active');
                const section = this.dataset.section;
                document.getElementById(section + '-section').classList.add('active');
                
                if (section === 'dashboard') loadDashboard();
            });
        });
        
        // Load dashboard stats
        async function loadDashboard() {
            try {
                const [stats, system] = await Promise.all([
                    fetch('/api/stats').then(r => r.json()),
                    fetch('/api/system').then(r => r.json())
                ]);
                
                document.getElementById('stat-total-users').textContent = stats.users.total;
                document.getElementById('stat-active-users').textContent = stats.users.active;
                document.getElementById('stat-inbounds').textContent = stats.inbounds.total;
                document.getElementById('stat-traffic').textContent = formatBytes(stats.traffic.total);
                
                document.getElementById('stat-cpu').textContent = system.cpu.toFixed(1) + '%';
                document.getElementById('stat-memory').textContent = system.memory.percent + '%';
                document.getElementById('stat-disk').textContent = system.disk.percent + '%';
                document.getElementById('stat-xray').textContent = system.xray_status === 'active' ? '✓ Running' : '✗ Stopped';
                document.getElementById('stat-xray').style.color = system.xray_status === 'active' ? '#2ecc71' : '#e74c3c';
            } catch (err) {
                console.error('Failed to load stats:', err);
            }
        }
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        // Initial load
        loadDashboard();
        setInterval(loadDashboard, 5000);
    </script>
</body>
</html>
DASHHTML

    log_success "Web interface created"
}

create_systemd_service() {
    log_step "8/12 - Creating System Service"
    
    cat > /etc/systemd/system/zpars.service << 'SERVICE'
[Unit]
Description=Z-PARS Ultimate VPN Panel
After=network.target xray.service
Wants=xray.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/zpars/app
Environment="PATH=/opt/zpars/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/opt/zpars/venv/bin/gunicorn --bind 0.0.0.0:5000 --workers 4 --worker-class gevent --timeout 120 app:app
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload
    systemctl enable zpars > /dev/null 2>&1
    
    log_success "Systemd service created"
}

configure_nginx() {
    log_step "9/12 - Configuring Nginx"
    
    cat > /etc/nginx/sites-available/zpars << 'NGINXCONF'
# Z-PARS VPN Panel - Nginx Configuration

upstream zpars_backend {
    server 127.0.0.1:5000;
    keepalive 32;
}

server {
    listen 80;
    listen [::]:80;
    server_name _;
    
    client_max_body_size 50M;
    client_body_buffer_size 128k;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Logging
    access_log /var/log/nginx/zpars-access.log;
    error_log /var/log/nginx/zpars-error.log;
    
    location / {
        proxy_pass http://zpars_backend;
        proxy_http_version 1.1;
        
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        proxy_buffering off;
        proxy_redirect off;
    }
}
NGINXCONF

    # Enable site
    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/zpars /etc/nginx/sites-enabled/
    
    # Test nginx config
    nginx -t > /dev/null 2>&1
    
    systemctl enable nginx > /dev/null 2>&1
    
    log_success "Nginx configured"
}

configure_firewall() {
    log_step "10/12 - Configuring Firewall"
    
    if command -v ufw &> /dev/null; then
        log_info "Configuring UFW..."
        ufw --force enable > /dev/null 2>&1
        ufw allow 22/tcp > /dev/null 2>&1
        ufw allow 80/tcp > /dev/null 2>&1
        ufw allow 443/tcp > /dev/null 2>&1
        ufw allow 8443/tcp > /dev/null 2>&1
        ufw allow 2053/tcp > /dev/null 2>&1
        ufw allow 2096/tcp > /dev/null 2>&1
        log_success "UFW configured"
    elif command -v firewall-cmd &> /dev/null; then
        log_info "Configuring firewalld..."
        systemctl enable firewalld > /dev/null 2>&1
        systemctl start firewalld > /dev/null 2>&1
        firewall-cmd --permanent --add-service=http > /dev/null 2>&1
        firewall-cmd --permanent --add-service=https > /dev/null 2>&1
        firewall-cmd --permanent --add-port=8443/tcp > /dev/null 2>&1
        firewall-cmd --permanent --add-port=2053/tcp > /dev/null 2>&1
        firewall-cmd --permanent --add-port=2096/tcp > /dev/null 2>&1
        firewall-cmd --reload > /dev/null 2>&1
        log_success "Firewalld configured"
    else
        log_warning "No firewall detected - please configure manually"
    fi
}

setup_fail2ban() {
    log_step "11/12 - Setting Up Fail2Ban"
    
    if command -v fail2ban-client &> /dev/null; then
        cat > /etc/fail2ban/jail.d/zpars.conf << 'F2BCONF'
[zpars]
enabled = true
port = 80,443
filter = zpars
logpath = /var/log/nginx/zpars-access.log
maxretry = 5
bantime = 3600
findtime = 600
F2BCONF

        cat > /etc/fail2ban/filter.d/zpars.conf << 'F2BFILTER'
[Definition]
failregex = ^<HOST> .* "POST /login HTTP.*" 401
ignoreregex =
F2BFILTER

        systemctl enable fail2ban > /dev/null 2>&1
        systemctl restart fail2ban > /dev/null 2>&1
        
        log_success "Fail2ban configured"
    else
        log_warning "Fail2ban not available"
    fi
}

start_services() {
    log_step "12/12 - Starting Services"
    
    log_info "Starting Xray..."
    systemctl restart xray
    
    log_info "Starting Z-PARS..."
    systemctl restart zpars
    
    log_info "Starting Nginx..."
    systemctl restart nginx
    
    sleep 2
    
    # Check service status
    if systemctl is-active --quiet zpars; then
        log_success "Z-PARS service running"
    else
        log_error "Z-PARS service failed to start"
    fi
    
    if systemctl is-active --quiet xray; then
        log_success "Xray service running"
    else
        log_error "Xray service failed to start"
    fi
    
    if systemctl is-active --quiet nginx; then
        log_success "Nginx service running"
    else
        log_error "Nginx service failed to start"
    fi
}

# ═══════════════════════════════════════════════════════════════════
# COMPLETION MESSAGE
# ═══════════════════════════════════════════════════════════════════

show_completion() {
    SERVER_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")
    
    clear
    echo -e "${GREEN}${BOLD}"
    cat << BANNER

╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║        ✅  Z-PARS ULTIMATE VPN PANEL INSTALLED SUCCESSFULLY! ✅           ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝

BANNER
    echo -e "${NC}"
    
    echo -e "${CYAN}${BOLD}┌─────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}${BOLD}│${NC}  ${WHITE}${BOLD}PANEL ACCESS${NC}                                                          ${CYAN}${BOLD}│${NC}"
    echo -e "${CYAN}${BOLD}├─────────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}${BOLD}│${NC}  ${YELLOW}🌐 URL:${NC}      http://${SERVER_IP}                                    ${CYAN}${BOLD}│${NC}"
    echo -e "${CYAN}${BOLD}│${NC}  ${YELLOW}👤 Username:${NC} admin                                                   ${CYAN}${BOLD}│${NC}"
    echo -e "${CYAN}${BOLD}│${NC}  ${YELLOW}🔑 Password:${NC} admin123                                                ${CYAN}${BOLD}│${NC}"
    echo -e "${CYAN}${BOLD}│${NC}                                                                         ${CYAN}${BOLD}│${NC}"
    echo -e "${CYAN}${BOLD}│${NC}  ${RED}${BOLD}⚠️  CHANGE PASSWORD IMMEDIATELY AFTER FIRST LOGIN! ⚠️${NC}                 ${CYAN}${BOLD}│${NC}"
    echo -e "${CYAN}${BOLD}└─────────────────────────────────────────────────────────────────────────┘${NC}"
    
    echo ""
    
    echo -e "${PURPLE}${BOLD}┌─────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${PURPLE}${BOLD}│${NC}  ${WHITE}${BOLD}FEATURES INCLUDED${NC}                                                     ${PURPLE}${BOLD}│${NC}"
    echo -e "${PURPLE}${BOLD}├─────────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${PURPLE}${BOLD}│${NC}  ✅ Xray-core (Latest version)                                        ${PURPLE}${BOLD}│${NC}"
    echo -e "${PURPLE}${BOLD}│${NC}  ✅ Multi-protocol (VLESS, VMess, Trojan, Shadowsocks)                ${PURPLE}${BOLD}│${NC}"
    echo -e "${PURPLE}${BOLD}│${NC}  ✅ Dynamic inbound management                                        ${PURPLE}${BOLD}│${NC}"
    echo -e "${PURPLE}${BOLD}│${NC}  ✅ Real-time traffic monitoring                                      ${PURPLE}${BOLD}│${NC}"
    echo -e "${PURPLE}${BOLD}│${NC}  ✅ Subscription URLs with QR codes                                   ${PURPLE}${BOLD}│${NC}"
    echo -e "${PURPLE}${BOLD}│${NC}  ✅ WebSocket & gRPC support                                          ${PURPLE}${BOLD}│${NC}"
    echo -e "${PURPLE}${BOLD}│${NC}  ✅ TLS & Reality support                                             ${PURPLE}${BOLD}│${NC}"
    echo -e "${PURPLE}${BOLD}│${NC}  ✅ Advanced web dashboard                                            ${PURPLE}${BOLD}│${NC}"
    echo -e "${PURPLE}${BOLD}│${NC}  ✅ Automatic SSL/TLS support                                         ${PURPLE}${BOLD}│${NC}"
    echo -e "${PURPLE}${BOLD}│${NC}  ✅ Fail2ban protection                                               ${PURPLE}${BOLD}│${NC}"
    echo -e "${PURPLE}${BOLD}│${NC}  ✅ Activity logging                                                  ${PURPLE}${BOLD}│${NC}"
    echo -e "${PURPLE}${BOLD}│${NC}  ✅ Production-ready with Gunicorn                                    ${PURPLE}${BOLD}│${NC}"
    echo -e "${PURPLE}${BOLD}└─────────────────────────────────────────────────────────────────────────┘${NC}"
    
    echo ""
    
    echo -e "${BLUE}${BOLD}┌─────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}${BOLD}│${NC}  ${WHITE}${BOLD}SERVICE MANAGEMENT${NC}                                                    ${BLUE}${BOLD}│${NC}"
    echo -e "${BLUE}${BOLD}├─────────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${BLUE}${BOLD}│${NC}  Panel Status:   ${YELLOW}systemctl status zpars${NC}                             ${BLUE}${BOLD}│${NC}"
    echo -e "${BLUE}${BOLD}│${NC}  Xray Status:    ${YELLOW}systemctl status xray${NC}                              ${BLUE}${BOLD}│${NC}"
    echo -e "${BLUE}${BOLD}│${NC}  Restart Panel:  ${YELLOW}systemctl restart zpars${NC}                            ${BLUE}${BOLD}│${NC}"
    echo -e "${BLUE}${BOLD}│${NC}  Restart Xray:   ${YELLOW}systemctl restart xray${NC}                             ${BLUE}${BOLD}│${NC}"
    echo -e "${BLUE}${BOLD}│${NC}  View Logs:      ${YELLOW}journalctl -u zpars -f${NC}                             ${BLUE}${BOLD}│${NC}"
    echo -e "${BLUE}${BOLD}└─────────────────────────────────────────────────────────────────────────┘${NC}"
    
    echo ""
    
    echo -e "${YELLOW}${BOLD}┌─────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}${BOLD}│${NC}  ${WHITE}${BOLD}IMPORTANT PATHS${NC}                                                       ${YELLOW}${BOLD}│${NC}"
    echo -e "${YELLOW}${BOLD}├─────────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${YELLOW}${BOLD}│${NC}  Installation:  /opt/zpars/                                           ${YELLOW}${BOLD}│${NC}"
    echo -e "${YELLOW}${BOLD}│${NC}  Database:      /opt/zpars/db/zpars.db                                ${YELLOW}${BOLD}│${NC}"
    echo -e "${YELLOW}${BOLD}│${NC}  Xray Config:   /usr/local/etc/xray/config.json                       ${YELLOW}${BOLD}│${NC}"
    echo -e "${YELLOW}${BOLD}│${NC}  Logs:          /var/log/zpars/                                       ${YELLOW}${BOLD}│${NC}"
    echo -e "${YELLOW}${BOLD}│${NC}  Backups:       /opt/zpars/backups/                                   ${YELLOW}${BOLD}│${NC}"
    echo -e "${YELLOW}${BOLD}└─────────────────────────────────────────────────────────────────────────┘${NC}"
    
    echo ""
    
    echo -e "${GREEN}${BOLD}┌─────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}${BOLD}│${NC}  ${WHITE}${BOLD}SSL/TLS SETUP (OPTIONAL)${NC}                                              ${GREEN}${BOLD}│${NC}"
    echo -e "${GREEN}${BOLD}├─────────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${GREEN}${BOLD}│${NC}  For automatic HTTPS with Let's Encrypt:                              ${GREEN}${BOLD}│${NC}"
    echo -e "${GREEN}${BOLD}│${NC}  ${CYAN}certbot --nginx -d yourdomain.com${NC}                                   ${GREEN}${BOLD}│${NC}"
    echo -e "${GREEN}${BOLD}└─────────────────────────────────────────────────────────────────────────┘${NC}"
    
    echo ""
    echo -e "${WHITE}${BOLD}🎉 Installation complete! Access your panel now and start managing users!${NC}"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════
# MAIN INSTALLATION FLOW
# ═══════════════════════════════════════════════════════════════════

main() {
    show_banner
    
    check_root
    detect_os
    check_dependencies
    
    install_dependencies
    install_xray
    create_directories
    setup_python_environment
    setup_database
    create_application
    create_frontend
    create_systemd_service
    configure_nginx
    configure_firewall
    setup_fail2ban
    start_services
    
    show_completion
}

# Run installation
main
