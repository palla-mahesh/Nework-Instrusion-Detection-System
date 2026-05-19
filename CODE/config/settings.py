"""
Advanced NIDS Configuration Settings
Pro Level Configuration with Tuning Parameters
"""

import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / 'logs'
REPORT_DIR = BASE_DIR / 'reports' / 'generated_reports'
MODEL_DIR = BASE_DIR / 'models'
STATIC_DIR = BASE_DIR / 'static'

# Ensure directories exist
for dir_path in [LOG_DIR, REPORT_DIR, MODEL_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# Network Interface Configuration
NETWORK_INTERFACE = 'eth0'  # Change to your interface
PROMISCUOUS_MODE = True
SNAPSHOT_LENGTH = 65535
PACKET_TIMEOUT = 0.5

# Detection Thresholds
THREAT_THRESHOLDS = {
    'low': 0.3,
    'medium': 0.6,
    'high': 0.8,
    'critical': 0.95
}

# Rate Limiting (packets per second)
RATE_LIMITS = {
    'icmp': 100,
    'tcp_syn': 200,
    'udp': 150,
    'http': 500
}

# Port Scan Detection
PORT_SCAN_THRESHOLD = 20  # ports in 10 seconds
SYN_FLOOD_THRESHOLD = 100  # SYN packets per second
DDOS_THRESHOLD = 1000  # packets per second

# Machine Learning Configuration
ML_CONFIG = {
    'model_type': 'isolation_forest',
    'contamination': 0.05,
    'n_estimators': 200,
    'max_samples': 'auto',
    'random_state': 42,
    'update_interval': 3600,  # Retrain every hour
    'feature_columns': [
        'packet_length', 'protocol', 'ttl', 'flags',
        'src_port', 'dst_port', 'packet_rate', 'bytes_per_sec'
    ]
}

# Alert Configuration
ALERT_CONFIG = {
    'email_enabled': False,
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'alerts@nids.local',
    'recipient_emails': ['admin@security.local'],
    'webhook_enabled': True,
    'webhook_url': 'http://localhost:8080/webhook',
    'sound_alert': True,
    'auto_block_ip': True,
    'block_duration': 300  # seconds
}

# Response Actions
RESPONSE_ACTIONS = {
    'low': ['log_only'],
    'medium': ['log', 'send_alert'],
    'high': ['log', 'send_alert', 'rate_limit'],
    'critical': ['log', 'send_alert', 'block_ip', 'notify_admin']
}

# Logging Configuration
LOGGING_CONFIG = {
    'threats_log': LOG_DIR / 'threats.log',
    'packets_log': LOG_DIR / 'packets.log',
    'max_log_size': 100 * 1024 * 1024,  # 100MB
    'backup_count': 5,
    'log_level': 'INFO'
}

# Web Dashboard Configuration
DASHBOARD_CONFIG = {
    'secret_key': 'your-secret-key-here-change-in-production',
    'debug': False,
    'host': '0.0.0.0',
    'port': 5000,
    'update_interval': 1000,  # milliseconds
    'max_alerts_display': 100
}

# Attack Signatures
SIGNATURES = {
    'ping_of_death': lambda p: p.get('icmp_type') == 8 and p.get('packet_length') > 65535,
    'smurf_attack': lambda p: p.get('icmp_type') == 8 and p.get('dst_ip') == '255.255.255.255',
    'land_attack': lambda p: p.get('src_ip') == p.get('dst_ip'),
    'syn_flood': lambda p: p.get('tcp_flags') == 'S',
    'nmap_scan': lambda p: p.get('tcp_flags') in ['S', 'F', 'X', 'N']
}

# IP Reputation (Blocked IPs)
BLOCKED_IPS = set()  # Will be loaded from file
ALLOWED_IPS = {'192.168.1.1', '127.0.0.1'}