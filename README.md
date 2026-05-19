# Nework-Instrusion-Detection-System
# 🛡️ Advanced Network Intrusion Detection System (NIDS)
Overview
The Advanced Network Intrusion Detection System (NIDS) is a sophisticated security solution designed to monitor network traffic in real-time, detect malicious activities, and automatically respond to cyber threats. This enterprise-grade system combines multiple detection methodologies including signature-based analysis, machine learning anomaly detection, behavioral analysis, and rate-based threat identification to provide comprehensive network security monitoring
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

An **enterprise-grade Network Intrusion Detection System** with real-time packet analysis, machine learning-based anomaly detection, automated threat response, and a beautiful web dashboard.

## 📋 Table of Contents
- [Features](#-features)
- [Architecture](#-architecture)
- [Technologies Used](#-technologies-used)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Detection Methods](#-detection-methods)
- [Screenshots](#-screenshots)
- [API Endpoints](#-api-endpoints)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

### 🔍 Real-time Packet Analysis
- Live packet capture using Scapy
- Support for TCP, UDP, ICMP, and IPv6 protocols
- Configurable packet filters
- High-performance packet processing queue

### 🧠 Multi-Layer Detection Engine
- **Signature-based Detection**: Known attack patterns (SQL Injection, Port Scan, etc.)
- **Anomaly Detection**: Isolation Forest ML algorithm
- **Behavioral Analysis**: Port scanning, connection tracking
- **Rate-based Detection**: DDoS, SYN flood, brute force attacks

### 🤖 Machine Learning Capabilities
- Isolation Forest for anomaly detection
- Real-time feature extraction
- Automatic model retraining
- Confidence scoring for detected threats

### 🚨 Alert Management
- Severity-based alerting (Low, Medium, High, Critical)
- Email notifications (SMTP)
- Webhook integrations (Slack, Teams, Discord)
- Desktop push notifications
- Audio alerts for critical threats

### 🛡️ Automated Response
- Automatic IP blocking via iptables
- Rate limiting for suspicious sources
- Configurable response actions per severity
- Blocked IP management

### 📊 Web Dashboard
- Real-time traffic statistics
- Live packet rate charts
- Attack distribution visualization
- Alert history with filtering
- System health monitoring
- WebSocket-based real-time updates

### 📈 Traffic Analysis
- Bandwidth utilization monitoring
- Protocol distribution analysis
- Top attackers identification
- Traffic pattern insights
- CSV export for reports

## 🏗️ Architecture
┌─────────────────────────────────────────────────────────────┐
│ Web Dashboard (Flask) │
│ Real-time Charts & Alerts │
└─────────────────────────────────────────────────────────────┘
▲
│ WebSocket
┌─────────────────────────────────────────────────────────────┐
│ Alert Manager │
│ (Email, Webhook, Desktop, Audio) │
└─────────────────────────────────────────────────────────────┘
▲
┌─────────────────────────────────────────────────────────────┐
│ Detection Engine │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │Signature │ │Anomaly │ │Behavioral│ │Rate-Based│ │
│ │Detection │ │Detection │ │Detection │ │Detection │ │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
└─────────────────────────────────────────────────────────────┘
▲
┌─────────────────────────────────────────────────────────────┐
│ Packet Sniffer │
│ (Scapy - Multi-threaded) │
└─────────────────────────────────────────────────────────────┘
▲
┌─────────────────────────────────────────────────────────────┐
│ Network Traffic │
│ (Live Capture/PCAP) │
└─────────────────────────────────────────────────────────────┘
text


## 💻 Technologies Used

- **Backend Framework**: Flask 2.3.3
- **Real-time Communication**: Flask-SocketIO, Eventlet
- **Packet Processing**: Scapy 2.5.0
- **Machine Learning**: Scikit-learn (Isolation Forest)
- **Data Processing**: Pandas, NumPy
- **Visualization**: Chart.js
- **Data Storage**: JSON logs, Joblib for ML models
- **Authentication**: Session-based (configurable)

## 📦 Installation

### Prerequisites

- Python 3.10 or higher
- pip package manager
- Network interface with capture permissions
- 4GB RAM minimum (8GB recommended)
- 1GB free disk space

### Windows Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/advanced-nids.git
cd advanced-nids

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Npcap for packet capture
# Download from: https://npcap.com

# Run the application
python app.py
🔍 Detection Methods
1. Signature-Based Detection

Detects known attack patterns using predefined signatures:

    SQL Injection (' OR '1'='1, UNION SELECT, etc.)

    Port scanning (multiple port connections)

    Ping of death (oversized ICMP packets)

    Land attack (same source/destination IP)

    Smurf attack (broadcast ICMP)

2. Anomaly Detection (ML)

Uses Isolation Forest algorithm to detect unusual traffic patterns:

    Unusual packet sizes

    Abnormal protocol usage

    Irregular timing patterns

    Statistical outliers

3. Behavioral Analysis

Monitors network behavior over time:

    Connection tracking

    Port scan detection (>20 ports in 10 seconds)

    Service probing patterns

    ARP spoofing detection

4. Rate-Based Detection

Identifies flood attacks:

    SYN flood (>100 SYN packets/sec)

    DDoS attack (>1000 packets/sec)

    ICMP flood (>100 ICMP packets/sec)

    HTTP request flooding
🔌 API Endpoints
Endpoint	Method	Description
/api/stats	GET	Get system statistics
/api/alerts	GET	Get recent alerts
/api/alerts?severity=critical	GET	Filter alerts by severity
/api/threats/summary	GET	Get threat summary
/api/traffic/analysis	GET	Traffic analysis
/api/blocked/ips	GET	List blocked IPs
/api/unblock/<ip>	POST	Unblock an IP
/api/clear-alerts	POST	Clear all alerts
/api/alerts/export	GET	Export alerts as CSV
WebSocket Events
Event	Direction	Description
stats_update	Server → Client	Real-time statistics
new_alert	Server → Client	New threat detected
request_stats	Client → Server	Request current stats
Project Structure:
advanced-nids/
│
├── app.py                      # Main application
├── requirements.txt            # Python dependencies
├── README.md                   # Documentation
│
├── core/                       # Core modules
│   ├── packet_sniffer.py      # Packet capture
│   ├── detection_engine.py    # Multi-layer detection
│   ├── ml_detector.py         # ML anomaly detection
│   ├── alert_manager.py       # Alert handling
│   ├── response_engine.py     # Automated responses
│   ├── traffic_analyzer.py    # Traffic analysis
│   └── utils.py               # Utilities
│
├── static/                     # Web assets
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   ├── dashboard.js
│   │   ├── alerts.js
│   │   └── charts.js
│   └── sounds/
│       └── alert.mp3
│
├── templates/                  # HTML templates
│   ├── index.html
│   ├── dashboard.html
│   └── alerts.html
│
├── logs/                       # Log files
│   ├── threats.log
│   └── packets.log
│
├── models/                     # ML models
│   └── anomaly_model.pkl
│
├── reports/                    # Generated reports
│   └── generated_reports/
│
└── config/                     # Configuration
    └── settings.py
📊 Performance Metrics

    Packet Processing: 10,000+ packets/second

    Alert Latency: < 100ms

    Memory Usage: ~200MB baseline

    CPU Usage: 5-15% (depending on traffic)

    ML Training Time: ~30 seconds (1000 packets)

🔒 Security Considerations

    Run with least privilege necessary

    Use HTTPS in production

    Implement authentication for web dashboard

    Regularly update ML models

    Monitor false positive rates

    Secure API endpoints with API keys

📝 License

This project is licensed under the MIT License - see the LICENSE file for details.
🙏 Acknowledgments

    Scapy team for packet manipulation library

    Scikit-learn for ML algorithms

    Flask and SocketIO teams for web framework

    All contributors and testers

Conclusion:

The Advanced Network Intrusion Detection System (NIDS) project successfully delivers a comprehensive, enterprise-grade security solution that effectively monitors network traffic, detects malicious activities in real-time, and provides automated response capabilities. This project demonstrates that powerful network security tools can be built using open-source technologies and made accessible to organizations of all sizes.
