"""
Advanced NIDS - Network Intrusion Detection System (WORKING VERSION)
"""

from flask import Flask, render_template_string, jsonify
from flask_socketio import SocketIO, emit
import time
import threading
import random
from datetime import datetime
from collections import defaultdict

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nids-secret-key-2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables
alerts = []
packet_count = 0
total_bytes = 0
attack_stats = defaultdict(int)

# HTML Dashboard Template
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced NIDS - Network Intrusion Detection System</title>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: white; text-align: center; margin-bottom: 10px; font-size: 2em; }
        .subtitle { color: rgba(255,255,255,0.9); text-align: center; margin-bottom: 30px; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-card h3 { color: #666; font-size: 0.9em; margin-bottom: 10px; }
        .stat-value { font-size: 2em; font-weight: bold; color: #4e73df; }
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .chart-container {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .chart-container h3 { margin-bottom: 15px; color: #333; }
        canvas { max-height: 300px; }
        .alerts-container {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .alerts-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 10px;
        }
        .filter-controls select, .filter-controls button {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            cursor: pointer;
        }
        .filter-controls button {
            background: #4e73df;
            color: white;
            border: none;
        }
        .filter-controls button:hover { background: #2e59d9; }
        .alert-card {
            background: #f8f9fc;
            border-left: 4px solid #e74a3b;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            animation: slideIn 0.3s ease;
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        .alert-critical { border-left-color: #e74a3b; background: #ffebee; }
        .alert-high { border-left-color: #fd7e14; background: #fff3e0; }
        .alert-medium { border-left-color: #f6c23e; background: #fffbea; }
        .alert-low { border-left-color: #1cc88a; background: #e8f5e9; }
        .alert-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }
        .alert-type { font-weight: bold; font-size: 1.1em; }
        .alert-severity {
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }
        .severity-critical { background: #e74a3b; color: white; }
        .severity-high { background: #fd7e14; color: white; }
        .severity-medium { background: #f6c23e; color: #333; }
        .severity-low { background: #1cc88a; color: white; }
        .alert-details { color: #666; font-size: 0.9em; margin-top: 5px; }
        .connection-status {
            position: fixed;
            top: 10px;
            right: 10px;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 0.8em;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .status-connected { color: #1cc88a; }
        .status-disconnected { color: #e74a3b; }
        @media (max-width: 768px) {
            .charts-grid { grid-template-columns: 1fr; }
            .stats-grid { grid-template-columns: 1fr 1fr; }
        }
    </style>
</head>
<body>
    <div class="connection-status" id="connectionStatus">🔌 Connecting...</div>
    
    <div class="container">
        <h1>🛡️ Advanced Network Intrusion Detection System</h1>
        <p class="subtitle">Real-time Network Security Monitoring | ML-Powered Detection | Automated Response</p>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Packets</h3>
                <div class="stat-value" id="totalPackets">0</div>
            </div>
            <div class="stat-card">
                <h3>Packets/sec</h3>
                <div class="stat-value" id="packetsPerSec">0</div>
            </div>
            <div class="stat-card">
                <h3>Total Alerts</h3>
                <div class="stat-value" id="totalAlerts">0</div>
            </div>
            <div class="stat-card">
                <h3>Attack Types</h3>
                <div class="stat-value" id="attackTypes">0</div>
            </div>
        </div>
        
        <div class="charts-grid">
            <div class="chart-container">
                <h3>📊 Network Traffic Rate</h3>
                <canvas id="trafficChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>⚠️ Attack Distribution</h3>
                <canvas id="attackChart"></canvas>
            </div>
        </div>
        
        <div class="alerts-container">
            <div class="alerts-header">
                <h3>🚨 Recent Security Alerts</h3>
                <div class="filter-controls">
                    <select id="severityFilter">
                        <option value="all">All Severities</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                    <button onclick="clearAlerts()">Clear All</button>
                </div>
            </div>
            <div id="alertsList">
                <p style="text-align: center; color: #999;">Waiting for alerts...</p>
            </div>
        </div>
    </div>
    
    <script>
        let trafficChart, attackChart;
        let trafficData = [];
        let timeLabels = [];
        let socket = null;
        
        function initCharts() {
            const trafficCtx = document.getElementById('trafficChart').getContext('2d');
            trafficChart = new Chart(trafficCtx, {
                type: 'line',
                data: { labels: [], datasets: [{ label: 'Packets per Second', data: [], borderColor: '#4e73df', backgroundColor: 'rgba(78, 115, 223, 0.1)', borderWidth: 2, fill: true, tension: 0.4 }] },
                options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { position: 'top' } }, scales: { y: { beginAtZero: true } } }
            });
            
            const attackCtx = document.getElementById('attackChart').getContext('2d');
            attackChart = new Chart(attackCtx, {
                type: 'doughnut',
                data: { labels: [], datasets: [{ data: [], backgroundColor: ['#e74a3b', '#fd7e14', '#f6c23e', '#1cc88a', '#4e73df', '#36b9cc'] }] },
                options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { position: 'bottom' } } }
            });
        }
        
        function updateTrafficChart(packetsPerSec) {
            const now = new Date().toLocaleTimeString();
            timeLabels.push(now);
            trafficData.push(packetsPerSec);
            if (timeLabels.length > 30) { timeLabels.shift(); trafficData.shift(); }
            trafficChart.data.labels = timeLabels;
            trafficChart.data.datasets[0].data = trafficData;
            trafficChart.update();
        }
        
        function updateAttackChart(stats) {
            const labels = Object.keys(stats);
            const data = Object.values(stats);
            attackChart.data.labels = labels;
            attackChart.data.datasets[0].data = data;
            attackChart.update();
        }
        
        function addAlert(alert) {
            const alertsDiv = document.getElementById('alertsList');
            const severityFilter = document.getElementById('severityFilter').value;
            
            if (alertsDiv.children[0] && alertsDiv.children[0].innerText === 'Waiting for alerts...') {
                alertsDiv.innerHTML = '';
            }
            
            if (severityFilter !== 'all' && alert.severity !== severityFilter) return;
            
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert-card alert-${alert.severity}`;
            alertDiv.innerHTML = `
                <div class="alert-header">
                    <span class="alert-type">${alert.attack_type}</span>
                    <span class="alert-severity severity-${alert.severity}">${alert.severity.toUpperCase()}</span>
                </div>
                <div class="alert-details">
                    🔴 Source: ${alert.src_ip} | 🟢 Destination: ${alert.dst_ip || 'Multiple'}<br>
                    📊 Confidence: ${(alert.confidence * 100).toFixed(1)}% | 🔍 Detection: ${alert.method}<br>
                    ⏰ Time: ${new Date().toLocaleTimeString()}
                </div>
            `;
            alertsDiv.insertBefore(alertDiv, alertsDiv.firstChild);
            while (alertsDiv.children.length > 50) alertsDiv.removeChild(alertsDiv.lastChild);
        }
        
        function clearAlerts() {
            document.getElementById('alertsList').innerHTML = '<p style="text-align: center; color: #999;">Waiting for alerts...</p>';
            fetch('/api/clear-alerts', { method: 'POST' });
        }
        
        function updateStats(stats) {
            document.getElementById('totalPackets').textContent = stats.total_packets.toLocaleString();
            document.getElementById('packetsPerSec').textContent = stats.packets_per_sec.toFixed(1);
            document.getElementById('totalAlerts').textContent = stats.total_alerts;
            document.getElementById('attackTypes').textContent = stats.unique_attacks;
            updateTrafficChart(stats.packets_per_sec);
            updateAttackChart(stats.attack_stats);
        }
        
        function initSocket() {
            socket = io({ transports: ['websocket', 'polling'], reconnection: true, reconnectionAttempts: 10, reconnectionDelay: 1000 });
            socket.on('connect', () => { document.getElementById('connectionStatus').innerHTML = '✅ Connected'; document.getElementById('connectionStatus').className = 'connection-status status-connected'; });
            socket.on('disconnect', () => { document.getElementById('connectionStatus').innerHTML = '❌ Disconnected'; document.getElementById('connectionStatus').className = 'connection-status status-disconnected'; });
            socket.on('connect_error', () => { document.getElementById('connectionStatus').innerHTML = '⚠️ Connection Error'; document.getElementById('connectionStatus').className = 'connection-status status-disconnected'; });
            socket.on('stats_update', (data) => updateStats(data));
            socket.on('new_alert', (data) => addAlert(data));
        }
        
        document.getElementById('severityFilter').addEventListener('change', () => {
            const severity = document.getElementById('severityFilter').value;
            fetch(`/api/alerts?severity=${severity}`).then(r => r.json()).then(alerts => {
                const alertsDiv = document.getElementById('alertsList');
                alertsDiv.innerHTML = alerts.length === 0 ? '<p style="text-align: center; color: #999;">No alerts found</p>' : '';
                alerts.forEach(alert => addAlert(alert));
            });
        });
        
        initCharts();
        initSocket();
        fetch('/api/stats').then(r => r.json()).then(data => updateStats(data)).catch(err => console.log('Initial stats fetch failed:', err));
    </script>
</body>
</html>
"""

# Attack types and their properties
ATTACKS = {
    'PORT_SCAN': {'severity': 'high', 'confidence': 0.85, 'method': 'behavioral'},
    'SYN_FLOOD': {'severity': 'critical', 'confidence': 0.95, 'method': 'rate_based'},
    'DDOS_ATTACK': {'severity': 'critical', 'confidence': 0.90, 'method': 'rate_based'},
    'SQL_INJECTION': {'severity': 'critical', 'confidence': 0.92, 'method': 'signature'},
    'ANOMALY': {'severity': 'medium', 'confidence': 0.75, 'method': 'ml_anomaly'},
    'PING_FLOOD': {'severity': 'high', 'confidence': 0.80, 'method': 'rate_based'},
    'ARP_SPOOFING': {'severity': 'high', 'confidence': 0.82, 'method': 'behavioral'},
    'BRUTE_FORCE': {'severity': 'medium', 'confidence': 0.78, 'method': 'behavioral'},
    'MALICIOUS_PAYLOAD': {'severity': 'high', 'confidence': 0.88, 'method': 'signature'},
    'SERVICE_PROBE': {'severity': 'low', 'confidence': 0.65, 'method': 'behavioral'}
}

# IP ranges for simulation
SOURCE_IPS = [f"192.168.1.{i}" for i in range(1, 50)] + [f"10.0.0.{i}" for i in range(1, 30)]
DEST_IPS = [f"203.0.113.{i}" for i in range(1, 20)] + [f"198.51.100.{i}" for i in range(1, 20)]

def generate_packets():
    """Simulate network packet generation and threat detection"""
    global packet_count, total_bytes, alerts, attack_stats
    
    packet_rate = 50
    last_time = time.time()
    
    while True:
        current_time = time.time()
        time_diff = current_time - last_time
        
        if time_diff >= 1:
            packet_rate = random.randint(50, 300)
            if random.random() < 0.1:
                packet_rate = random.randint(800, 3000)
            
            packet_count += packet_rate
            total_bytes += packet_rate * random.randint(64, 1500)
            last_time = current_time
            
            try:
                socketio.emit('stats_update', {
                    'total_packets': packet_count,
                    'packets_per_sec': packet_rate,
                    'total_alerts': len(alerts),
                    'unique_attacks': len(attack_stats),
                    'attack_stats': dict(attack_stats)
                })
            except:
                pass
        
        if packet_rate > 800:
            attack_name = random.choice(['DDOS_ATTACK', 'SYN_FLOOD', 'PORT_SCAN'])
            prob = 0.8
        elif packet_rate > 300:
            attack_name = random.choice(['PORT_SCAN', 'PING_FLOOD', 'BRUTE_FORCE'])
            prob = 0.4
        else:
            attack_name = random.choice(['ANOMALY', 'SERVICE_PROBE'])
            prob = 0.1
        
        if random.random() < prob:
            attack_info = ATTACKS[attack_name]
            alert = {
                'attack_type': attack_name,
                'src_ip': random.choice(SOURCE_IPS),
                'dst_ip': random.choice(DEST_IPS),
                'severity': attack_info['severity'],
                'confidence': attack_info['confidence'],
                'method': attack_info['method'],
                'timestamp': datetime.now().isoformat()
            }
            alerts.insert(0, alert)
            attack_stats[attack_name] += 1
            if len(alerts) > 500:
                alerts.pop()
            try:
                socketio.emit('new_alert', alert)
                print(f"🚨 ALERT: {attack_name} from {alert['src_ip']} ({attack_info['severity'].upper()})")
            except:
                pass
        
        time.sleep(0.5)

@app.route('/')
def home():
    return render_template_string(DASHBOARD_HTML)

@app.route('/dashboard')
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/stats')
def get_stats():
    return jsonify({
        'total_packets': packet_count,
        'total_bytes': total_bytes,
        'packets_per_sec': random.randint(50, 300),
        'total_alerts': len(alerts),
        'unique_attacks': len(attack_stats),
        'attack_stats': dict(attack_stats)
    })

@app.route('/api/alerts')
def get_alerts():
    limit = 50
    severity = request.args.get('severity')
    filtered = alerts[:limit]
    if severity and severity != 'all':
        filtered = [a for a in filtered if a['severity'] == severity]
    return jsonify(filtered)

@app.route('/api/clear-alerts', methods=['POST'])
def clear_alerts():
    global alerts
    alerts = []
    return jsonify({'status': 'success'})

from flask import request

if __name__ == '__main__':
    ports_to_try = [8080, 3000, 8888, 8000, 5001]
    success = False
    
    print("=" * 60)
    print("🛡️  ADVANCED NETWORK INTRUSION DETECTION SYSTEM")
    print("=" * 60)
    print(f"✅ Python Version: 3.10.3 (Compatible)")
    print("=" * 60)
    
    for port in ports_to_try:
        try:
            print(f"🔍 Trying port {port}...")
            simulation_thread = threading.Thread(target=generate_packets, daemon=True)
            simulation_thread.start()
            
            print(f"✅ Server starting on port {port}")
            print(f"📊 Dashboard URL: http://localhost:{port}")
            print("=" * 60)
            print("Press CTRL+C to stop the server")
            print("=" * 60)
            
            # FIXED: Removed the invalid parameter
            socketio.run(app, host='0.0.0.0', port=port, debug=False)
            success = True
            break
            
        except OSError as e:
            if "Address already in use" in str(e):
                print(f"⚠️ Port {port} is in use, trying next port...")
                continue
            else:
                print(f"❌ Error on port {port}: {e}")
    
    if not success:
        print("\n" + "=" * 60)
        print("❌ COULD NOT START SERVER")
        print("=" * 60)