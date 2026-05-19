// Real-time Dashboard JavaScript
const socket = io();

// Chart instances
let packetRateChart, threatTrendChart, protocolChart;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    loadInitialData();
    setupEventListeners();
    startRealTimeUpdates();
});

function initializeCharts() {
    // Packet Rate Chart
    const packetCtx = document.getElementById('packetRateChart')?.getContext('2d');
    if (packetCtx) {
        packetRateChart = new Chart(packetCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets/sec',
                    data: [],
                    borderColor: 'rgb(75, 192, 192)',
                    tension: 0.1
                }, {
                    label: 'Mbps',
                    data: [],
                    borderColor: 'rgb(255, 99, 132)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                animation: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
    
    // Threat Trend Chart
    const threatCtx = document.getElementById('threatTrendChart')?.getContext('2d');
    if (threatCtx) {
        threatTrendChart = new Chart(threatCtx, {
            type: 'bar',
            data: {
                labels: ['Low', 'Medium', 'High', 'Critical'],
                datasets: [{
                    label: 'Threats',
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#28a745', '#ffc107', '#fd7e14', '#dc3545']
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
    
    // Protocol Distribution Chart
    const protocolCtx = document.getElementById('protocolChart')?.getContext('2d');
    if (protocolCtx) {
        protocolChart = new Chart(protocolCtx, {
            type: 'pie',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: ['#4e73df', '#1cc88a', '#36b9cc', '#f6c23e']
                }]
            },
            options: {
                responsive: true
            }
        });
    }
}

async function loadInitialData() {
    try {
        const [stats, alerts, threatSummary] = await Promise.all([
            fetch('/api/stats').then(r => r.json()),
            fetch('/api/alerts?limit=50').then(r => r.json()),
            fetch('/api/threats/summary').then(r => r.json())
        ]);
        
        updateDashboard(stats);
        updateAlertTable(alerts);
        updateThreatSummary(threatSummary);
        
    } catch (error) {
        console.error('Error loading initial data:', error);
    }
}

function setupEventListeners() {
    // Refresh button
    document.getElementById('refreshBtn')?.addEventListener('click', () => {
        loadInitialData();
    });
    
    // Filter alerts
    document.getElementById('severityFilter')?.addEventListener('change', (e) => {
        loadAlertsBySeverity(e.target.value);
    });
    
    // Auto-refresh toggle
    let autoRefresh = true;
    document.getElementById('autoRefreshToggle')?.addEventListener('change', (e) => {
        autoRefresh = e.target.checked;
        if (autoRefresh) {
            startRealTimeUpdates();
        } else {
            stopRealTimeUpdates();
        }
    });
}

function startRealTimeUpdates() {
    // Request stats every 2 seconds
    setInterval(() => {
        socket.emit('request_stats');
    }, 2000);
}

function stopRealTimeUpdates() {
    // Will be implemented if needed
}

// Socket event handlers
socket.on('connected', (data) => {
    console.log('Connected to NIDS:', data);
    showNotification('Connected to NIDS', 'success');
});

socket.on('stats_update', (stats) => {
    updateDashboard(stats);
});

socket.on('new_alert', (data) => {
    updateAlertTable([data.alert], true);
    updateThreatSummary(data.stats.alerts);
    showNotification(`New ${data.alert.severity.toUpperCase()} threat: ${data.alert.attack_type}`, 'warning');
    playAlertSound();
});

function updateDashboard(stats) {
    // Update counters
    document.getElementById('totalPackets').textContent = stats.packets.total_packets?.toLocaleString() || '0';
    document.getElementById('packetsPerSec').textContent = stats.packets.rates?.packets_per_sec?.toFixed(1) || '0';
    document.getElementById('mbps').textContent = stats.packets.rates?.mbits_per_sec?.toFixed(2) || '0';
    document.getElementById('activeAlerts').textContent = stats.alerts.total || '0';
    document.getElementById('blockedIPs').textContent = stats.blocked_ips || '0';
    document.getElementById('queueSize').textContent = stats.system_health.queue_size || '0';
    
    // Update charts
    updatePacketChart(stats.packets.rates);
    updateThreatChart(stats.alerts.by_severity);
    updateProtocolChart(stats.packets.protocols);
    
    // Update system health indicators
    updateHealthIndicators(stats.system_health);
}

function updatePacketChart(rates) {
    if (!packetRateChart) return;
    
    const now = new Date().toLocaleTimeString();
    if (packetRateChart.data.labels.length > 20) {
        packetRateChart.data.labels.shift();
        packetRateChart.data.datasets[0].data.shift();
        packetRateChart.data.datasets[1].data.shift();
    }
    
    packetRateChart.data.labels.push(now);
    packetRateChart.data.datasets[0].data.push(rates.packets_per_sec || 0);
    packetRateChart.data.datasets[1].data.push(rates.mbits_per_sec || 0);
    packetRateChart.update();
}

function updateThreatChart(severityData) {
    if (!threatTrendChart) return;
    
    threatTrendChart.data.datasets[0].data = [
        severityData.low || 0,
        severityData.medium || 0,
        severityData.high || 0,
        severityData.critical || 0
    ];
    threatTrendChart.update();
}

function updateProtocolChart(protocols) {
    if (!protocolChart) return;
    
    const labels = Object.keys(protocols || {});
    const data = Object.values(protocols || {});
    
    protocolChart.data.labels = labels;
    protocolChart.data.datasets[0].data = data;
    protocolChart.update();
}

function updateAlertTable(alerts, prepend = false) {
    const tbody = document.getElementById('alertsTableBody');
    if (!tbody) return;
    
    const rows = alerts.map(alert => `
        <tr class="alert-${alert.severity}">
            <td>${new Date(alert.timestamp).toLocaleTimeString()}</td>
            <td><span class="badge badge-${getSeverityClass(alert.severity)}">${alert.severity.toUpperCase()}</span></td>
            <td>${alert.attack_type}</td>
            <td>${alert.packet_info?.src_ip || 'Unknown'}</td>
            <td>${alert.packet_info?.dst_ip || 'Unknown'}</td>
            <td>${(alert.confidence * 100).toFixed(1)}%</td>
            <td>${alert.detection_method}</td>
        </tr>
    `).join('');
    
    if (prepend) {
        tbody.innerHTML = rows + tbody.innerHTML;
        // Keep only last 100 rows
        if (tbody.children.length > 100) {
            while (tbody.children.length > 100) {
                tbody.removeChild(tbody.lastChild);
            }
        }
    } else {
        tbody.innerHTML = rows;
    }
}

function updateThreatSummary(summary) {
    const container = document.getElementById('threatSummary');
    if (!container) return;
    
    container.innerHTML = `
        <div class="summary-stats">
            <div class="summary-item">
                <strong>Total Threats:</strong> ${summary.total || 0}
            </div>
            <div class="summary-item">
                <strong>Low:</strong> ${summary.by_severity?.low || 0}
            </div>
            <div class="summary-item">
                <strong>Medium:</strong> ${summary.by_severity?.medium || 0}
            </div>
            <div class="summary-item">
                <strong>High:</strong> ${summary.by_severity?.high || 0}
            </div>
            <div class="summary-item">
                <strong>Critical:</strong> ${summary.by_severity?.critical || 0}
            </div>
        </div>
    `;
}

function updateHealthIndicators(health) {
    const statusElement = document.getElementById('systemStatus');
    if (statusElement) {
        const status = health.is_sniffing ? '🟢 Active' : '🔴 Stopped';
        statusElement.textContent = status;
        statusElement.className = health.is_sniffing ? 'status-active' : 'status-inactive';
    }
}

function getSeverityClass(severity) {
    const classes = {
        'low': 'success',
        'medium': 'warning',
        'high': 'danger',
        'critical': 'danger'
    };
    return classes[severity] || 'secondary';
}

function showNotification(message, type) {
    // Simple toast notification
    const toastContainer = document.getElementById('toastContainer') || createToastContainer();
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <div class="toast-header">
            <strong class="mr-auto">NIDS Alert</strong>
            <button type="button" class="ml-2 mb-1 close" data-dismiss="toast">&times;</button>
        </div>
        <div class="toast-body">${message}</div>
    `;
    toastContainer.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 5000);
}

function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toastContainer';
    container.style.position = 'fixed';
    container.style.bottom = '20px';
    container.style.right = '20px';
    container.style.zIndex = '9999';
    document.body.appendChild(container);
    return container;
}

function playAlertSound() {
    const audio = new Audio('/static/sounds/alert.mp3');
    audio.play().catch(e => console.log('Audio play failed:', e));
}

async function loadAlertsBySeverity(severity) {
    try {
        const url = severity ? `/api/alerts?severity=${severity}` : '/api/alerts';
        const response = await fetch(url);
        const alerts = await response.json();
        updateAlertTable(alerts);
    } catch (error) {
        console.error('Error loading alerts:', error);
    }
}