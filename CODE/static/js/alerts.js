/**
 * Advanced NIDS - Alerts Management Module
 * Handles real-time alerts, filtering, and notification system
 */

class AlertsManager {
    constructor() {
        this.alerts = [];
        this.filters = {
            severity: 'all',
            attackType: 'all',
            timeRange: '1h',
            sourceIp: '',
            destinationIp: ''
        };
        this.sortConfig = {
            column: 'timestamp',
            direction: 'desc'
        };
        this.audioContext = null;
        this.notificationPermission = false;
        this.alertSoundEnabled = true;
        this.desktopNotifications = true;
        
        this.init();
    }
    
    init() {
        this.requestNotificationPermission();
        this.setupEventListeners();
        this.startAlertPolling();
        this.initAudioContext();
    }
    
    requestNotificationPermission() {
        if ('Notification' in window) {
            Notification.requestPermission().then(permission => {
                this.notificationPermission = permission === 'granted';
            });
        }
    }
    
    initAudioContext() {
        // Initialize audio context for alert sounds (user interaction required)
        document.body.addEventListener('click', () => {
            if (!this.audioContext) {
                this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
            }
        }, { once: true });
    }
    
    setupEventListeners() {
        // Severity filter
        const severityFilter = document.getElementById('severityFilter');
        if (severityFilter) {
            severityFilter.addEventListener('change', (e) => {
                this.filters.severity = e.target.value;
                this.applyFilters();
            });
        }
        
        // Attack type filter
        const attackTypeFilter = document.getElementById('attackTypeFilter');
        if (attackTypeFilter) {
            attackTypeFilter.addEventListener('change', (e) => {
                this.filters.attackType = e.target.value;
                this.applyFilters();
            });
        }
        
        // Time range filter
        const timeRangeFilter = document.getElementById('timeRangeFilter');
        if (timeRangeFilter) {
            timeRangeFilter.addEventListener('change', (e) => {
                this.filters.timeRange = e.target.value;
                this.applyFilters();
            });
        }
        
        // Source IP filter
        const sourceIpFilter = document.getElementById('sourceIpFilter');
        if (sourceIpFilter) {
            sourceIpFilter.addEventListener('input', (e) => {
                this.filters.sourceIp = e.target.value;
                this.applyFilters();
            });
        }
        
        // Destination IP filter
        const destIpFilter = document.getElementById('destIpFilter');
        if (destIpFilter) {
            destIpFilter.addEventListener('input', (e) => {
                this.filters.destinationIp = e.target.value;
                this.applyFilters();
            });
        }
        
        // Clear filters button
        const clearFiltersBtn = document.getElementById('clearFiltersBtn');
        if (clearFiltersBtn) {
            clearFiltersBtn.addEventListener('click', () => this.clearFilters());
        }
        
        // Export alerts button
        const exportBtn = document.getElementById('exportAlertsBtn');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => this.exportAlerts());
        }
        
        // Settings toggles
        const soundToggle = document.getElementById('alertSoundToggle');
        if (soundToggle) {
            soundToggle.addEventListener('change', (e) => {
                this.alertSoundEnabled = e.target.checked;
                localStorage.setItem('alertSoundEnabled', this.alertSoundEnabled);
            });
            this.alertSoundEnabled = localStorage.getItem('alertSoundEnabled') !== 'false';
            soundToggle.checked = this.alertSoundEnabled;
        }
        
        const notificationToggle = document.getElementById('notificationToggle');
        if (notificationToggle) {
            notificationToggle.addEventListener('change', (e) => {
                this.desktopNotifications = e.target.checked;
                localStorage.setItem('desktopNotifications', this.desktopNotifications);
            });
            this.desktopNotifications = localStorage.getItem('desktopNotifications') !== 'false';
            notificationToggle.checked = this.desktopNotifications;
        }
    }
    
    startAlertPolling() {
        // Poll for new alerts every 2 seconds
        setInterval(() => {
            this.fetchRecentAlerts();
        }, 2000);
    }
    
    async fetchRecentAlerts() {
        try {
            const response = await fetch('/api/alerts?limit=50');
            const alerts = await response.json();
            
            // Check for new alerts
            if (this.alerts.length > 0) {
                const newAlerts = alerts.filter(alert => 
                    !this.alerts.some(existing => existing.alert_id === alert.alert_id)
                );
                
                if (newAlerts.length > 0) {
                    this.handleNewAlerts(newAlerts);
                }
            }
            
            this.alerts = alerts;
            this.applyFilters();
            
        } catch (error) {
            console.error('Error fetching alerts:', error);
        }
    }
    
    handleNewAlerts(newAlerts) {
        newAlerts.forEach(alert => {
            // Play sound for high/critical alerts
            if ((alert.severity === 'high' || alert.severity === 'critical') && this.alertSoundEnabled) {
                this.playAlertSound(alert.severity);
            }
            
            // Show desktop notification
            if (this.desktopNotifications && this.notificationPermission) {
                this.showDesktopNotification(alert);
            }
            
            // Add to live feed
            this.addToLiveFeed(alert);
            
            // Update statistics
            this.updateAlertStats(alert);
        });
        
        // Trigger custom event for other components
        window.dispatchEvent(new CustomEvent('newAlerts', { detail: newAlerts }));
    }
    
    playAlertSound(severity) {
        if (!this.audioContext) return;
        
        try {
            const oscillator = this.audioContext.createOscillator();
            const gainNode = this.audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(this.audioContext.destination);
            
            // Different sounds for different severities
            if (severity === 'critical') {
                oscillator.frequency.value = 880; // A5
                oscillator.type = 'square';
                gainNode.gain.value = 0.3;
                oscillator.start();
                oscillator.stop(this.audioContext.currentTime + 0.5);
            } else if (severity === 'high') {
                oscillator.frequency.value = 660; // E5
                oscillator.type = 'sawtooth';
                gainNode.gain.value = 0.2;
                oscillator.start();
                oscillator.stop(this.audioContext.currentTime + 0.3);
            }
        } catch (error) {
            console.error('Error playing sound:', error);
        }
    }
    
    showDesktopNotification(alert) {
        const options = {
            body: `${alert.attack_type} detected from ${alert.packet_info?.src_ip || 'unknown'} (${(alert.confidence * 100).toFixed(1)}% confidence)`,
            icon: '/static/icons/alert-icon.png',
            tag: alert.alert_id,
            requireInteraction: alert.severity === 'critical',
            silent: false
        };
        
        const notification = new Notification(`NIDS: ${alert.severity.toUpperCase()} Alert`, options);
        
        notification.onclick = () => {
            window.focus();
            this.showAlertDetails(alert);
        };
    }
    
    addToLiveFeed(alert) {
        const liveFeed = document.getElementById('liveAlertFeed');
        if (!liveFeed) return;
        
        const alertElement = this.createAlertElement(alert);
        liveFeed.insertBefore(alertElement, liveFeed.firstChild);
        
        // Keep only last 50 alerts in live feed
        while (liveFeed.children.length > 50) {
            liveFeed.removeChild(liveFeed.lastChild);
        }
        
        // Animate new alert
        alertElement.style.animation = 'slideIn 0.3s ease';
        setTimeout(() => {
            alertElement.style.animation = '';
        }, 300);
    }
    
    createAlertElement(alert) {
        const div = document.createElement('div');
        div.className = `alert-card alert-${alert.severity}`;
        div.dataset.alertId = alert.alert_id;
        
        const timestamp = new Date(alert.timestamp).toLocaleTimeString();
        
        div.innerHTML = `
            <div class="alert-card-header">
                <span class="alert-severity-badge badge-${alert.severity}">${alert.severity.toUpperCase()}</span>
                <span class="alert-time">${timestamp}</span>
                <button class="alert-details-btn" onclick="alertsManager.showAlertDetails(${JSON.stringify(alert).replace(/"/g, '&quot;')})">
                    Details
                </button>
            </div>
            <div class="alert-card-body">
                <div class="alert-type">${this.formatAttackType(alert.attack_type)}</div>
                <div class="alert-sources">
                    <span>🔴 ${alert.packet_info?.src_ip || 'Unknown'}</span>
                    <span>➡️</span>
                    <span>🟢 ${alert.packet_info?.dst_ip || 'Unknown'}</span>
                </div>
                <div class="alert-confidence">
                    <div class="confidence-bar">
                        <div class="confidence-fill" style="width: ${alert.confidence * 100}%"></div>
                    </div>
                    <span>${(alert.confidence * 100).toFixed(1)}% confidence</span>
                </div>
                <div class="alert-method">Detection: ${alert.detection_method}</div>
                ${alert.details ? `<div class="alert-details">${alert.details}</div>` : ''}
            </div>
        `;
        
        return div;
    }
    
    formatAttackType(attackType) {
        const icons = {
            'SYN_FLOOD': '🌊',
            'DDOS_ATTACK': '💥',
            'PORT_SCAN': '🔍',
            'SQL_INJECTION': '🗄️',
            'ANOMALY': '⚠️',
            'SERVICE_PROBE': '📡',
            'RATE_LIMIT_EXCEEDED': '⏱️',
            'PING_OF_DEATH': '💀',
            'LAND_ATTACK': '🏔️',
            'SMURF_ATTACK': '👾'
        };
        
        const icon = icons[attackType] || '🚨';
        return `${icon} ${attackType.replace(/_/g, ' ')}`;
    }
    
    applyFilters() {
        let filteredAlerts = [...this.alerts];
        
        // Apply severity filter
        if (this.filters.severity !== 'all') {
            filteredAlerts = filteredAlerts.filter(alert => 
                alert.severity === this.filters.severity
            );
        }
        
        // Apply attack type filter
        if (this.filters.attackType !== 'all') {
            filteredAlerts = filteredAlerts.filter(alert => 
                alert.attack_type === this.filters.attackType
            );
        }
        
        // Apply time range filter
        filteredAlerts = this.filterByTimeRange(filteredAlerts);
        
        // Apply source IP filter
        if (this.filters.sourceIp) {
            filteredAlerts = filteredAlerts.filter(alert => 
                alert.packet_info?.src_ip?.includes(this.filters.sourceIp)
            );
        }
        
        // Apply destination IP filter
        if (this.filters.destinationIp) {
            filteredAlerts = filteredAlerts.filter(alert => 
                alert.packet_info?.dst_ip?.includes(this.filters.destinationIp)
            );
        }
        
        // Apply sorting
        filteredAlerts = this.sortAlerts(filteredAlerts);
        
        // Render alerts table
        this.renderAlertsTable(filteredAlerts);
        
        // Update attack type filter options
        this.updateAttackTypeOptions();
        
        // Update statistics
        this.updateStatisticsPanel(filteredAlerts);
    }
    
    filterByTimeRange(alerts) {
        const now = new Date();
        const ranges = {
            '1h': 60 * 60 * 1000,
            '6h': 6 * 60 * 60 * 1000,
            '12h': 12 * 60 * 60 * 1000,
            '24h': 24 * 60 * 60 * 1000,
            '7d': 7 * 24 * 60 * 60 * 1000,
            '30d': 30 * 24 * 60 * 60 * 1000
        };
        
        const rangeMs = ranges[this.filters.timeRange];
        if (rangeMs && this.filters.timeRange !== 'all') {
            const cutoff = now - rangeMs;
            return alerts.filter(alert => new Date(alert.timestamp) > cutoff);
        }
        
        return alerts;
    }
    
    sortAlerts(alerts) {
        return [...alerts].sort((a, b) => {
            let aVal, bVal;
            
            switch (this.sortConfig.column) {
                case 'timestamp':
                    aVal = new Date(a.timestamp);
                    bVal = new Date(b.timestamp);
                    break;
                case 'severity':
                    const severityOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 };
                    aVal = severityOrder[a.severity] || 0;
                    bVal = severityOrder[b.severity] || 0;
                    break;
                case 'confidence':
                    aVal = a.confidence;
                    bVal = b.confidence;
                    break;
                default:
                    aVal = a[this.sortConfig.column];
                    bVal = b[this.sortConfig.column];
            }
            
            if (this.sortConfig.direction === 'asc') {
                return aVal > bVal ? 1 : -1;
            } else {
                return aVal < bVal ? 1 : -1;
            }
        });
    }
    
    renderAlertsTable(alerts) {
        const tbody = document.getElementById('alertsTableBody');
        if (!tbody) return;
        
        if (alerts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align: center;">No alerts found</td></tr>';
            return;
        }
        
        tbody.innerHTML = alerts.map(alert => `
            <tr class="alert-row alert-${alert.severity}" data-alert-id="${alert.alert_id}">
                <td class="alert-time">${new Date(alert.timestamp).toLocaleString()}</td>
                <td class="alert-severity">
                    <span class="severity-badge severity-${alert.severity}">${alert.severity}</span>
                </td>
                <td class="alert-type">${this.formatAttackType(alert.attack_type)}</td>
                <td class="alert-source">
                    <code>${alert.packet_info?.src_ip || 'Unknown'}</code>
                    ${alert.packet_info?.src_port ? `:${alert.packet_info.src_port}` : ''}
                </td>
                <td class="alert-destination">
                    <code>${alert.packet_info?.dst_ip || 'Unknown'}</code>
                    ${alert.packet_info?.dst_port ? `:${alert.packet_info.dst_port}` : ''}
                </td>
                <td class="alert-confidence">
                    <div class="confidence-indicator">
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: ${alert.confidence * 100}%"></div>
                        </div>
                        <span>${(alert.confidence * 100).toFixed(1)}%</span>
                    </div>
                </td>
                <td class="alert-method">
                    <span class="method-badge method-${alert.detection_method}">
                        ${alert.detection_method}
                    </span>
                </td>
                <td class="alert-actions">
                    <button class="btn-sm" onclick="alertsManager.showAlertDetails(${JSON.stringify(alert).replace(/"/g, '&quot;')})">
                        Details
                    </button>
                    <button class="btn-sm btn-block" onclick="alertsManager.blockIp('${alert.packet_info?.src_ip}')">
                        Block IP
                    </button>
                </td>
            </tr>
        `).join('');
    }
    
    updateAttackTypeOptions() {
        const attackTypes = new Set(this.alerts.map(alert => alert.attack_type));
        const select = document.getElementById('attackTypeFilter');
        if (!select) return;
        
        const currentValue = select.value;
        select.innerHTML = '<option value="all">All Types</option>' + 
            Array.from(attackTypes).sort().map(type => 
                `<option value="${type}">${type.replace(/_/g, ' ')}</option>`
            ).join('');
        
        if (currentValue && attackTypes.has(currentValue)) {
            select.value = currentValue;
        }
    }
    
    updateStatisticsPanel(alerts) {
        const stats = this.calculateStatistics(alerts);
        
        // Update stats display
        const statElements = {
            'totalAlerts': stats.total,
            'criticalAlerts': stats.bySeverity.critical,
            'highAlerts': stats.bySeverity.high,
            'mediumAlerts': stats.bySeverity.medium,
            'lowAlerts': stats.bySeverity.low,
            'uniqueSources': stats.uniqueSources,
            'uniqueDestinations': stats.uniqueDestinations,
            'avgConfidence': stats.avgConfidence
        };
        
        for (const [id, value] of Object.entries(statElements)) {
            const element = document.getElementById(id);
            if (element) element.textContent = value;
        }
        
        // Update severity chart if available
        if (window.chartsManager && window.chartsManager.severityChart) {
            window.chartsManager.updateSeverityChart(stats.bySeverity);
        }
        
        // Update top attackers list
        this.updateTopAttackers(stats.topAttackers);
    }
    
    calculateStatistics(alerts) {
        const bySeverity = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };
        
        const sources = new Map();
        const destinations = new Map();
        let totalConfidence = 0;
        
        alerts.forEach(alert => {
            bySeverity[alert.severity]++;
            totalConfidence += alert.confidence;
            
            const srcIp = alert.packet_info?.src_ip;
            if (srcIp) {
                sources.set(srcIp, (sources.get(srcIp) || 0) + 1);
            }
            
            const dstIp = alert.packet_info?.dst_ip;
            if (dstIp) {
                destinations.set(dstIp, (destinations.get(dstIp) || 0) + 1);
            }
        });
        
        const topAttackers = Array.from(sources.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([ip, count]) => ({ ip, count }));
        
        return {
            total: alerts.length,
            bySeverity,
            uniqueSources: sources.size,
            uniqueDestinations: destinations.size,
            avgConfidence: alerts.length > 0 ? (totalConfidence / alerts.length * 100).toFixed(1) : 0,
            topAttackers
        };
    }
    
    updateTopAttackers(attackers) {
        const container = document.getElementById('topAttackersList');
        if (!container) return;
        
        if (attackers.length === 0) {
            container.innerHTML = '<p>No attackers detected</p>';
            return;
        }
        
        container.innerHTML = attackers.map(attacker => `
            <div class="attacker-item">
                <span class="attacker-ip">
                    <code>${attacker.ip}</code>
                    <button class="btn-xs" onclick="alertsManager.blockIp('${attacker.ip}')">Block</button>
                </span>
                <span class="attacker-count">${attacker.count} alerts</span>
                <div class="attacker-bar">
                    <div class="attacker-bar-fill" style="width: ${Math.min(100, attacker.count / attackers[0].count * 100)}%"></div>
                </div>
            </div>
        `).join('');
    }
    
    async blockIp(ip) {
        if (!ip || ip === 'Unknown') {
            this.showToast('Cannot block unknown IP', 'error');
            return;
        }
        
        try {
            const response = await fetch(`/api/unblock/${ip}`, { method: 'POST' });
            if (response.ok) {
                this.showToast(`IP ${ip} has been blocked`, 'success');
                this.updateBlockedIPsList();
            } else {
                throw new Error('Block failed');
            }
        } catch (error) {
            console.error('Error blocking IP:', error);
            this.showToast(`Failed to block ${ip}`, 'error');
        }
    }
    
    async updateBlockedIPsList() {
        try {
            const response = await fetch('/api/blocked/ips');
            const ips = await response.json();
            
            const container = document.getElementById('blockedIPsList');
            if (container) {
                if (ips.length === 0) {
                    container.innerHTML = '<p>No blocked IPs</p>';
                } else {
                    container.innerHTML = ips.map(ip => `
                        <div class="blocked-ip-item">
                            <code>${ip}</code>
                            <button class="btn-xs" onclick="alertsManager.unblockIp('${ip}')">Unblock</button>
                        </div>
                    `).join('');
                }
            }
        } catch (error) {
            console.error('Error fetching blocked IPs:', error);
        }
    }
    
    async unblockIp(ip) {
        try {
            const response = await fetch(`/api/unblock/${ip}`, { method: 'POST' });
            if (response.ok) {
                this.showToast(`IP ${ip} has been unblocked`, 'success');
                this.updateBlockedIPsList();
            }
        } catch (error) {
            console.error('Error unblocking IP:', error);
        }
    }
    
    showAlertDetails(alert) {
        const modal = document.getElementById('alertDetailsModal');
        if (!modal) return;
        
        const content = document.getElementById('alertDetailsContent');
        content.innerHTML = `
            <div class="details-header alert-${alert.severity}">
                <h3>${this.formatAttackType(alert.attack_type)}</h3>
                <span class="severity-badge severity-${alert.severity}">${alert.severity.toUpperCase()}</span>
            </div>
            <div class="details-body">
                <div class="detail-row">
                    <strong>Alert ID:</strong> <code>${alert.alert_id}</code>
                </div>
                <div class="detail-row">
                    <strong>Timestamp:</strong> ${new Date(alert.timestamp).toLocaleString()}
                </div>
                <div class="detail-row">
                    <strong>Confidence:</strong> ${(alert.confidence * 100).toFixed(1)}%
                    <div class="confidence-bar">
                        <div class="confidence-fill" style="width: ${alert.confidence * 100}%"></div>
                    </div>
                </div>
                <div class="detail-row">
                    <strong>Detection Method:</strong> ${alert.detection_method}
                </div>
                <div class="detail-row">
                    <strong>Source:</strong> ${alert.packet_info?.src_ip || 'Unknown'}${alert.packet_info?.src_port ? `:${alert.packet_info.src_port}` : ''}
                </div>
                <div class="detail-row">
                    <strong>Destination:</strong> ${alert.packet_info?.dst_ip || 'Unknown'}${alert.packet_info?.dst_port ? `:${alert.packet_info.dst_port}` : ''}
                </div>
                <div class="detail-row">
                    <strong>Protocol:</strong> ${alert.packet_info?.protocol || 'Unknown'}
                </div>
                ${alert.packet_info?.payload ? `
                <div class="detail-row">
                    <strong>Payload (hex):</strong>
                    <pre class="payload-preview">${alert.packet_info.payload}</pre>
                </div>
                ` : ''}
                ${alert.details ? `
                <div class="detail-row">
                    <strong>Additional Details:</strong> ${alert.details}
                </div>
                ` : ''}
            </div>
            <div class="details-footer">
                <button class="btn" onclick="alertsManager.blockIp('${alert.packet_info?.src_ip}')">Block Source IP</button>
                <button class="btn btn-primary" onclick="alertsManager.closeModal()">Close</button>
            </div>
        `;
        
        modal.style.display = 'block';
    }
    
    closeModal() {
        const modal = document.getElementById('alertDetailsModal');
        if (modal) modal.style.display = 'none';
    }
    
    exportAlerts() {
        const filteredAlerts = this.getCurrentFilteredAlerts();
        const csv = this.convertToCSV(filteredAlerts);
        
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `nids_alerts_${new Date().toISOString()}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        
        this.showToast(`Exported ${filteredAlerts.length} alerts`, 'success');
    }
    
    convertToCSV(alerts) {
        const headers = ['Timestamp', 'Severity', 'Attack Type', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Confidence', 'Detection Method', 'Details'];
        const rows = alerts.map(alert => [
            alert.timestamp,
            alert.severity,
            alert.attack_type,
            alert.packet_info?.src_ip || '',
            alert.packet_info?.src_port || '',
            alert.packet_info?.dst_ip || '',
            alert.packet_info?.dst_port || '',
            alert.confidence,
            alert.detection_method,
            alert.details || ''
        ]);
        
        return [headers, ...rows].map(row => row.map(cell => 
            typeof cell === 'string' && cell.includes(',') ? `"${cell}"` : cell
        ).join(',')).join('\n');
    }
    
    getCurrentFilteredAlerts() {
        let filtered = [...this.alerts];
        
        if (this.filters.severity !== 'all') {
            filtered = filtered.filter(a => a.severity === this.filters.severity);
        }
        if (this.filters.attackType !== 'all') {
            filtered = filtered.filter(a => a.attack_type === this.filters.attackType);
        }
        
        return this.filterByTimeRange(filtered);
    }
    
    clearFilters() {
        this.filters = {
            severity: 'all',
            attackType: 'all',
            timeRange: '1h',
            sourceIp: '',
            destinationIp: ''
        };
        
        // Reset UI elements
        const severityFilter = document.getElementById('severityFilter');
        if (severityFilter) severityFilter.value = 'all';
        
        const attackTypeFilter = document.getElementById('attackTypeFilter');
        if (attackTypeFilter) attackTypeFilter.value = 'all';
        
        const timeRangeFilter = document.getElementById('timeRangeFilter');
        if (timeRangeFilter) timeRangeFilter.value = '1h';
        
        const sourceIpFilter = document.getElementById('sourceIpFilter');
        if (sourceIpFilter) sourceIpFilter.value = '';
        
        const destIpFilter = document.getElementById('destIpFilter');
        if (destIpFilter) destIpFilter.value = '';
        
        this.applyFilters();
        this.showToast('Filters cleared', 'info');
    }
    
    updateAlertStats(newAlert) {
        // Update real-time statistics when new alert arrives
        const stats = this.calculateStatistics(this.alerts);
        
        const elements = {
            'totalAlerts': stats.total,
            'criticalAlerts': stats.bySeverity.critical,
            'highAlerts': stats.bySeverity.high
        };
        
        for (const [id, value] of Object.entries(elements)) {
            const element = document.getElementById(id);
            if (element) {
                element.classList.add('pulse');
                element.textContent = value;
                setTimeout(() => element.classList.remove('pulse'), 500);
            }
        }
    }
    
    showToast(message, type = 'info') {
        const toastContainer = document.getElementById('toastContainer') || this.createToastContainer();
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `
            <div class="toast-header">
                <strong>NIDS Alert</strong>
                <button class="toast-close">&times;</button>
            </div>
            <div class="toast-body">${message}</div>
        `;
        
        toast.querySelector('.toast-close').addEventListener('click', () => toast.remove());
        toastContainer.appendChild(toast);
        
        setTimeout(() => toast.remove(), 5000);
    }
    
    createToastContainer() {
        const container = document.createElement('div');
        container.id = 'toastContainer';
        container.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 10000;
        `;
        document.body.appendChild(container);
        return container;
    }
    
    sort(column) {
        if (this.sortConfig.column === column) {
            this.sortConfig.direction = this.sortConfig.direction === 'asc' ? 'desc' : 'asc';
        } else {
            this.sortConfig.column = column;
            this.sortConfig.direction = 'desc';
        }
        
        this.applyFilters();
        
        // Update sort indicators
        document.querySelectorAll('.sortable').forEach(el => {
            el.classList.remove('sort-asc', 'sort-desc');
            if (el.dataset.sort === column) {
                el.classList.add(`sort-${this.sortConfig.direction}`);
            }
        });
    }
}

// Initialize alerts manager when DOM is ready
let alertsManager;
document.addEventListener('DOMContentLoaded', () => {
    alertsManager = new AlertsManager();
    window.alertsManager = alertsManager;
});

// CSS styles for alerts (inject dynamically)
const alertStyles = document.createElement('style');
alertStyles.textContent = `
    .alert-card {
        background: white;
        border-radius: 8px;
        margin-bottom: 10px;
        padding: 15px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        border-left: 4px solid #ccc;
    }
    .alert-critical { border-left-color: #dc3545; }
    .alert-high { border-left-color: #fd7e14; }
    .alert-medium { border-left-color: #ffc107; }
    .alert-low { border-left-color: #28a745; }
    .severity-badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: bold;
        text-transform: uppercase;
    }
    .severity-critical { background: #dc3545; color: white; }
    .severity-high { background: #fd7e14; color: white; }
    .severity-medium { background: #ffc107; color: #333; }
    .severity-low { background: #28a745; color: white; }
    .confidence-bar {
        background: #e9ecef;
        border-radius: 4px;
        height: 6px;
        overflow: hidden;
    }
    .confidence-fill {
        background: linear-gradient(90deg, #4e73df, #224abe);
        height: 100%;
        transition: width 0.3s;
    }
    .attacker-item {
        padding: 8px;
        border-bottom: 1px solid #eee;
    }
    .attacker-bar {
        background: #e9ecef;
        border-radius: 4px;
        height: 4px;
        margin-top: 4px;
        overflow: hidden;
    }
    .attacker-bar-fill {
        background: #dc3545;
        height: 100%;
        transition: width 0.3s;
    }
    .pulse {
        animation: pulse 0.5s ease;
    }
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }
    @keyframes slideIn {
        from {
            opacity: 0;
            transform: translateX(-20px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
`;
document.head.appendChild(alertStyles);