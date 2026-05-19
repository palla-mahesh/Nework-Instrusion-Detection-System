/**
 * Advanced NIDS - Charts and Visualization Module
 * Handles real-time data visualization, dashboards, and analytics
 */

class ChartsManager {
    constructor() {
        this.charts = {};
        this.updateIntervals = {};
        this.colorSchemes = {
            primary: '#4e73df',
            success: '#1cc88a',
            warning: '#f6c23e',
            danger: '#e74a3b',
            dark: '#5a5c69',
            purple: '#6f42c1',
            cyan: '#36b9cc',
            pink: '#e83e8c'
        };
        
        this.init();
    }
    
    init() {
        this.initializeAllCharts();
        this.startRealTimeUpdates();
        this.setupResizeHandler();
    }
    
    initializeAllCharts() {
        // Packet Rate Chart (Line)
        this.createPacketRateChart();
        
        // Threat Severity Chart (Bar/Doughnut)
        this.createThreatSeverityChart();
        
        // Protocol Distribution Chart (Pie)
        this.createProtocolChart();
        
        // Top Attackers Chart (Horizontal Bar)
        this.createTopAttackersChart();
        
        // Traffic Timeline Chart (Area)
        this.createTrafficTimelineChart();
        
        // Alert Trend Chart (Line)
        this.createAlertTrendChart();
        
        // Geographic Distribution Chart (if map available)
        this.createGeoChart();
    }
    
    createPacketRateChart() {
        const canvas = document.getElementById('packetRateChart');
        if (!canvas) return;
        
        this.charts.packetRate = new Chart(canvas, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Packets per Second',
                        data: [],
                        borderColor: this.colorSchemes.primary,
                        backgroundColor: 'rgba(78, 115, 223, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 3,
                        pointHoverRadius: 5
                    },
                    {
                        label: 'Bandwidth (Mbps)',
                        data: [],
                        borderColor: this.colorSchemes.success,
                        backgroundColor: 'rgba(28, 200, 138, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 3,
                        pointHoverRadius: 5,
                        yAxisID: 'y1'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                interaction: {
                    mode: 'index',
                    intersect: false
                },
                plugins: {
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        callbacks: {
                            label: function(context) {
                                let label = context.dataset.label || '';
                                let value = context.parsed.y;
                                if (context.dataset.label.includes('Mbps')) {
                                    return `${label}: ${value.toFixed(2)} Mbps`;
                                }
                                return `${label}: ${Math.round(value)}`;
                            }
                        }
                    },
                    legend: {
                        position: 'top',
                        labels: {
                            usePointStyle: true,
                            boxWidth: 10
                        }
                    },
                    zoom: {
                        zoom: {
                            wheel: { enabled: true },
                            pinch: { enabled: true },
                            mode: 'x'
                        },
                        pan: {
                            enabled: true,
                            mode: 'x'
                        }
                    }
                },
                scales: {
                    x: {
                        title: {
                            display: true,
                            text: 'Time',
                            color: this.colorSchemes.dark
                        },
                        ticks: {
                            maxRotation: 45,
                            minRotation: 45
                        }
                    },
                    y: {
                        title: {
                            display: true,
                            text: 'Packets per Second',
                            color: this.colorSchemes.primary
                        },
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.05)'
                        }
                    },
                    y1: {
                        position: 'right',
                        title: {
                            display: true,
                            text: 'Bandwidth (Mbps)',
                            color: this.colorSchemes.success
                        },
                        beginAtZero: true,
                        grid: {
                            drawOnChartArea: false
                        }
                    }
                }
            }
        });
    }
    
    createThreatSeverityChart() {
        const canvas = document.getElementById('threatTrendChart');
        if (!canvas) return;
        
        this.charts.threatSeverity = new Chart(canvas, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        this.colorSchemes.danger,
                        this.colorSchemes.warning,
                        this.colorSchemes.primary,
                        this.colorSchemes.success
                    ],
                    borderWidth: 2,
                    borderColor: '#fff',
                    hoverOffset: 10
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            usePointStyle: true,
                            padding: 15,
                            font: {
                                size: 12
                            }
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                },
                cutout: '60%',
                animation: {
                    animateRotate: true,
                    animateScale: true
                }
            }
        });
        
        // Add center text
        this.addCenterTextToDoughnut(canvas, 'Total Threats', '0');
    }
    
    addCenterTextToDoughnut(canvas, title, value) {
        const ctx = canvas.getContext('2d');
        const originalDraw = this.charts.threatSeverity.draw;
        
        this.charts.threatSeverity.draw = function() {
            originalDraw.apply(this, arguments);
            
            const width = this.width;
            const height = this.height;
            const centerX = width / 2;
            const centerY = height / 2;
            
            ctx.save();
            ctx.font = 'bold 20px "Segoe UI", sans-serif';
            ctx.fillStyle = this.colorSchemes.dark;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText(value, centerX, centerY - 5);
            
            ctx.font = '12px "Segoe UI", sans-serif';
            ctx.fillStyle = '#858796';
            ctx.fillText(title, centerX, centerY + 15);
            ctx.restore();
        };
    }
    
    createProtocolChart() {
        const canvas = document.getElementById('protocolChart');
        if (!canvas) return;
        
        this.charts.protocol = new Chart(canvas, {
            type: 'pie',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        this.colorSchemes.primary,
                        this.colorSchemes.success,
                        this.colorSchemes.warning,
                        this.colorSchemes.danger,
                        this.colorSchemes.purple,
                        this.colorSchemes.cyan
                    ],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            usePointStyle: true,
                            font: {
                                size: 11
                            }
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                                return `${label}: ${value.toLocaleString()} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
    }
    
    createTopAttackersChart() {
        const canvas = document.getElementById('topAttackersChart');
        if (!canvas) return;
        
        this.charts.topAttackers = new Chart(canvas, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Alert Count',
                    data: [],
                    backgroundColor: this.colorSchemes.danger,
                    borderRadius: 4,
                    barPercentage: 0.7,
                    categoryPercentage: 0.8
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return `Alerts: ${context.parsed.x}`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        title: {
                            display: true,
                            text: 'Number of Alerts',
                            color: this.colorSchemes.dark
                        },
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.05)'
                        }
                    },
                    y: {
                        title: {
                            display: true,
                            text: 'Source IP Address',
                            color: this.colorSchemes.dark
                        },
                        ticks: {
                            font: {
                                size: 10
                            }
                        }
                    }
                }
            }
        });
    }
    
    createTrafficTimelineChart() {
        const canvas = document.getElementById('trafficTimelineChart');
        if (!canvas) return;
        
        this.charts.trafficTimeline = new Chart(canvas, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Incoming Traffic',
                        data: [],
                        borderColor: this.colorSchemes.primary,
                        backgroundColor: 'rgba(78, 115, 223, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4
                    },
                    {
                        label: 'Outgoing Traffic',
                        data: [],
                        borderColor: this.colorSchemes.warning,
                        backgroundColor: 'rgba(246, 194, 62, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                },
                scales: {
                    x: {
                        title: {
                            display: true,
                            text: 'Time'
                        }
                    },
                    y: {
                        title: {
                            display: true,
                            text: 'Packets per Second'
                        },
                        beginAtZero: true
                    }
                }
            }
        });
    }
    
    createAlertTrendChart() {
        const canvas = document.getElementById('alertTrendChart');
        if (!canvas) return;
        
        this.charts.alertTrend = new Chart(canvas, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Critical',
                        data: [],
                        borderColor: this.colorSchemes.danger,
                        backgroundColor: 'transparent',
                        borderWidth: 2,
                        tension: 0.3,
                        pointRadius: 2
                    },
                    {
                        label: 'High',
                        data: [],
                        borderColor: this.colorSchemes.warning,
                        backgroundColor: 'transparent',
                        borderWidth: 2,
                        tension: 0.3,
                        pointRadius: 2
                    },
                    {
                        label: 'Medium',
                        data: [],
                        borderColor: this.colorSchemes.primary,
                        backgroundColor: 'transparent',
                        borderWidth: 2,
                        tension: 0.3,
                        pointRadius: 2
                    },
                    {
                        label: 'Low',
                        data: [],
                        borderColor: this.colorSchemes.success,
                        backgroundColor: 'transparent',
                        borderWidth: 2,
                        tension: 0.3,
                        pointRadius: 2
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                },
                scales: {
                    x: {
                        title: {
                            display: true,
                            text: 'Time'
                        },
                        ticks: {
                            maxRotation: 45,
                            minRotation: 45
                        }
                    },
                    y: {
                        title: {
                            display: true,
                            text: 'Number of Alerts'
                        },
                        beginAtZero: true,
                        stacked: false
                    }
                }
            }
        });
    }
    
    createGeoChart() {
        // Placeholder for geographic distribution (requires additional library)
        const canvas = document.getElementById('geoChart');
        if (!canvas) return;
        
        // This would be implemented with a map library like Leaflet or Mapbox
        console.log('Geo chart would be initialized here');
    }
    
    updatePacketRateData(packetsPerSec, mbps) {
        const chart = this.charts.packetRate;
        if (!chart) return;
        
        const now = new Date().toLocaleTimeString();
        
        // Keep last 30 data points
        if (chart.data.labels.length > 30) {
            chart.data.labels.shift();
            chart.data.datasets[0].data.shift();
            chart.data.datasets[1].data.shift();
        }
        
        chart.data.labels.push(now);
        chart.data.datasets[0].data.push(packetsPerSec || 0);
        chart.data.datasets[1].data.push(mbps || 0);
        
        chart.update('none'); // 'none' for performance, 'active' for animation
    }
    
    updateSeverityChart(severityData) {
        const chart = this.charts.threatSeverity;
        if (!chart) return;
        
        const data = [
            severityData.critical || 0,
            severityData.high || 0,
            severityData.medium || 0,
            severityData.low || 0
        ];
        
        chart.data.datasets[0].data = data;
        chart.update();
        
        // Update center text
        const total = data.reduce((a, b) => a + b, 0);
        const canvas = document.getElementById('threatTrendChart');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            // The center text will be updated on next draw
            chart.update();
        }
    }
    
    updateProtocolChart(protocols) {
        const chart = this.charts.protocol;
        if (!chart) return;
        
        const labels = Object.keys(protocols || {});
        const data = Object.values(protocols || {});
        
        chart.data.labels = labels;
        chart.data.datasets[0].data = data;
        chart.update();
    }
    
    updateTopAttackersChart(attackers) {
        const chart = this.charts.topAttackers;
        if (!chart) return;
        
        const top10 = attackers.slice(0, 10);
        chart.data.labels = top10.map(a => a.ip);
        chart.data.datasets[0].data = top10.map(a => a.count);
        chart.update();
    }
    
    updateTrafficTimeline(incoming, outgoing) {
        const chart = this.charts.trafficTimeline;
        if (!chart) return;
        
        const now = new Date().toLocaleTimeString();
        
        if (chart.data.labels.length > 30) {
            chart.data.labels.shift();
            chart.data.datasets[0].data.shift();
            chart.data.datasets[1].data.shift();
        }
        
        chart.data.labels.push(now);
        chart.data.datasets[0].data.push(incoming || 0);
        chart.data.datasets[1].data.push(outgoing || 0);
        
        chart.update('none');
    }
    
    updateAlertTrend(timeframe, data) {
        const chart = this.charts.alertTrend;
        if (!chart) return;
        
        // Data format: { timestamps: [], critical: [], high: [], medium: [], low: [] }
        if (data && data.timestamps) {
            chart.data.labels = data.timestamps;
            chart.data.datasets[0].data = data.critical || [];
            chart.data.datasets[1].data = data.high || [];
            chart.data.datasets[2].data = data.medium || [];
            chart.data.datasets[3].data = data.low || [];
            chart.update();
        }
    }
    
    startRealTimeUpdates() {
        // Fetch initial data
        this.fetchAndUpdateCharts();
        
        // Set up periodic updates
        this.updateIntervals.charts = setInterval(() => {
            this.fetchAndUpdateCharts();
        }, 5000);
    }
    
    async fetchAndUpdateCharts() {
        try {
            const [statsResponse, alertsResponse] = await Promise.all([
                fetch('/api/stats'),
                fetch('/api/alerts?limit=100')
            ]);
            
            const stats = await statsResponse.json();
            const alerts = await alertsResponse.json();
            
            // Update packet rate chart
            if (stats.packets && stats.packets.rates) {
                this.updatePacketRateData(
                    stats.packets.rates.packets_per_sec || 0,
                    stats.packets.rates.mbits_per_sec || 0
                );
            }
            
            // Update protocol chart
            if (stats.packets && stats.packets.protocols) {
                this.updateProtocolChart(stats.packets.protocols);
            }
            
            // Calculate and update severity data
            const severityData = this.calculateSeverityData(alerts);
            this.updateSeverityChart(severityData);
            
            // Calculate and update top attackers
            const topAttackers = this.calculateTopAttackers(alerts);
            this.updateTopAttackersChart(topAttackers);
            
            // Update alert trend
            const trendData = this.calculateAlertTrend(alerts);
            this.updateAlertTrend('1h', trendData);
            
        } catch (error) {
            console.error('Error fetching chart data:', error);
        }
    }
    
    calculateSeverityData(alerts) {
        const severity = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };
        
        alerts.forEach(alert => {
            if (severity[alert.severity] !== undefined) {
                severity[alert.severity]++;
            }
        });
        
        return severity;
    }
    
    calculateTopAttackers(alerts, limit = 10) {
        const attackerCount = new Map();
        
        alerts.forEach(alert => {
            const srcIp = alert.packet_info?.src_ip;
            if (srcIp && srcIp !== 'Unknown') {
                attackerCount.set(srcIp, (attackerCount.get(srcIp) || 0) + 1);
            }
        });
        
        return Array.from(attackerCount.entries())
            .map(([ip, count]) => ({ ip, count }))
            .sort((a, b) => b.count - a.count)
            .slice(0, limit);
    }
    
    calculateAlertTrend(alerts, hours = 24) {
        const now = new Date();
        const hourBuckets = {};
        
        alerts.forEach(alert => {
            const alertTime = new Date(alert.timestamp);
            const hourDiff = (now - alertTime) / (1000 * 60 * 60);
            
            if (hourDiff <= hours) {
                const hourKey = Math.floor(alertTime.getTime() / (1000 * 60 * 60));
                if (!hourBuckets[hourKey]) {
                    hourBuckets[hourKey] = {
                        timestamp: alertTime,
                        critical: 0,
                        high: 0,
                        medium: 0,
                        low: 0
                    };
                }
                hourBuckets[hourKey][alert.severity]++;
            }
        });
        
        // Sort by time
        const sorted = Object.values(hourBuckets).sort((a, b) => 
            a.timestamp - b.timestamp
        );
        
        return {
            timestamps: sorted.map(b => b.timestamp.toLocaleTimeString()),
            critical: sorted.map(b => b.critical),
            high: sorted.map(b => b.high),
            medium: sorted.map(b => b.medium),
            low: sorted.map(b => b.low)
        };
    }
    
    setupResizeHandler() {
        let resizeTimeout;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(() => {
                Object.values(this.charts).forEach(chart => {
                    if (chart && chart.resize) {
                        chart.resize();
                    }
                });
            }, 250);
        });
    }
    
    exportChartAsImage(chartId) {
        const chart = this.charts[chartId];
        if (!chart) return;
        
        const canvas = chart.canvas;
        const link = document.createElement('a');
        link.download = `${chartId}_${new Date().toISOString()}.png`;
        link.href = canvas.toDataURL();
        link.click();
    }
    
    toggleChartLegend(chartId) {
        const chart = this.charts[chartId];
        if (!chart) return;
        
        chart.options.plugins.legend.display = !chart.options.plugins.legend.display;
        chart.update();
    }
    
    resetChartZoom(chartId) {
        const chart = this.charts[chartId];
        if (chart && chart.resetZoom) {
            chart.resetZoom();
        }
    }
    
    destroy() {
        // Clear all update intervals
        Object.values(this.updateIntervals).forEach(interval => {
            clearInterval(interval);
        });
        
        // Destroy all charts
        Object.values(this.charts).forEach(chart => {
            if (chart && chart.destroy) {
                chart.destroy();
            }
        });
        
        this.charts = {};
    }
}

// Initialize charts manager when DOM is ready
let chartsManager;
document.addEventListener('DOMContentLoaded', () => {
    chartsManager = new ChartsManager();
    window.chartsManager = chartsManager;
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ChartsManager };
}