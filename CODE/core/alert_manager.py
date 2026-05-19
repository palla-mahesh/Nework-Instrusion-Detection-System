"""
Advanced Alert Management System
"""

import json
import smtplib
import requests
import threading
import logging
from datetime import datetime
from typing import Dict, List, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import deque
from pathlib import Path

from config.settings import ALERT_CONFIG
from core.utils import AlertFormatter

class AlertManager:
    """Centralized alert management with multiple outputs"""
    
    def __init__(self):
        self.alert_queue = deque(maxlen=1000)
        self.alert_history = deque(maxlen=10000)
        self.alert_callbacks = []
        self.logger = logging.getLogger(__name__)
        self.processing_thread = None
        self.is_running = False
        
    def start(self):
        """Start alert processing thread"""
        self.is_running = True
        self.processing_thread = threading.Thread(target=self._process_alerts, daemon=True)
        self.processing_thread.start()
        self.logger.info("Alert manager started")
        
    def stop(self):
        """Stop alert processing"""
        self.is_running = False
        if self.processing_thread:
            self.processing_thread.join(timeout=2)
            
    def add_alert(self, threat_data: Dict):
        """Add new alert to queue"""
        # Add timestamp if not present
        if 'timestamp' not in threat_data:
            threat_data['timestamp'] = datetime.now().isoformat()
            
        # Add alert ID
        threat_data['alert_id'] = hash(f"{threat_data['timestamp']}{threat_data.get('attack_type', '')}")
        
        self.alert_queue.append(threat_data)
        self.alert_history.append(threat_data)
        
        # Trigger immediate processing for critical alerts
        if threat_data.get('severity') == 'critical':
            self._send_immediate_alert(threat_data)
            
        self.logger.info(f"Alert added: {threat_data.get('attack_type')} - {threat_data.get('severity')}")
        
    def register_callback(self, callback):
        """Register callback for real-time alerts (for WebSocket)"""
        self.alert_callbacks.append(callback)
        
    def _process_alerts(self):
        """Background thread for processing alerts"""
        while self.is_running:
            try:
                if self.alert_queue:
                    alert = self.alert_queue.popleft()
                    self._dispatch_alert(alert)
            except Exception as e:
                self.logger.error(f"Alert processing error: {e}")
                
    def _dispatch_alert(self, alert: Dict):
        """Dispatch alert to all configured outputs"""
        severity = alert.get('severity', 'medium')
        
        # Log to file
        self._log_to_file(alert)
        
        # Send email for high/critical
        if severity in ['high', 'critical'] and ALERT_CONFIG['email_enabled']:
            self._send_email_alert(alert)
            
        # Send webhook
        if ALERT_CONFIG['webhook_enabled']:
            self._send_webhook(alert)
            
        # Notify all callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                self.logger.error(f"Callback error: {e}")
                
    def _send_immediate_alert(self, alert: Dict):
        """Send immediate alert for critical threats"""
        self._log_to_file(alert)
        self._send_webhook(alert)
        
        # For critical, also print to console
        print(f"\n🚨 CRITICAL ALERT: {alert.get('attack_type')} from {alert.get('packet_info', {}).get('src_ip', 'unknown')}\n")
        
    def _log_to_file(self, alert: Dict):
        """Log alert to threats.log"""
        log_entry = AlertFormatter.format_json(alert)
        with open(Path('logs/threats.log'), 'a') as f:
            f.write(log_entry + '\n')
            
    def _send_email_alert(self, alert: Dict):
        """Send email alert"""
        try:
            msg = MIMEMultipart()
            msg['From'] = ALERT_CONFIG['sender_email']
            msg['To'] = ', '.join(ALERT_CONFIG['recipient_emails'])
            msg['Subject'] = f"NIDS Alert: {alert.get('attack_type')} - {alert.get('severity').upper()}"
            
            body = AlertFormatter.format_html(alert)
            msg.attach(MIMEText(body, 'html'))
            
            with smtplib.SMTP(ALERT_CONFIG['smtp_server'], ALERT_CONFIG['smtp_port']) as server:
                server.starttls()
                server.login(ALERT_CONFIG['sender_email'], 'your-password-here')
                server.send_message(msg)
                
            self.logger.info(f"Email alert sent for {alert.get('alert_id')}")
        except Exception as e:
            self.logger.error(f"Email failed: {e}")
            
    def _send_webhook(self, alert: Dict):
        """Send webhook notification"""
        try:
            webhook_data = {
                'event': 'security_alert',
                'alert': {
                    'id': alert.get('alert_id'),
                    'type': alert.get('attack_type'),
                    'severity': alert.get('severity'),
                    'confidence': alert.get('confidence'),
                    'source_ip': alert.get('packet_info', {}).get('src_ip'),
                    'destination_ip': alert.get('packet_info', {}).get('dst_ip'),
                    'timestamp': alert.get('timestamp'),
                    'details': alert.get('details', '')
                }
            }
            
            response = requests.post(
                ALERT_CONFIG['webhook_url'],
                json=webhook_data,
                timeout=2
            )
            
            if response.status_code == 200:
                self.logger.debug(f"Webhook sent for alert {alert.get('alert_id')}")
                
        except Exception as e:
            self.logger.debug(f"Webhook failed: {e}")
            
    def get_alerts(self, limit: int = 100, severity: Optional[str] = None) -> List[Dict]:
        """Get recent alerts with optional filtering"""
        alerts = list(self.alert_history)[-limit:]
        
        if severity:
            alerts = [a for a in alerts if a.get('severity') == severity]
            
        return alerts
        
    def get_statistics(self) -> Dict:
        """Get alert statistics"""
        if not self.alert_history:
            return {'total': 0, 'by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}}
            
        stats = {
            'total': len(self.alert_history),
            'by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
            'by_type': {}
        }
        
        for alert in self.alert_history:
            severity = alert.get('severity', 'low')
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            attack_type = alert.get('attack_type', 'UNKNOWN')
            stats['by_type'][attack_type] = stats['by_type'].get(attack_type, 0) + 1
            
        return stats