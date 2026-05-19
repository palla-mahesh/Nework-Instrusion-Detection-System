"""
Automated Response Engine for Threat Mitigation
"""

import subprocess
import threading
import time
import logging
from typing import Dict, List, Set
from collections import defaultdict
from datetime import datetime, timedelta

from config.settings import RESPONSE_ACTIONS, BLOCKED_IPS, ALLOWED_IPS

class ResponseEngine:
    """Automated response system for detected threats"""
    
    def __init__(self):
        self.blocked_ips: Set[str] = set()
        self.rate_limited_ips: Dict[str, float] = {}
        self.action_history: List[Dict] = []
        self.logger = logging.getLogger(__name__)
        self.cleanup_thread = None
        self.is_running = False
        
    def start(self):
        """Start cleanup thread"""
        self.is_running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
        
    def stop(self):
        """Stop response engine"""
        self.is_running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=2)
            
    def handle_threat(self, threat: Dict):
        """Take appropriate action based on threat severity"""
        severity = threat.get('severity', 'low')
        src_ip = threat.get('packet_info', {}).get('src_ip')
        
        if not src_ip or src_ip in ALLOWED_IPS:
            return
            
        actions = RESPONSE_ACTIONS.get(severity, RESPONSE_ACTIONS['low'])
        
        for action in actions:
            if action == 'log_only':
                self._log_action(threat, 'logged')
            elif action == 'send_alert':
                # Alert already sent by AlertManager
                pass
            elif action == 'rate_limit':
                self._apply_rate_limit(src_ip)
            elif action == 'block_ip':
                self._block_ip(src_ip, threat)
            elif action == 'notify_admin':
                self._notify_admin(threat)
                
    def _block_ip(self, ip: str, threat: Dict):
        """Block IP address using iptables"""
        if ip in self.blocked_ips or ip in ALLOWED_IPS:
            return
            
        try:
            # Add to iptables (Linux)
            subprocess.run(
                ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                check=True,
                capture_output=True
            )
            self.blocked_ips.add(ip)
            BLOCKED_IPS.add(ip)
            
            self._log_action(threat, f'blocked IP: {ip}')
            self.logger.warning(f"Blocked IP: {ip} due to {threat.get('attack_type')}")
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to block IP {ip}: {e}")
            
    def _apply_rate_limit(self, ip: str):
        """Apply rate limiting to IP"""
        try:
            subprocess.run(
                ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-m', 'limit', 
                 '--limit', '10/second', '-j', 'ACCEPT'],
                check=True,
                capture_output=True
            )
            self.rate_limited_ips[ip] = time.time()
            self.logger.info(f"Rate limited IP: {ip}")
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to rate limit IP {ip}: {e}")
            
    def _notify_admin(self, threat: Dict):
        """Send admin notification"""
        message = f"""
        CRITICAL SECURITY THREAT DETECTED
        
        Type: {threat.get('attack_type')}
        Severity: {threat.get('severity')}
        Confidence: {threat.get('confidence', 0)*100:.1f}%
        Source IP: {threat.get('packet_info', {}).get('src_ip', 'Unknown')}
        Time: {datetime.now().isoformat()}
        
        Automated action has been taken.
        """
        
        # Could integrate with Slack, Teams, etc.
        self.logger.critical(message)
        
    def _log_action(self, threat: Dict, action: str):
        """Log response action"""
        self.action_history.append({
            'timestamp': datetime.now(),
            'threat': threat.get('attack_type'),
            'severity': threat.get('severity'),
            'action': action,
            'ip': threat.get('packet_info', {}).get('src_ip')
        })
        
        # Keep only last 1000 actions
        self.action_history = self.action_history[-1000:]
        
    def _cleanup_loop(self):
        """Periodically clean up blocked IPs"""
        while self.is_running:
            time.sleep(300)  # Every 5 minutes
            self._cleanup_old_blocks()
            
    def _cleanup_old_blocks(self):
        """Remove old IP blocks after duration"""
        # This would require tracking block times
        # Simplified version - unblock after 5 minutes
        current_time = time.time()
        
        # For demonstration, we'll just log
        self.logger.debug("Running cleanup of old blocks")
        
    def unblock_ip(self, ip: str):
        """Manually unblock an IP"""
        if ip in self.blocked_ips:
            try:
                subprocess.run(
                    ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                    check=True,
                    capture_output=True
                )
                self.blocked_ips.discard(ip)
                self.logger.info(f"Unblocked IP: {ip}")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to unblock IP {ip}: {e}")
                
    def get_blocked_ips(self) -> List[str]:
        """Get list of blocked IPs"""
        return list(self.blocked_ips)
        
    def get_action_history(self, limit: int = 50) -> List[Dict]:
        """Get recent response actions"""
        return self.action_history[-limit:]