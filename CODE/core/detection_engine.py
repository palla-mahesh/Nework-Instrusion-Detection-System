"""
Advanced Detection Engine with Signature-based and Anomaly-based Detection
"""

import threading
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import logging
import time

from config.settings import (
    THREAT_THRESHOLDS, RATE_LIMITS, PORT_SCAN_THRESHOLD,
    SYN_FLOOD_THRESHOLD, DDOS_THRESHOLD, SIGNATURES
)
from core.ml_detector import MLAnomalyDetector

class DetectionEngine:
    """Multi-layer detection engine for various attack types"""
    
    def __init__(self, alert_callback):
        self.alert_callback = alert_callback
        self.ml_detector = MLAnomalyDetector()
        
        # Trackers for behavioral detection
        self.connection_tracker = defaultdict(lambda: {'count': 0, 'first_seen': time.time(), 'ports': set()})
        self.packet_rate_tracker = defaultdict(list)
        self.syn_tracker = defaultdict(int)
        
        self.logger = logging.getLogger(__name__)
        self.lock = threading.Lock()
        
    def analyze_packet(self, packet: Dict) -> List[Dict]:
        """Comprehensive packet analysis"""
        threats = []
        
        # Run all detection methods
        threats.extend(self._signature_detection(packet))
        threats.extend(self._anomaly_detection(packet))
        threats.extend(self._behavioral_detection(packet))
        threats.extend(self._rate_based_detection(packet))
        
        return threats
        
    def _signature_detection(self, packet: Dict) -> List[Dict]:
        """Signature-based attack detection"""
        threats = []
        
        # Check each signature
        for attack_name, signature_func in SIGNATURES.items():
            try:
                if signature_func(packet):
                    threats.append({
                        'attack_type': attack_name.upper(),
                        'severity': 'high',
                        'confidence': 0.95,
                        'detection_method': 'signature',
                        'packet_info': packet
                    })
            except Exception:
                continue
                
        # Additional signature checks
        if packet.get('protocol') == 'TCP':
            # Port scan detection
            if packet.get('dst_port') in [21, 22, 23, 25, 80, 443, 3306, 5432, 3389]:
                threats.append({
                    'attack_type': 'SERVICE_PROBE',
                    'severity': 'medium',
                    'confidence': 0.7,
                    'detection_method': 'signature',
                    'packet_info': packet
                })
                
        # SQL Injection detection in payload
        if packet.get('payload'):
            payload_str = packet['payload'].lower()
            sql_patterns = ['select', 'union', 'insert', 'drop', 'delete', '--', '1=1']
            if any(pattern in payload_str for pattern in sql_patterns):
                threats.append({
                    'attack_type': 'SQL_INJECTION',
                    'severity': 'critical',
                    'confidence': 0.9,
                    'detection_method': 'signature',
                    'packet_info': packet
                })
                
        return threats
        
    def _anomaly_detection(self, packet: Dict) -> List[Dict]:
        """ML-based anomaly detection"""
        threats = []
        
        is_anomaly, confidence = self.ml_detector.detect_anomaly(packet)
        
        if is_anomaly and confidence > THREAT_THRESHOLDS['medium']:
            severity = 'low'
            if confidence > THREAT_THRESHOLDS['critical']:
                severity = 'critical'
            elif confidence > THREAT_THRESHOLDS['high']:
                severity = 'high'
            elif confidence > THREAT_THRESHOLDS['medium']:
                severity = 'medium'
                
            threats.append({
                'attack_type': 'ANOMALY',
                'severity': severity,
                'confidence': confidence,
                'detection_method': 'ml_anomaly',
                'packet_info': packet
            })
            
        return threats
        
    def _behavioral_detection(self, packet: Dict) -> List[Dict]:
        """Behavioral analysis for complex attacks"""
        threats = []
        
        src_ip = packet.get('src_ip')
        dst_ip = packet.get('dst_ip')
        dst_port = packet.get('dst_port')
        
        if not src_ip:
            return threats
            
        with self.lock:
            # Track connections per source IP
            conn_key = f"{src_ip}_{dst_ip}"
            tracker = self.connection_tracker[conn_key]
            tracker['count'] += 1
            
            if dst_port:
                tracker['ports'].add(dst_port)
                
            # Port scan detection
            if len(tracker['ports']) > PORT_SCAN_THRESHOLD:
                if (time.time() - tracker['first_seen']) < 10:  # Within 10 seconds
                    threats.append({
                        'attack_type': 'PORT_SCAN',
                        'severity': 'medium',
                        'confidence': 0.85,
                        'detection_method': 'behavioral',
                        'packet_info': packet,
                        'details': f"Scanned {len(tracker['ports'])} ports"
                    })
                    
            # Clean old trackers
            current_time = time.time()
            expired = [k for k, v in self.connection_tracker.items() 
                      if current_time - v['first_seen'] > 300]
            for k in expired:
                del self.connection_tracker[k]
                
        return threats
        
    def _rate_based_detection(self, packet: Dict) -> List[Dict]:
        """Rate-based attack detection (DDoS, Flooding)"""
        threats = []
        current_time = time.time()
        src_ip = packet.get('src_ip')
        
        if not src_ip:
            return threats
            
        with self.lock:
            # Track packet rates
            self.packet_rate_tracker[src_ip].append(current_time)
            
            # Remove old entries (last second)
            self.packet_rate_tracker[src_ip] = [
                t for t in self.packet_rate_tracker[src_ip] 
                if current_time - t < 1
            ]
            
            rate = len(self.packet_rate_tracker[src_ip])
            
            # SYN flood detection
            if packet.get('flags') == 'S':
                self.syn_tracker[src_ip] += 1
                syn_rate = self.syn_tracker[src_ip]
                
                if syn_rate > SYN_FLOOD_THRESHOLD:
                    threats.append({
                        'attack_type': 'SYN_FLOOD',
                        'severity': 'critical',
                        'confidence': 0.95,
                        'detection_method': 'rate_based',
                        'packet_info': packet,
                        'details': f"{syn_rate} SYN packets/sec"
                    })
                    
            # General DDoS detection
            if rate > DDOS_THRESHOLD:
                threats.append({
                    'attack_type': 'DDOS_ATTACK',
                    'severity': 'critical',
                    'confidence': 0.9,
                    'detection_method': 'rate_based',
                    'packet_info': packet,
                    'details': f"{rate} packets/sec"
                })
            elif rate > RATE_LIMITS.get('tcp_syn', 200):
                threats.append({
                    'attack_type': 'RATE_LIMIT_EXCEEDED',
                    'severity': 'high',
                    'confidence': 0.75,
                    'detection_method': 'rate_based',
                    'packet_info': packet,
                    'details': f"{rate} packets/sec"
                })
                
            # Reset syn tracker periodically
            if int(current_time) % 10 == 0:
                self.syn_tracker.clear()
                
        return threats
        
    def get_stats(self) -> Dict:
        """Get detection engine statistics"""
        return {
            'ml_stats': self.ml_detector.get_anomaly_stats(),
            'active_connections': len(self.connection_tracker),
            'active_sources': len(self.packet_rate_tracker)
        }