"""
Utility Functions for Advanced NIDS
"""

import hashlib
import json
import logging
import time
from datetime import datetime
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Any, Optional

import pandas as pd
import numpy as np

class ThreatLogger:
    """Advanced logging system for threats"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.setup_loggers()
        
    def setup_loggers(self):
        """Setup specialized loggers"""
        # Threats logger
        self.threats_logger = logging.getLogger('threats')
        self.threats_logger.setLevel(logging.INFO)
        handler = logging.FileHandler(self.config['threats_log'])
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.threats_logger.addHandler(handler)
        
        # Packets logger
        self.packets_logger = logging.getLogger('packets')
        self.packets_logger.setLevel(logging.DEBUG)
        handler2 = logging.FileHandler(self.config['packets_log'])
        handler2.setFormatter(formatter)
        self.packets_logger.addHandler(handler2)
        
    def log_threat(self, threat_data: Dict):
        """Log detected threat"""
        self.threats_logger.warning(json.dumps(threat_data, default=str))
        
    def log_packet(self, packet_info: Dict):
        """Log packet information"""
        self.packets_logger.debug(json.dumps(packet_info, default=str))


class FeatureExtractor:
    """Extract features from packets for ML detection"""
    
    PROTOCOL_MAP = {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'OTHER': 0}
    FLAG_MAP = {'S': 1, 'SA': 2, 'F': 3, 'R': 4, 'A': 5}
    
    def __init__(self):
        self.packet_history = defaultdict(list)
        self.connection_tracker = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': time.time(),
            'last_time': time.time()
        })
        
    def extract_features(self, packet: Dict) -> np.ndarray:
        """Extract feature vector for ML model"""
        features = {}
        
        # Basic packet features
        features['packet_length'] = packet.get('length', 0)
        features['protocol'] = self.PROTOCOL_MAP.get(packet.get('protocol', 'OTHER'), 0)
        features['ttl'] = packet.get('ttl', 64)
        features['flags'] = self.FLAG_MAP.get(packet.get('tcp_flags', ''), 0)
        features['src_port'] = packet.get('src_port', 0)
        features['dst_port'] = packet.get('dst_port', 0)
        
        # Flow-based features
        flow_key = f"{packet.get('src_ip', '')}_{packet.get('dst_ip', '')}_{packet.get('protocol', '')}"
        flow_data = self.connection_tracker[flow_key]
        
        current_time = time.time()
        time_diff = current_time - flow_data['last_time']
        
        features['packet_rate'] = flow_data['packet_count'] / max(1, (current_time - flow_data['start_time']))
        features['bytes_per_sec'] = flow_data['byte_count'] / max(1, (current_time - flow_data['start_time']))
        features['time_since_last'] = time_diff
        
        # Update flow data
        flow_data['packet_count'] += 1
        flow_data['byte_count'] += packet.get('length', 0)
        flow_data['last_time'] = current_time
        
        # Keep only recent history (cleanup every 1000 packets)
        if len(self.packet_history) > 1000:
            self.cleanup_old_connections()
            
        # Return feature vector
        return np.array([[
            features['packet_length'],
            features['protocol'],
            features['ttl'],
            features['flags'],
            features['src_port'],
            features['dst_port'],
            features['packet_rate'],
            features['bytes_per_sec']
        ]])
    
    def cleanup_old_connections(self, timeout: int = 300):
        """Remove old connection data"""
        current_time = time.time()
        to_remove = []
        for key, data in self.connection_tracker.items():
            if current_time - data['last_time'] > timeout:
                to_remove.append(key)
        for key in to_remove:
            del self.connection_tracker[key]


class AlertFormatter:
    """Format alerts for different outputs"""
    
    @staticmethod
    def format_json(threat_data: Dict) -> str:
        """Format as JSON"""
        return json.dumps(threat_data, default=str, indent=2)
    
    @staticmethod
    def format_html(threat_data: Dict) -> str:
        """Format as HTML"""
        html = f"""
        <div class="alert alert-{threat_data.get('severity', 'medium')}">
            <strong>{threat_data.get('attack_type', 'Unknown')}</strong><br>
            Source: {threat_data.get('src_ip', 'Unknown')}<br>
            Destination: {threat_data.get('dst_ip', 'Unknown')}<br>
            Confidence: {threat_data.get('confidence', 0)*100:.1f}%<br>
            Time: {threat_data.get('timestamp', 'Unknown')}
        </div>
        """
        return html
    
    @staticmethod
    def format_syslog(threat_data: Dict) -> str:
        """Format for syslog"""
        return f"NIDS[{threat_data.get('severity', 'info')}]: {threat_data.get('attack_type')} from {threat_data.get('src_ip')} to {threat_data.get('dst_ip')}"


class PacketStats:
    """Real-time packet statistics"""
    
    def __init__(self):
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'packets_by_protocol': defaultdict(int),
            'packets_by_source': defaultdict(int),
            'top_attackers': defaultdict(int),
            'start_time': time.time()
        }
        
    def update(self, packet: Dict):
        """Update statistics with new packet"""
        self.stats['total_packets'] += 1
        self.stats['total_bytes'] += packet.get('length', 0)
        self.stats['packets_by_protocol'][packet.get('protocol', 'UNKNOWN')] += 1
        self.stats['packets_by_source'][packet.get('src_ip', 'UNKNOWN')] += 1
        
    def get_rates(self) -> Dict:
        """Get current packet rates"""
        elapsed = time.time() - self.stats['start_time']
        return {
            'packets_per_sec': self.stats['total_packets'] / max(1, elapsed),
            'bytes_per_sec': self.stats['total_bytes'] / max(1, elapsed),
            'mbits_per_sec': (self.stats['total_bytes'] * 8) / (max(1, elapsed) * 1000000)
        }
    
    def get_summary(self) -> Dict:
        """Get statistics summary"""
        return {
            'total_packets': self.stats['total_packets'],
            'total_bytes': self.stats['total_bytes'],
            'protocols': dict(self.stats['packets_by_protocol']),
            'rates': self.get_rates()
        }