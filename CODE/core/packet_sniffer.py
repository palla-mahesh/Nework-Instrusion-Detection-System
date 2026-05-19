"""
Advanced Packet Sniffer with Multi-threading Support
"""

import threading
import queue
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from scapy.layers.inet6 import IPv6
import logging
from typing import Dict, Optional, Callable
from datetime import datetime

from config.settings import NETWORK_INTERFACE, PROMISCUOUS_MODE, PACKET_TIMEOUT

class AdvancedPacketSniffer:
    """High-performance packet sniffer with filtering capabilities"""
    
    def __init__(self, packet_queue: queue.Queue):
        self.packet_queue = packet_queue
        self.sniffing = False
        self.sniff_thread = None
        self.filter_rules = []
        self.logger = logging.getLogger(__name__)
        self.packet_count = 0
        
    def start_sniffing(self):
        """Start packet capture in separate thread"""
        self.sniffing = True
        self.sniff_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.sniff_thread.start()
        self.logger.info(f"Packet sniffer started on interface {NETWORK_INTERFACE}")
        
    def stop_sniffing(self):
        """Stop packet capture"""
        self.sniffing = False
        if self.sniff_thread:
            self.sniff_thread.join(timeout=2)
        self.logger.info("Packet sniffer stopped")
        
    def _sniff_packets(self):
        """Internal sniffing method"""
        try:
            sniff(
                iface=NETWORK_INTERFACE,
                prn=self._process_packet,
                store=False,
                timeout=PACKET_TIMEOUT,
                stop_filter=lambda x: not self.sniffing
            )
        except Exception as e:
            self.logger.error(f"Sniffing error: {e}")
            
    def _process_packet(self, packet):
        """Process and extract packet information"""
        try:
            packet_info = self._extract_packet_info(packet)
            
            if self._should_process(packet_info):
                self.packet_queue.put(packet_info)
                self.packet_count += 1
                
        except Exception as e:
            self.logger.debug(f"Error processing packet: {e}")
            
    def _extract_packet_info(self, packet) -> Dict:
        """Extract relevant information from packet"""
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'length': len(packet),
            'protocol': 'UNKNOWN',
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'flags': None,
            'ttl': None,
            'payload': None
        }
        
        # IP Layer
        if IP in packet:
            ip_layer = packet[IP]
            packet_info['src_ip'] = ip_layer.src
            packet_info['dst_ip'] = ip_layer.dst
            packet_info['ttl'] = ip_layer.ttl
            packet_info['protocol'] = 'IP'
            
        elif IPv6 in packet:
            ip6_layer = packet[IPv6]
            packet_info['src_ip'] = ip6_layer.src
            packet_info['dst_ip'] = ip6_layer.dst
            packet_info['ttl'] = ip6_layer.hlim
            packet_info['protocol'] = 'IPv6'
            
        # TCP Layer
        if TCP in packet:
            tcp_layer = packet[TCP]
            packet_info['src_port'] = tcp_layer.sport
            packet_info['dst_port'] = tcp_layer.dport
            packet_info['protocol'] = 'TCP'
            packet_info['flags'] = self._get_tcp_flags(tcp_layer)
            
        # UDP Layer
        elif UDP in packet:
            udp_layer = packet[UDP]
            packet_info['src_port'] = udp_layer.sport
            packet_info['dst_port'] = udp_layer.dport
            packet_info['protocol'] = 'UDP'
            
        # ICMP Layer
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            packet_info['protocol'] = 'ICMP'
            packet_info['icmp_type'] = icmp_layer.type
            packet_info['icmp_code'] = icmp_layer.code
            
        # Extract payload
        if Raw in packet:
            raw_layer = packet[Raw]
            packet_info['payload'] = bytes(raw_layer).hex()[:100]  # First 100 bytes hex
            
        return packet_info
        
    def _get_tcp_flags(self, tcp_layer) -> str:
        """Extract TCP flags as string"""
        flags = []
        if tcp_layer.flags.S: flags.append('S')
        if tcp_layer.flags.A: flags.append('A')
        if tcp_layer.flags.F: flags.append('F')
        if tcp_layer.flags.R: flags.append('R')
        if tcp_layer.flags.P: flags.append('P')
        if tcp_layer.flags.U: flags.append('U')
        return ''.join(flags) if flags else 'None'
        
    def _should_process(self, packet_info: Dict) -> bool:
        """Apply filter rules to packet"""
        # Skip local broadcast/multicast if not needed
        if packet_info.get('dst_ip') in ['255.255.255.255', '224.0.0.1']:
            return True  # Still process for DDoS detection
            
        # Apply custom filters
        for rule in self.filter_rules:
            if not rule(packet_info):
                return False
        return True
        
    def add_filter(self, filter_func: Callable):
        """Add custom packet filter"""
        self.filter_rules.append(filter_func)
        
    def get_stats(self) -> Dict:
        """Get sniffer statistics"""
        return {
            'total_packets_captured': self.packet_count,
            'queue_size': self.packet_queue.qsize(),
            'is_sniffing': self.sniffing
        }