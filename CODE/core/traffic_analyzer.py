"""
Advanced Traffic Analyzer for Network Behavior Analysis
"""

import numpy as np
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Any
import logging

class TrafficAnalyzer:
    """Analyze network traffic patterns and generate insights"""
    
    def __init__(self):
        self.traffic_history = []
        self.baseline = None
        self.logger = logging.getLogger(__name__)
        
    def analyze_traffic(self, current_stats: Dict) -> Dict:
        """Analyze current traffic and detect anomalies"""
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'summary': current_stats,
            'insights': [],
            'recommendations': []
        }
        
        # Add to history
        self.traffic_history.append({
            'timestamp': datetime.now(),
            'stats': current_stats
        })
        
        # Keep last hour of data
        cutoff = datetime.now() - timedelta(hours=1)
        self.traffic_history = [h for h in self.traffic_history if h['timestamp'] > cutoff]
        
        # Generate insights
        insights = self._generate_insights(current_stats)
        analysis['insights'].extend(insights)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(current_stats)
        analysis['recommendations'].extend(recommendations)
        
        return analysis
        
    def _generate_insights(self, stats: Dict) -> List[str]:
        """Generate insights from traffic patterns"""
        insights = []
        
        # Check for traffic spikes
        if len(self.traffic_history) > 10:
            recent_rates = [h['stats'].get('rates', {}).get('packets_per_sec', 0) 
                          for h in self.traffic_history[-10:]]
            avg_rate = np.mean(recent_rates)
            current_rate = stats.get('rates', {}).get('packets_per_sec', 0)
            
            if current_rate > avg_rate * 3:
                insights.append(f"Significant traffic spike detected: {current_rate:.1f} pps (avg: {avg_rate:.1f} pps)")
                
        # Protocol distribution insights
        protocols = stats.get('protocols', {})
        if protocols:
            top_protocol = max(protocols, key=protocols.get)
            insights.append(f"Most active protocol: {top_protocol} ({protocols[top_protocol]} packets)")
            
        # Bandwidth utilization
        bandwidth = stats.get('rates', {}).get('mbits_per_sec', 0)
        if bandwidth > 100:
            insights.append(f"High bandwidth utilization: {bandwidth:.1f} Mbps")
        elif bandwidth > 50:
            insights.append(f"Moderate bandwidth utilization: {bandwidth:.1f} Mbps")
            
        return insights
        
    def _generate_recommendations(self, stats: Dict) -> List[str]:
        """Generate security recommendations based on traffic"""
        recommendations = []
        
        # Rate-based recommendations
        rate = stats.get('rates', {}).get('packets_per_sec', 0)
        if rate > 1000:
            recommendations.append("Consider implementing rate limiting for DDoS protection")
            
        # Protocol recommendations
        protocols = stats.get('protocols', {})
        if protocols.get('ICMP', 0) > 100:
            recommendations.append("High ICMP traffic detected - investigate potential ping flood")
            
        if protocols.get('TCP', 0) > protocols.get('UDP', 0) * 10:
            recommendations.append("Unusually high TCP to UDP ratio - check for port scanning")
            
        return recommendations
        
    def get_traffic_patterns(self) -> Dict:
        """Analyze historical traffic patterns"""
        if len(self.traffic_history) < 10:
            return {'status': 'insufficient_data'}
            
        rates = [h['stats'].get('rates', {}).get('packets_per_sec', 0) 
                for h in self.traffic_history]
        
        return {
            'mean_rate': np.mean(rates),
            'std_rate': np.std(rates),
            'max_rate': np.max(rates),
            'min_rate': np.min(rates),
            'trend': 'increasing' if rates[-1] > rates[0] else 'decreasing',
            'volatility': np.std(rates) / max(1, np.mean(rates))
        }