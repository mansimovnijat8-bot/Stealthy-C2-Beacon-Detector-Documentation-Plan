# src/core/conn_analyzer.py
import pandas as pd
from collections import defaultdict
from datetime import datetime
import logging
from typing import Dict, List, Tuple, Set, Any, Optional
import math
import ipaddress
from dataclasses import dataclass
from enum import Enum

from ..utils.helpers import calculate_statistics, is_internal_ip, safe_divide

logger = logging.getLogger('ConnAnalyzer')

class AlertSeverity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

@dataclass
class ConnMetrics:
    """Data class for connection analysis metrics"""
    total_connections: int = 0
    unique_sources: int = 0
    unique_destinations: int = 0
    unique_ports: int = 0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    avg_connections_per_source: float = 0.0
    connection_rate_per_minute: float = 0.0

class ConnAnalyzer:
    """
    Professional connection analysis engine for network traffic monitoring
    and anomaly detection
    """
    
    def __init__(self, config: Dict):
        """
        Initialize connection analyzer with configuration
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.thresholds = config.get('thresholds', {})
        
        # Initialize data structures
        self.source_conn_count = defaultdict(int)
        self.dest_conn_count = defaultdict(int)
        self.port_conn_count = defaultdict(int)
        self.protocol_count = defaultdict(int)
        self.conn_state_count = defaultdict(int)
        
        self.source_bytes_sent = defaultdict(int)
        self.source_bytes_received = defaultdict(int)
        self.dest_bytes_sent = defaultdict(int)
        self.dest_bytes_received = defaultdict(int)
        
        self.source_temporal_patterns = defaultdict(list)
        self.long_connections = defaultdict(list)
        self.high_throughput_conns = defaultdict(list)
        
        self.internal_ips = set()
        self.external_ips = set()
        self.private_ips = set()
        self.public_ips = set()
        
        # Statistics
        self.metrics = ConnMetrics()
        self.analysis_start = datetime.now()
        
        # Known suspicious ports
        self.suspicious_ports = {
            4444, 5555, 6666, 7777, 8888, 9999,  # Common backdoor ports
            31337, 12345, 12346, 20034,          # NetBus, Sub7, BackOrifice
            27374, 54320, 54321,                 # Sub7, BackOrifice
            9989, 10000, 10001,                  # Other suspicious
            2323, 23231, 27374, 65535            # More suspicious ports
        }
        
        logger.info("Connection Analyzer initialized with professional detection algorithms")

    def process_conn_data(self, zeek_parser, log_type: str = "conn") -> bool:
        """
        Process connection data with enhanced validation and statistics
        
        Args:
            zeek_parser: ZeekLogParser instance with loaded data
            log_type: Type of log to process (default: "conn")
            
        Returns:
            True if successful, False otherwise
        """
        if log_type not in zeek_parser.log_dataframes:
            logger.error(f"Log type '{log_type}' not found in parser data")
            return False
            
        df = zeek_parser.log_dataframes[log_type]
        
        if df.empty:
            logger.warning(f"No connection data to process for log type '{log_type}'")
            return False
            
        try:
            # Reset metrics for new processing
            self._reset_metrics()
            
            # Basic metrics
            self.metrics.total_connections = len(df)
            
            # Check for required columns
            required_columns = ['id.orig_h', 'id.resp_h', 'id.resp_p', 'proto', 'conn_state']
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                logger.warning(f"Missing some columns in connection data: {missing_columns}")
            
            if 'id.orig_h' in df.columns:
                self.metrics.unique_sources = df['id.orig_h'].nunique()
            if 'id.resp_h' in df.columns:
                self.metrics.unique_destinations = df['id.resp_h'].nunique()
            if 'id.resp_p' in df.columns:
                self.metrics.unique_ports = df['id.resp_p'].nunique()
            
            # Process each record
            for _, row in df.iterrows():
                source_ip = row.get('id.orig_h', '')
                dest_ip = row.get('id.resp_h', '')
                dest_port = row.get('id.resp_p', 0)
                protocol = row.get('proto', 'unknown')
                conn_state = row.get('conn_state', '')
                orig_bytes = int(row.get('orig_bytes', 0)) if pd.notna(row.get('orig_bytes')) else 0
                resp_bytes = int(row.get('resp_bytes', 0)) if pd.notna(row.get('resp_bytes')) else 0
                duration = float(row.get('duration', 0)) if pd.notna(row.get('duration')) else 0
                
                # Update counters
                if source_ip:
                    self.source_conn_count[source_ip] += 1
                    self.source_bytes_sent[source_ip] += orig_bytes
                    self.source_bytes_received[source_ip] += resp_bytes
                
                if dest_ip:
                    self.dest_conn_count[dest_ip] += 1
                    self.dest_bytes_sent[dest_ip] += resp_bytes
                    self.dest_bytes_received[dest_ip] += orig_bytes
                
                if dest_port:
                    self.port_conn_count[dest_port] += 1
                
                self.protocol_count[protocol] += 1
                self.conn_state_count[conn_state] += 1
                
                # Update total bytes
                self.metrics.total_bytes_sent += orig_bytes
                self.metrics.total_bytes_received += resp_bytes
                
                # Detect suspicious patterns
                self._detect_suspicious_patterns(source_ip, dest_ip, dest_port, protocol, 
                                               orig_bytes, resp_bytes, duration, conn_state)
                
                # Classify IP addresses
                self._classify_ip_addresses(source_ip, dest_ip)
                
                # Store timestamp for temporal analysis
                if isinstance(row.name, pd.Timestamp):
                    if source_ip:
                        self.source_temporal_patterns[source_ip].append(row.name)
                elif 'ts' in row and pd.notna(row['ts']):
                    try:
                        timestamp = pd.to_datetime(row['ts'])
                        if source_ip:
                            self.source_temporal_patterns[source_ip].append(timestamp)
                    except (ValueError, TypeError):
                        pass
            
            # Calculate derived metrics
            total_sources = max(len(self.source_conn_count), 1)
            self.metrics.avg_connections_per_source = safe_divide(
                sum(self.source_conn_count.values()), total_sources
            )
            
            # Calculate connection rate
            time_span = (datetime.now() - self.analysis_start).total_seconds() / 60
            self.metrics.connection_rate_per_minute = safe_divide(
                self.metrics.total_connections, max(time_span, 1)
            )
            
            logger.info(f"Processed {self.metrics.total_connections} connections "
                       f"from {self.metrics.unique_sources} sources")
            
            return True
                       
        except Exception as e:
            logger.error(f"Error processing connection data: {e}")
            return False

    def _detect_suspicious_patterns(self, source_ip: str, dest_ip: str, dest_port: int, 
                                  protocol: str, orig_bytes: int, resp_bytes: int, 
                                  duration: float, conn_state: str):
        """Detect suspicious patterns in connection data"""
        
        # Check suspicious ports
        if dest_port in self.suspicious_ports:
            self.high_throughput_conns[source_ip].append({
                'dest_ip': dest_ip,
                'dest_port': dest_port,
                'bytes_sent': orig_bytes,
                'bytes_received': resp_bytes
            })
        
        # Check long connections
        long_duration_threshold = self.thresholds.get('long_connection_duration', 3600)  # 1 hour
        if duration > long_duration_threshold:
            self.long_connections[source_ip].append({
                'dest_ip': dest_ip,
                'duration': duration,
                'bytes_sent': orig_bytes,
                'bytes_received': resp_bytes
            })
        
        # Check high throughput connections
        throughput_threshold = self.thresholds.get('high_throughput_bytes', 104857600)  # 100MB
        total_bytes = orig_bytes + resp_bytes
        if total_bytes > throughput_threshold:
            self.high_throughput_conns[source_ip].append({
                'dest_ip': dest_ip,
                'dest_port': dest_port,
                'total_bytes': total_bytes,
                'duration': duration
            })

    def _classify_ip_addresses(self, source_ip: str, dest_ip: str):
        """Classify IP addresses into different categories"""
        
        def classify_single_ip(ip):
            if not ip:
                return
                
            try:
                ip_obj = ipaddress.ip_address(ip)
                
                if ip_obj.is_private:
                    self.private_ips.add(ip)
                else:
                    self.public_ips.add(ip)
                    
                if is_internal_ip(ip):
                    self.internal_ips.add(ip)
                else:
                    self.external_ips.add(ip)
                    
            except ValueError:
                pass
        
        classify_single_ip(source_ip)
        classify_single_ip(dest_ip)

    def _reset_metrics(self):
        """Reset all metrics and data structures"""
        self.source_conn_count.clear()
        self.dest_conn_count.clear()
        self.port_conn_count.clear()
        self.protocol_count.clear()
        self.conn_state_count.clear()
        
        self.source_bytes_sent.clear()
        self.source_bytes_received.clear()
        self.dest_bytes_sent.clear()
        self.dest_bytes_received.clear()
        
        self.source_temporal_patterns.clear()
        self.long_connections.clear()
        self.high_throughput_conns.clear()
        
        self.internal_ips.clear()
        self.external_ips.clear()
        self.private_ips.clear()
        self.public_ips.clear()
        
        self.metrics = ConnMetrics()
        self.analysis_start = datetime.now()

    def detect_anomalies(self) -> List[Dict]:
        """
        Comprehensive connection anomaly detection
        
        Returns:
            List of alert dictionaries
        """
        alerts = []
        
        if self.metrics.total_connections == 0:
            logger.warning("No connection data available for anomaly detection")
            return alerts
        
        # Run all detection methods
        alerts.extend(self._detect_volume_anomalies())
        alerts.extend(self._detect_port_anomalies())
        alerts.extend(self._detect_throughput_anomalies())
        alerts.extend(self._detect_duration_anomalies())
        alerts.extend(self._detect_temporal_anomalies())
        alerts.extend(self._detect_geographical_anomalies())
        
        # Sort alerts by severity
        alerts.sort(key=lambda x: x.get('severity_score', 0), reverse=True)
        
        logger.info(f"Generated {len(alerts)} connection anomaly alerts")
        return alerts

    def _detect_volume_anomalies(self) -> List[Dict]:
        """Detect volume-based anomalies"""
        alerts = []
        if not self.source_conn_count:
            return alerts
            
        threshold = self.thresholds.get('conn_per_minute', 500)
        avg_volume = self.metrics.avg_connections_per_source
        
        for source, count in self.source_conn_count.items():
            # Absolute threshold
            if count > threshold:
                severity_score = min(100, (count / threshold) * 100)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'HIGH_CONNECTION_VOLUME',
                    'severity': 'HIGH',
                    'severity_score': severity_score,
                    'source_ip': source,
                    'connection_count': count,
                    'threshold': threshold,
                    'description': f'Excessive connections: {count} connections (threshold: {threshold})'
                })
            
            # Relative threshold (5x average)
            elif count > avg_volume * 5 and avg_volume > 10:
                severity_score = min(90, (count / (avg_volume * 5)) * 100)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'ABNORMAL_CONNECTION_VOLUME',
                    'severity': 'MEDIUM',
                    'severity_score': severity_score,
                    'source_ip': source,
                    'connection_count': count,
                    'average_volume': avg_volume,
                    'description': f'Abnormal connection volume: {count} connections (5x average: {avg_volume:.1f})'
                })
                
        return alerts

    def _detect_port_anomalies(self) -> List[Dict]:
        """Detect port-based anomalies"""
        alerts = []
        
        # Suspicious ports
        suspicious_threshold = self.thresholds.get('suspicious_port_count', 3)
        for source, connections in self.high_throughput_conns.items():
            suspicious_ports = set()
            for conn in connections:
                if conn['dest_port'] in self.suspicious_ports:
                    suspicious_ports.add(conn['dest_port'])
            
            if len(suspicious_ports) >= suspicious_threshold:
                severity_score = min(100, (len(suspicious_ports) / suspicious_threshold) * 100)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'SUSPICIOUS_PORTS',
                    'severity': 'HIGH',
                    'severity_score': severity_score,
                    'source_ip': source,
                    'suspicious_port_count': len(suspicious_ports),
                    'ports': list(suspicious_ports),
                    'description': f'Multiple suspicious ports detected: {len(suspicious_ports)} ports'
                })
                
        return alerts

    def _detect_throughput_anomalies(self) -> List[Dict]:
        """Detect throughput anomalies"""
        alerts = []
        
        throughput_threshold = self.thresholds.get('high_throughput_bytes', 104857600)  # 100MB
        for source, connections in self.high_throughput_conns.items():
            high_throughput_count = 0
            total_throughput = 0
            
            for conn in connections:
                if conn.get('total_bytes', 0) > throughput_threshold:
                    high_throughput_count += 1
                    total_throughput += conn['total_bytes']
            
            if high_throughput_count > 0:
                severity_score = min(100, (total_throughput / throughput_threshold) * 10)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'HIGH_THROUGHPUT',
                    'severity': 'MEDIUM',
                    'severity_score': severity_score,
                    'source_ip': source,
                    'high_throughput_count': high_throughput_count,
                    'total_bytes': total_throughput,
                    'description': f'High throughput connections detected: {high_throughput_count} connections'
                })
                
        return alerts

    def _detect_duration_anomalies(self) -> List[Dict]:
        """Detect duration anomalies"""
        alerts = []
        
        duration_threshold = self.thresholds.get('long_connection_duration', 3600)  # 1 hour
        for source, connections in self.long_connections.items():
            long_connections_count = 0
            max_duration = 0
            
            for conn in connections:
                if conn['duration'] > duration_threshold:
                    long_connections_count += 1
                    max_duration = max(max_duration, conn['duration'])
            
            if long_connections_count > 0:
                severity_score = min(100, (max_duration / duration_threshold) * 50)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'LONG_CONNECTIONS',
                    'severity': 'MEDIUM',
                    'severity_score': severity_score,
                    'source_ip': source,
                    'long_connection_count': long_connections_count,
                    'max_duration': max_duration,
                    'description': f'Long duration connections detected: {long_connections_count} connections'
                })
                
        return alerts

    def _detect_temporal_anomalies(self) -> List[Dict]:
        """Detect temporal patterns"""
        alerts = []
        std_threshold = self.thresholds.get('conn_beacon_interval_std', 5.0)
        
        for source, timestamps in self.source_temporal_patterns.items():
            if len(timestamps) < 20:  # Minimum samples for connection analysis
                continue
                
            timestamps.sort()
            intervals = [(timestamps[i] - timestamps[i-1]).total_seconds() 
                       for i in range(1, len(timestamps))]
            
            if not intervals:
                continue
                
            stats = calculate_statistics(intervals)
            
            # Detect regular beaconing (low standard deviation)
            if stats['stdev'] < std_threshold and stats['mean'] > 0:
                severity = min(100, (std_threshold / max(stats['stdev'], 0.1)) * 20)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'CONNECTION_BEACONING',
                    'severity': 'HIGH',
                    'severity_score': severity,
                    'source_ip': source,
                    'interval_mean': stats['mean'],
                    'interval_stdev': stats['stdev'],
                    'connection_count': len(timestamps),
                    'description': f'Regular connection beaconing detected ({stats["mean"]:.1f}s ± {stats["stdev"]:.1f}s)'
                })
                
        return alerts

    def _detect_geographical_anomalies(self) -> List[Dict]:
        """Detect geographical anomalies"""
        alerts = []
        
        # Internal to external ratio anomaly
        internal_ext_threshold = self.thresholds.get('internal_external_ratio', 0.1)
        for source in self.source_conn_count.keys():
            if source in self.internal_ips:
                internal_conns = self.source_conn_count[source]
                total_conns = internal_conns
                
                # Estimate external connections (simplified)
                external_ratio = safe_divide(len(self.external_ips), total_conns)
                
                if external_ratio > internal_ext_threshold and total_conns > 50:
                    severity_score = min(100, (external_ratio / internal_ext_threshold) * 100)
                    alerts.append({
                        'timestamp': datetime.now(),
                        'alert_type': 'HIGH_EXTERNAL_TRAFFIC',
                        'severity': 'MEDIUM',
                        'severity_score': severity_score,
                        'source_ip': source,
                        'external_ratio': external_ratio,
                        'total_connections': total_conns,
                        'description': f'High external traffic ratio: {external_ratio:.1%}'
                    })
                
        return alerts

    def generate_detailed_report(self) -> Dict:
        """
        Generate comprehensive connection analysis report
        
        Returns:
            Detailed report dictionary
        """
        report = {
            'analysis_period': {
                'start_time': self.analysis_start,
                'end_time': datetime.now(),
                'duration_minutes': (datetime.now() - self.analysis_start).total_seconds() / 60
            },
            'metrics': self.metrics.__dict__,
            'top_sources': dict(sorted(
                self.source_conn_count.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]),
            'top_destinations': dict(sorted(
                self.dest_conn_count.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'top_ports': dict(sorted(
                self.port_conn_count.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'protocols': dict(self.protocol_count),
            'connection_states': dict(self.conn_state_count),
            'network_analysis': {
                'internal_ips_count': len(self.internal_ips),
                'external_ips_count': len(self.external_ips),
                'private_ips_count': len(self.private_ips),
                'public_ips_count': len(self.public_ips),
                'total_bytes_sent_mb': self.metrics.total_bytes_sent / 1024 / 1024,
                'total_bytes_received_mb': self.metrics.total_bytes_received / 1024 / 1024
            }
        }
        
        return report
