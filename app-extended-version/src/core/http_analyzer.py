# src/core/http_analyzer.py
import pandas as pd
from collections import defaultdict
from datetime import datetime
import logging
from typing import Dict, List, Tuple, Set, Any, Optional
import math
import re
from dataclasses import dataclass
from enum import Enum

from ..utils.helpers import calculate_statistics, is_internal_ip, safe_divide

logger = logging.getLogger('HTTPAnalyzer')

class AlertSeverity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

@dataclass
class HTTPMetrics:
    """Data class for HTTP analysis metrics"""
    total_requests: int = 0
    unique_clients: int = 0
    unique_servers: int = 0
    unique_hosts: int = 0
    unique_uris: int = 0
    avg_requests_per_client: float = 0.0
    request_rate_per_minute: float = 0.0

class HTTPAnalyzer:
    """
    Professional HTTP analysis engine for web traffic monitoring
    and anomaly detection
    """
    
    def __init__(self, config: Dict):
        """
        Initialize HTTP analyzer with configuration
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.thresholds = config.get('thresholds', {})
        
        # Initialize data structures
        self.client_request_count = defaultdict(int)
        self.server_request_count = defaultdict(int)
        self.host_request_count = defaultdict(int)
        self.uri_request_count = defaultdict(int)
        self.user_agent_count = defaultdict(int)
        self.status_code_count = defaultdict(int)
        self.method_count = defaultdict(int)
        
        self.client_temporal_patterns = defaultdict(list)
        self.suspicious_user_agents = defaultdict(int)
        self.suspicious_uris = defaultdict(int)
        
        self.internal_ips = set()
        self.external_ips = set()
        
        # Statistics
        self.metrics = HTTPMetrics()
        self.analysis_start = datetime.now()
        
        # Predefined patterns for detection
        self.suspicious_ua_patterns = [
            r'curl', r'wget', r'python', r'go-http', r'java', 
            r'nmap', r'sqlmap', r'nikto', r'metasploit', r'burp',
            r'scanner', r'spider', r'bot', r'crawler'
        ]
        
        self.suspicious_uri_patterns = [
            r'\.php$', r'\.asp$', r'\.jsp$', r'\/admin', r'\/login',
            r'\/wp-admin', r'\/console', r'\/cmd', r'\/shell',
            r'\/\.env', r'\/config', r'\/backup', r'\.bak$',
            r'\/phpmyadmin', r'\/mysql', r'\/database'
        ]
        
        logger.info("HTTP Analyzer initialized with professional detection algorithms")

    def process_http_data(self, zeek_parser, log_type: str = "http") -> bool:
        """
        Process HTTP data with enhanced validation and statistics
        
        Args:
            zeek_parser: ZeekLogParser instance with loaded data
            log_type: Type of log to process (default: "http")
            
        Returns:
            True if successful, False otherwise
        """
        if log_type not in zeek_parser.log_dataframes:
            logger.error(f"Log type '{log_type}' not found in parser data")
            return False
            
        df = zeek_parser.log_dataframes[log_type]
        
        if df.empty:
            logger.warning(f"No HTTP data to process for log type '{log_type}'")
            return False
            
        try:
            # Reset metrics for new processing
            self._reset_metrics()
            
            # Basic metrics
            self.metrics.total_requests = len(df)
            
            # Check for required columns
            required_columns = ['id.orig_h', 'id.resp_h', 'host', 'uri', 'method']
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                logger.warning(f"Missing some columns in HTTP data: {missing_columns}")
            
            if 'id.orig_h' in df.columns:
                self.metrics.unique_clients = df['id.orig_h'].nunique()
            if 'id.resp_h' in df.columns:
                self.metrics.unique_servers = df['id.resp_h'].nunique()
            if 'host' in df.columns:
                self.metrics.unique_hosts = df['host'].nunique()
            if 'uri' in df.columns:
                self.metrics.unique_uris = df['uri'].nunique()
            
            # Process each record
            for _, row in df.iterrows():
                client_ip = row.get('id.orig_h', '')
                server_ip = row.get('id.resp_h', '')
                host = str(row.get('host', '')) if pd.notna(row.get('host')) else ''
                uri = str(row.get('uri', '')) if pd.notna(row.get('uri')) else ''
                method = str(row.get('method', '')) if pd.notna(row.get('method')) else 'UNKNOWN'
                status_code = str(row.get('status_code', '')) if pd.notna(row.get('status_code')) else 'UNKNOWN'
                user_agent = str(row.get('user_agent', '')) if pd.notna(row.get('user_agent')) else ''
                
                # Update counters
                if client_ip:
                    self.client_request_count[client_ip] += 1
                if server_ip:
                    self.server_request_count[server_ip] += 1
                if host:
                    self.host_request_count[host] += 1
                if uri:
                    self.uri_request_count[uri] += 1
                
                self.method_count[method] += 1
                self.status_code_count[status_code] += 1
                
                if user_agent:
                    self.user_agent_count[user_agent] += 1
                
                # Detect suspicious patterns
                self._detect_suspicious_patterns(client_ip, user_agent, uri, method)
                
                # Classify IP addresses
                if client_ip and is_internal_ip(client_ip):
                    self.internal_ips.add(client_ip)
                elif client_ip:
                    self.external_ips.add(client_ip)
                
                # Store timestamp for temporal analysis
                if isinstance(row.name, pd.Timestamp):
                    if client_ip:
                        self.client_temporal_patterns[client_ip].append(row.name)
                elif 'ts' in row and pd.notna(row['ts']):
                    try:
                        timestamp = pd.to_datetime(row['ts'])
                        if client_ip:
                            self.client_temporal_patterns[client_ip].append(timestamp)
                    except (ValueError, TypeError):
                        pass
            
            # Calculate derived metrics
            total_clients = max(len(self.client_request_count), 1)
            self.metrics.avg_requests_per_client = safe_divide(
                sum(self.client_request_count.values()), total_clients
            )
            
            # Calculate request rate
            time_span = (datetime.now() - self.analysis_start).total_seconds() / 60
            self.metrics.request_rate_per_minute = safe_divide(
                self.metrics.total_requests, max(time_span, 1)
            )
            
            logger.info(f"Processed {self.metrics.total_requests} HTTP requests "
                       f"from {self.metrics.unique_clients} clients")
            
            return True
                       
        except Exception as e:
            logger.error(f"Error processing HTTP data: {e}")
            return False

    def _detect_suspicious_patterns(self, client_ip: str, user_agent: str, uri: str, method: str):
        """Detect suspicious patterns in HTTP requests"""
        # Check suspicious user agents
        if user_agent:
            ua_lower = user_agent.lower()
            for pattern in self.suspicious_ua_patterns:
                if re.search(pattern, ua_lower, re.IGNORECASE):
                    self.suspicious_user_agents[client_ip] += 1
                    break
        
        # Check suspicious URIs
        if uri:
            uri_lower = uri.lower()
            for pattern in self.suspicious_uri_patterns:
                if re.search(pattern, uri_lower, re.IGNORECASE):
                    self.suspicious_uris[client_ip] += 1
                    break
        
        # Check suspicious methods
        if method in ['PUT', 'DELETE', 'TRACE', 'CONNECT']:
            self.suspicious_uris[client_ip] += 1

    def _reset_metrics(self):
        """Reset all metrics and data structures"""
        self.client_request_count.clear()
        self.server_request_count.clear()
        self.host_request_count.clear()
        self.uri_request_count.clear()
        self.user_agent_count.clear()
        self.status_code_count.clear()
        self.method_count.clear()
        
        self.client_temporal_patterns.clear()
        self.suspicious_user_agents.clear()
        self.suspicious_uris.clear()
        
        self.internal_ips.clear()
        self.external_ips.clear()
        
        self.metrics = HTTPMetrics()
        self.analysis_start = datetime.now()

    def detect_anomalies(self) -> List[Dict]:
        """
        Comprehensive HTTP anomaly detection
        
        Returns:
            List of alert dictionaries
        """
        alerts = []
        
        if self.metrics.total_requests == 0:
            logger.warning("No HTTP data available for anomaly detection")
            return alerts
        
        # Run all detection methods
        alerts.extend(self._detect_volume_anomalies())
        alerts.extend(self._detect_suspicious_activity())
        alerts.extend(self._detect_error_patterns())
        alerts.extend(self._detect_temporal_anomalies())
        
        # Sort alerts by severity
        alerts.sort(key=lambda x: x.get('severity_score', 0), reverse=True)
        
        logger.info(f"Generated {len(alerts)} HTTP anomaly alerts")
        return alerts

    def _detect_volume_anomalies(self) -> List[Dict]:
        """Detect volume-based anomalies"""
        alerts = []
        if not self.client_request_count:
            return alerts
            
        threshold = self.thresholds.get('http_requests_per_minute', 200)
        avg_volume = self.metrics.avg_requests_per_client
        
        for client, count in self.client_request_count.items():
            # Absolute threshold
            if count > threshold:
                severity_score = min(100, (count / threshold) * 100)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'HIGH_HTTP_VOLUME',
                    'severity': 'HIGH',
                    'severity_score': severity_score,
                    'source_ip': client,
                    'request_count': count,
                    'threshold': threshold,
                    'description': f'Excessive HTTP requests: {count} requests (threshold: {threshold})'
                })
            
            # Relative threshold (3x average)
            elif count > avg_volume * 3 and avg_volume > 10:
                severity_score = min(90, (count / (avg_volume * 3)) * 100)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'ABNORMAL_REQUEST_VOLUME',
                    'severity': 'MEDIUM',
                    'severity_score': severity_score,
                    'source_ip': client,
                    'request_count': count,
                    'average_volume': avg_volume,
                    'description': f'Abnormal request volume: {count} requests (3x average: {avg_volume:.1f})'
                })
                
        return alerts

    def _detect_suspicious_activity(self) -> List[Dict]:
        """Detect suspicious HTTP activity"""
        alerts = []
        
        # Suspicious user agents
        ua_threshold = self.thresholds.get('suspicious_ua_count', 5)
        for client, count in self.suspicious_user_agents.items():
            if count > ua_threshold:
                severity_score = min(100, (count / ua_threshold) * 100)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'SUSPICIOUS_USER_AGENT',
                    'severity': 'HIGH',
                    'severity_score': severity_score,
                    'source_ip': client,
                    'suspicious_count': count,
                    'description': f'Suspicious user agent patterns detected: {count} requests'
                })
        
        # Suspicious URIs
        uri_threshold = self.thresholds.get('suspicious_uri_count', 10)
        for client, count in self.suspicious_uris.items():
            if count > uri_threshold:
                severity_score = min(100, (count / uri_threshold) * 100)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'SUSPICIOUS_URI',
                    'severity': 'HIGH',
                    'severity_score': severity_score,
                    'source_ip': client,
                    'suspicious_count': count,
                    'description': f'Suspicious URI patterns detected: {count} requests'
                })
                
        return alerts

    def _detect_error_patterns(self) -> List[Dict]:
        """Detect HTTP error patterns"""
        alerts = []
        
        # Client error patterns (4xx)
        client_errors = {code: count for code, count in self.status_code_count.items() 
                        if code.startswith('4')}
        error_threshold = self.thresholds.get('error_rate_threshold', 50)
        
        for client, count in self.client_request_count.items():
            error_count = sum(1 for ts in self.client_temporal_patterns.get(client, []) 
                            if self._is_error_status(ts))
            
            error_rate = safe_divide(error_count, count) * 100
            if error_rate > error_threshold and count > 10:
                severity_score = min(100, (error_rate / error_threshold) * 100)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'HIGH_ERROR_RATE',
                    'severity': 'MEDIUM',
                    'severity_score': severity_score,
                    'source_ip': client,
                    'error_rate': error_rate,
                    'request_count': count,
                    'description': f'High HTTP error rate: {error_rate:.1f}% (threshold: {error_threshold}%)'
                })
                
        return alerts

    def _is_error_status(self, status_code: str) -> bool:
        """Check if status code indicates an error"""
        return status_code.startswith('4') or status_code.startswith('5')

    def _detect_temporal_anomalies(self) -> List[Dict]:
        """Detect temporal patterns"""
        alerts = []
        std_threshold = self.thresholds.get('http_beacon_interval_std', 3.0)
        
        for client, timestamps in self.client_temporal_patterns.items():
            if len(timestamps) < 15:  # Minimum samples for HTTP analysis
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
                    'alert_type': 'HTTP_BEACONING',
                    'severity': 'HIGH',
                    'severity_score': severity,
                    'source_ip': client,
                    'interval_mean': stats['mean'],
                    'interval_stdev': stats['stdev'],
                    'request_count': len(timestamps),
                    'description': f'Regular HTTP beaconing detected ({stats["mean"]:.1f}s ± {stats["stdev"]:.1f}s)'
                })
                
        return alerts

    def generate_detailed_report(self) -> Dict:
        """
        Generate comprehensive HTTP analysis report
        
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
            'top_clients': dict(sorted(
                self.client_request_count.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]),
            'top_servers': dict(sorted(
                self.server_request_count.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]),
            'top_hosts': dict(sorted(
                self.host_request_count.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]),
            'http_methods': dict(self.method_count),
            'status_codes': dict(self.status_code_count),
            'suspicious_activity': {
                'suspicious_user_agents': dict(self.suspicious_user_agents),
                'suspicious_uris': dict(self.suspicious_uris)
            }
        }
        
        return report
