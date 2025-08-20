# src/core/ssh_analyzer.py
import pandas as pd
from collections import defaultdict
from datetime import datetime
import logging
from typing import Dict, List, Tuple, Set, Any, Optional
import re
from dataclasses import dataclass
from enum import Enum

from ..utils.helpers import calculate_statistics, is_internal_ip, safe_divide

logger = logging.getLogger('SSHAnalyzer')

class AlertSeverity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

@dataclass
class SSHMetrics:
    """Data class for SSH analysis metrics"""
    total_connections: int = 0
    unique_clients: int = 0
    unique_servers: int = 0
    successful_logins: int = 0
    failed_logins: int = 0
    login_success_rate: float = 0.0
    connection_rate_per_minute: float = 0.0

class SSHAnalyzer:
    """
    Professional SSH analysis engine for SSH traffic monitoring
    and brute-force/unauthorized access detection
    """
    
    def __init__(self, config: Dict):
        """
        Initialize SSH analyzer with configuration
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.thresholds = config.get('thresholds', {})
        
        # Initialize data structures
        self.client_connection_count = defaultdict(int)
        self.server_connection_count = defaultdict(int)
        self.client_auth_attempts = defaultdict(int)
        self.client_failed_attempts = defaultdict(int)
        self.client_successful_logins = defaultdict(int)
        self.server_auth_attempts = defaultdict(int)
        
        self.auth_method_count = defaultdict(int)
        self.client_version_count = defaultdict(int)
        self.server_version_count = defaultdict(int)
        
        self.client_temporal_patterns = defaultdict(list)
        self.failed_login_patterns = defaultdict(list)
        self.successful_login_patterns = defaultdict(list)
        
        self.internal_ips = set()
        self.external_ips = set()
        
        # Known suspicious patterns
        self.suspicious_clients = [
            'libssh', 'paramiko', 'jsch', 'ssh2', 'sshj',
            'brute', 'scan', 'hydra', 'medusa', 'ncrack'
        ]
        
        self.weak_auth_methods = ['password', 'keyboard-interactive']
        
        # Statistics
        self.metrics = SSHMetrics()
        self.analysis_start = datetime.now()
        
        logger.info("SSH Analyzer initialized with professional detection algorithms")

    def process_ssh_data(self, zeek_parser, log_type: str = "ssh") -> bool:
        """
        Process SSH data with enhanced validation and statistics
        
        Args:
            zeek_parser: ZeekLogParser instance with loaded data
            log_type: Type of log to process (default: "ssh")
            
        Returns:
            True if successful, False otherwise
        """
        if log_type not in zeek_parser.log_dataframes:
            logger.error(f"Log type '{log_type}' not found in parser data")
            return False
            
        df = zeek_parser.log_dataframes[log_type]
        
        if df.empty:
            logger.warning(f"No SSH data to process for log type '{log_type}'")
            return False
            
        try:
            # Reset metrics for new processing
            self._reset_metrics()
            
            # Basic metrics
            self.metrics.total_connections = len(df)
            
            # Check for required columns
            required_columns = ['id.orig_h', 'id.resp_h', 'auth_success', 'client']
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                logger.warning(f"Missing some columns in SSH data: {missing_columns}")
            
            if 'id.orig_h' in df.columns:
                self.metrics.unique_clients = df['id.orig_h'].nunique()
            if 'id.resp_h' in df.columns:
                self.metrics.unique_servers = df['id.resp_h'].nunique()
            
            # Process each record
            for _, row in df.iterrows():
                client_ip = row.get('id.orig_h', '')
                server_ip = row.get('id.resp_h', '')
                auth_success = row.get('auth_success', False)
                client = str(row.get('client', '')) if pd.notna(row.get('client')) else ''
                server = str(row.get('server', '')) if pd.notna(row.get('server')) else ''
                auth_method = str(row.get('auth_method', '')) if pd.notna(row.get('auth_method')) else 'unknown'
                direction = row.get('direction', '')
                
                # Update counters
                if client_ip:
                    self.client_connection_count[client_ip] += 1
                    if auth_success:
                        self.client_successful_logins[client_ip] += 1
                        self.metrics.successful_logins += 1
                    else:
                        self.client_failed_attempts[client_ip] += 1
                        self.metrics.failed_logins += 1
                
                if server_ip:
                    self.server_connection_count[server_ip] += 1
                
                # Update authentication methods
                self.auth_method_count[auth_method] += 1
                
                # Update client/server versions
                if client:
                    self.client_version_count[client] += 1
                if server:
                    self.server_version_count[server] += 1
                
                # Detect suspicious patterns
                self._detect_suspicious_patterns(client_ip, client, auth_success, auth_method, direction)
                
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
            total_clients = max(len(self.client_connection_count), 1)
            self.metrics.login_success_rate = safe_divide(
                self.metrics.successful_logins, 
                self.metrics.successful_logins + self.metrics.failed_logins
            ) * 100
            
            # Calculate connection rate
            time_span = (datetime.now() - self.analysis_start).total_seconds() / 60
            self.metrics.connection_rate_per_minute = safe_divide(
                self.metrics.total_connections, max(time_span, 1)
            )
            
            logger.info(f"Processed {self.metrics.total_connections} SSH connections "
                       f"from {self.metrics.unique_clients} clients")
            
            return True
                       
        except Exception as e:
            logger.error(f"Error processing SSH data: {e}")
            return False

    def _detect_suspicious_patterns(self, client_ip: str, client: str, 
                                  auth_success: bool, auth_method: str, direction: str):
        """Detect suspicious patterns in SSH connections"""
        
        # Check suspicious clients
        if client:
            client_lower = client.lower()
            for pattern in self.suspicious_clients:
                if pattern.lower() in client_lower:
                    self.failed_login_patterns[client_ip].append({
                        'client': client,
                        'auth_method': auth_method,
                        'success': auth_success
                    })
                    break
        
        # Check weak authentication methods
        if auth_method in self.weak_auth_methods:
            self.failed_login_patterns[client_ip].append({
                'auth_method': auth_method,
                'success': auth_success
            })
        
        # Check inbound connections from external IPs
        if direction == 'INBOUND' and client_ip and not is_internal_ip(client_ip):
            self.failed_login_patterns[client_ip].append({
                'direction': direction,
                'success': auth_success
            })

    def _reset_metrics(self):
        """Reset all metrics and data structures"""
        self.client_connection_count.clear()
        self.server_connection_count.clear()
        self.client_auth_attempts.clear()
        self.client_failed_attempts.clear()
        self.client_successful_logins.clear()
        self.server_auth_attempts.clear()
        
        self.auth_method_count.clear()
        self.client_version_count.clear()
        self.server_version_count.clear()
        
        self.client_temporal_patterns.clear()
        self.failed_login_patterns.clear()
        self.successful_login_patterns.clear()
        
        self.internal_ips.clear()
        self.external_ips.clear()
        
        self.metrics = SSHMetrics()
        self.analysis_start = datetime.now()

    def detect_anomalies(self) -> List[Dict]:
        """
        Comprehensive SSH anomaly detection
        
        Returns:
            List of alert dictionaries
        """
        alerts = []
        
        if self.metrics.total_connections == 0:
            logger.warning("No SSH data available for anomaly detection")
            return alerts
        
        # Run all detection methods
        alerts.extend(self._detect_brute_force_attempts())
        alerts.extend(self._detect_suspicious_clients())
        alerts.extend(self._detect_weak_auth_methods())
        alerts.extend(self._detect_external_access())
        alerts.extend(self._detect_temporal_anomalies())
        
        # Sort alerts by severity
        alerts.sort(key=lambda x: x.get('severity_score', 0), reverse=True)
        
        logger.info(f"Generated {len(alerts)} SSH anomaly alerts")
        return alerts

    def _detect_brute_force_attempts(self) -> List[Dict]:
        """Detect brute force attack patterns"""
        alerts = []
        
        threshold = self.thresholds.get('ssh_failed_attempts', 10)
        time_window = self.thresholds.get('ssh_brute_force_window', 300)  # 5 minutes
        
        for client, attempts in self.client_failed_attempts.items():
            if attempts >= threshold:
                severity_score = min(100, (attempts / threshold) * 100)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'SSH_BRUTE_FORCE',
                    'severity': 'HIGH',
                    'severity_score': severity_score,
                    'source_ip': client,
                    'failed_attempts': attempts,
                    'threshold': threshold,
                    'description': f'SSH brute force detected: {attempts} failed attempts'
                })
                
        return alerts

    def _detect_suspicious_clients(self) -> List[Dict]:
        """Detect suspicious SSH clients"""
        alerts = []
        
        for client, patterns in self.failed_login_patterns.items():
            suspicious_count = len(patterns)
            if suspicious_count > 5:
                severity_score = min(100, (suspicious_count / 5) * 100)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'SUSPICIOUS_SSH_CLIENT',
                    'severity': 'MEDIUM',
                    'severity_score': severity_score,
                    'source_ip': client,
                    'suspicious_events': suspicious_count,
                    'description': f'Suspicious SSH client activity detected: {suspicious_count} events'
                })
                
        return alerts

    def _detect_weak_auth_methods(self) -> List[Dict]:
        """Detect weak authentication methods"""
        alerts = []
        
        password_count = self.auth_method_count.get('password', 0)
        total_auths = sum(self.auth_method_count.values())
        
        if total_auths > 0:
            password_ratio = (password_count / total_auths) * 100
            if password_ratio > 80:  # 80% threshold for password usage
                severity_score = min(100, (password_ratio / 80) * 100)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'WEAK_SSH_AUTH',
                    'severity': 'MEDIUM',
                    'severity_score': severity_score,
                    'password_ratio': password_ratio,
                    'total_auths': total_auths,
                    'description': f'Weak SSH authentication methods detected: {password_ratio:.1f}% password usage'
                })
                
        return alerts

    def _detect_external_access(self) -> List[Dict]:
        """Detect external SSH access attempts"""
        alerts = []
        
        external_attempts = 0
        for client in self.client_connection_count:
            if not is_internal_ip(client):
                external_attempts += self.client_connection_count[client]
        
        if external_attempts > 20:
            severity_score = min(100, (external_attempts / 20) * 100)
            alerts.append({
                'timestamp': datetime.now(),
                'alert_type': 'EXTERNAL_SSH_ACCESS',
                'severity': 'LOW',
                'severity_score': severity_score,
                'external_attempts': external_attempts,
                'description': f'External SSH access attempts: {external_attempts} connections'
            })
                
        return alerts

    def _detect_temporal_anomalies(self) -> List[Dict]:
        """Detect temporal patterns in SSH connections"""
        alerts = []
        std_threshold = self.thresholds.get('ssh_beacon_interval_std', 3.0)
        
        for client, timestamps in self.client_temporal_patterns.items():
            if len(timestamps) < 10:  # Minimum samples for analysis
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
                    'alert_type': 'SSH_BEACONING',
                    'severity': 'HIGH',
                    'severity_score': severity,
                    'source_ip': client,
                    'interval_mean': stats['mean'],
                    'interval_stdev': stats['stdev'],
                    'connection_count': len(timestamps),
                    'description': f'Regular SSH beaconing detected ({stats["mean"]:.1f}s ± {stats["stdev"]:.1f}s)'
                })
                
        return alerts

    def generate_detailed_report(self) -> Dict:
        """
        Generate comprehensive SSH analysis report
        
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
                self.client_connection_count.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]),
            'top_servers': dict(sorted(
                self.server_connection_count.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]),
            'auth_methods': dict(self.auth_method_count),
            'client_versions': dict(sorted(
                self.client_version_count.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]),
            'security_analysis': {
                'failed_attempts': sum(self.client_failed_attempts.values()),
                'successful_logins': sum(self.client_successful_logins.values()),
                'login_success_rate': self.metrics.login_success_rate,
                'internal_ips_count': len(self.internal_ips),
                'external_ips_count': len(self.external_ips)
            }
        }
        
        return report

    def process_real_time_entry(self, entry: Dict) -> Optional[Dict]:
        """
        Process a single real-time SSH entry for immediate analysis
        
        Args:
            entry: Real-time SSH log entry
            
        Returns:
            Alert dictionary if anomaly detected, None otherwise
        """
        try:
            if entry.get('log_type') != 'ssh':
                return None
                
            client_ip = entry.get('id.orig_h', '')
            auth_success = entry.get('auth_success', False)
            client = entry.get('client', '')
            
            if not client_ip:
                return None
            
            # Update counters
            self.client_connection_count[client_ip] += 1
            if auth_success:
                self.client_successful_logins[client_ip] += 1
                self.metrics.successful_logins += 1
            else:
                self.client_failed_attempts[client_ip] += 1
                self.metrics.failed_logins += 1
            
            # Update metrics
            self.metrics.total_connections += 1
            
            # Check for immediate brute force
            threshold = self.thresholds.get('ssh_failed_attempts', 10)
            if self.client_failed_attempts[client_ip] >= threshold:
                return {
                    'timestamp': datetime.now(),
                    'alert_type': 'SSH_BRUTE_FORCE_REALTIME',
                    'severity': 'HIGH',
                    'severity_score': min(100, (self.client_failed_attempts[client_ip] / threshold) * 100),
                    'source_ip': client_ip,
                    'failed_attempts': self.client_failed_attempts[client_ip],
                    'description': f'Real-time: SSH brute force detected'
                }
            
            # Check suspicious client
            if client:
                client_lower = client.lower()
                for pattern in self.suspicious_clients:
                    if pattern.lower() in client_lower:
                        return {
                            'timestamp': datetime.now(),
                            'alert_type': 'SUSPICIOUS_SSH_CLIENT_REALTIME',
                            'severity': 'MEDIUM',
                            'severity_score': 75,
                            'source_ip': client_ip,
                            'client': client,
                            'description': f'Real-time: Suspicious SSH client detected'
                        }
            
            return None
            
        except Exception as e:
            logger.error(f"Error processing real-time SSH entry: {e}")
            return None
