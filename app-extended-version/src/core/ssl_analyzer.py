# src/core/ssl_analyzer.py
import pandas as pd
from collections import defaultdict
from datetime import datetime
import logging
from typing import Dict, List, Tuple, Set, Any, Optional
import re
import ssl
from dataclasses import dataclass
from enum import Enum

from ..utils.helpers import calculate_statistics, is_internal_ip, safe_divide

logger = logging.getLogger('SSLAnalyzer')

class AlertSeverity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

@dataclass
class SSLMetrics:
    """Data class for SSL analysis metrics"""
    total_connections: int = 0
    unique_clients: int = 0
    unique_servers: int = 0
    unique_servers_names: int = 0
    ssl_versions: Dict[str, int] = None
    cipher_suites: Dict[str, int] = None
    validation_status_count: Dict[str, int] = None

class SSLAnalyzer:
    """
    Professional SSL/TLS analysis engine for encrypted traffic monitoring
    and anomaly detection
    """
    
    def __init__(self, config: Dict):
        """
        Initialize SSL analyzer with configuration
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.thresholds = config.get('thresholds', {})
        
        # Initialize data structures
        self.client_ssl_count = defaultdict(int)
        self.server_ssl_count = defaultdict(int)
        self.server_name_count = defaultdict(int)
        self.ssl_version_count = defaultdict(int)
        self.cipher_suite_count = defaultdict(int)
        self.validation_status_count = defaultdict(int)
        self.curve_count = defaultdict(int)
        
        self.client_temporal_patterns = defaultdict(list)
        self.weak_ciphers_detected = defaultdict(int)
        self.self_signed_certs = defaultdict(int)
        self.suspicious_server_names = defaultdict(int)
        
        self.internal_ips = set()
        self.external_ips = set()
        
        # Statistics
        self.metrics = SSLMetrics()
        self.analysis_start = datetime.now()
        
        # Predefined patterns for detection
        self.weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'ANON', 'ADH',
            'CBC', 'TLS_RSA_', 'SSL_RSA_', '_CHACHA20_', '_GCM_'
        ]
        
        self.weak_ssl_versions = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
        
        self.suspicious_server_patterns = [
            r'([0-9]{1,3}\.){3}[0-9]{1,3}',  # IP addresses as SNI
            r'localhost', r'local', r'test', r'example',
            r'vpn', r'proxy', r'tor', r'anonymous',
            r'free', r'hidden', r'secret', r'private'
        ]
        
        logger.info("SSL Analyzer initialized with professional detection algorithms")

    def process_ssl_data(self, zeek_parser, log_type: str = "ssl") -> bool:
        """
        Process SSL data with enhanced validation and statistics
        
        Args:
            zeek_parser: ZeekLogParser instance with loaded data
            log_type: Type of log to process (default: "ssl")
            
        Returns:
            True if successful, False otherwise
        """
        if log_type not in zeek_parser.log_dataframes:
            logger.error(f"Log type '{log_type}' not found in parser data")
            return False
            
        df = zeek_parser.log_dataframes[log_type]
        
        if df.empty:
            logger.warning(f"No SSL data to process for log type '{log_type}'")
            return False
            
        try:
            # Reset metrics for new processing
            self._reset_metrics()
            
            # Basic metrics
            self.metrics.total_connections = len(df)
            
            # Check for required columns
            required_columns = ['id.orig_h', 'id.resp_h', 'server_name', 'version', 'cipher']
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                logger.warning(f"Missing some columns in SSL data: {missing_columns}")
            
            if 'id.orig_h' in df.columns:
                self.metrics.unique_clients = df['id.orig_h'].nunique()
            if 'id.resp_h' in df.columns:
                self.metrics.unique_servers = df['id.resp_h'].nunique()
            if 'server_name' in df.columns:
                self.metrics.unique_servers_names = df['server_name'].nunique()
            
            # Process each record
            for _, row in df.iterrows():
                client_ip = row.get('id.orig_h', '')
                server_ip = row.get('id.resp_h', '')
                server_name = str(row.get('server_name', '')) if pd.notna(row.get('server_name')) else ''
                ssl_version = str(row.get('version', '')) if pd.notna(row.get('version')) else 'UNKNOWN'
                cipher = str(row.get('cipher', '')) if pd.notna(row.get('cipher')) else 'UNKNOWN'
                curve = str(row.get('curve', '')) if pd.notna(row.get('curve')) else ''
                validation_status = str(row.get('validation_status', '')) if pd.notna(row.get('validation_status')) else 'UNKNOWN'
                resumed = row.get('resumed', False)
                established = row.get('established', False)
                
                # Update counters
                if client_ip:
                    self.client_ssl_count[client_ip] += 1
                if server_ip:
                    self.server_ssl_count[server_ip] += 1
                if server_name:
                    self.server_name_count[server_name] += 1
                
                self.ssl_version_count[ssl_version] += 1
                self.cipher_suite_count[cipher] += 1
                self.validation_status_count[validation_status] += 1
                
                if curve:
                    self.curve_count[curve] += 1
                
                # Detect suspicious patterns
                self._detect_suspicious_patterns(client_ip, server_name, ssl_version, 
                                               cipher, validation_status, curve)
                
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
            
            # Update metrics
            self.metrics.ssl_versions = dict(self.ssl_version_count)
            self.metrics.cipher_suites = dict(self.cipher_suite_count)
            self.metrics.validation_status_count = dict(self.validation_status_count)
            
            logger.info(f"Processed {self.metrics.total_connections} SSL connections "
                       f"from {self.metrics.unique_clients} clients")
            
            return True
                       
        except Exception as e:
            logger.error(f"Error processing SSL data: {e}")
            return False

    def _detect_suspicious_patterns(self, client_ip: str, server_name: str, ssl_version: str, 
                                  cipher: str, validation_status: str, curve: str):
        """Detect suspicious patterns in SSL connections"""
        
        # Check weak SSL/TLS versions
        if ssl_version in self.weak_ssl_versions:
            self.weak_ciphers_detected[client_ip] += 1
        
        # Check weak ciphers
        cipher_upper = cipher.upper()
        for weak_cipher in self.weak_ciphers:
            if weak_cipher in cipher_upper:
                self.weak_ciphers_detected[client_ip] += 1
                break
        
        # Check self-signed certificates
        if 'self signed' in validation_status.lower() or 'unable to get local' in validation_status.lower():
            self.self_signed_certs[client_ip] += 1
        
        # Check suspicious server names
        if server_name:
            server_lower = server_name.lower()
            for pattern in self.suspicious_server_patterns:
                if re.search(pattern, server_lower, re.IGNORECASE):
                    self.suspicious_server_names[client_ip] += 1
                    break

    def _reset_metrics(self):
        """Reset all metrics and data structures"""
        self.client_ssl_count.clear()
        self.server_ssl_count.clear()
        self.server_name_count.clear()
        self.ssl_version_count.clear()
        self.cipher_suite_count.clear()
        self.validation_status_count.clear()
        self.curve_count.clear()
        
        self.client_temporal_patterns.clear()
        self.weak_ciphers_detected.clear()
        self.self_signed_certs.clear()
        self.suspicious_server_names.clear()
        
        self.internal_ips.clear()
        self.external_ips.clear()
        
        self.metrics = SSLMetrics()
        self.analysis_start = datetime.now()

    def detect_anomalies(self) -> List[Dict]:
        """
        Comprehensive SSL anomaly detection
        
        Returns:
            List of alert dictionaries
        """
        alerts = []
        
        if self.metrics.total_connections == 0:
            logger.warning("No SSL data available for anomaly detection")
            return alerts
        
        # Run all detection methods
        alerts.extend(self._detect_weak_ssl())
        alerts.extend(self._detect_certificate_issues())
        alerts.extend(self._detect_suspicious_servers())
        alerts.extend(self._detect_temporal_anomalies())
        alerts.extend(self._detect_volume_anomalies())
        
        # Sort alerts by severity
        alerts.sort(key=lambda x: x.get('severity_score', 0), reverse=True)
        
        logger.info(f"Generated {len(alerts)} SSL anomaly alerts")
        return alerts

    def _detect_weak_ssl(self) -> List[Dict]:
        """Detect weak SSL/TLS configurations"""
        alerts = []
        
        # Weak SSL versions
        weak_version_threshold = self.thresholds.get('weak_ssl_count', 3)
        for client, count in self.weak_ciphers_detected.items():
            if count >= weak_version_threshold:
                severity_score = min(100, (count / weak_version_threshold) * 100)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'WEAK_SSL_CONFIG',
                    'severity': 'HIGH',
                    'severity_score': severity_score,
                    'source_ip': client,
                    'weak_connection_count': count,
                    'threshold': weak_version_threshold,
                    'description': f'Weak SSL/TLS configurations detected: {count} connections'
                })
        
        # Specific weak version alerts
        for version, count in self.ssl_version_count.items():
            if version in self.weak_ssl_versions and count > 0:
                severity_score = 90 if version in ['SSLv2', 'SSLv3'] else 70
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'DEPRECATED_SSL_VERSION',
                    'severity': 'HIGH' if version in ['SSLv2', 'SSLv3'] else 'MEDIUM',
                    'severity_score': severity_score,
                    'ssl_version': version,
                    'connection_count': count,
                    'description': f'Deprecated SSL version detected: {version} ({count} connections)'
                })
                
        return alerts

    def _detect_certificate_issues(self) -> List[Dict]:
        """Detect certificate validation issues"""
        alerts = []
        
        # Self-signed certificates
        self_signed_threshold = self.thresholds.get('self_signed_cert_count', 2)
        for client, count in self.self_signed_certs.items():
            if count >= self_signed_threshold:
                severity_score = min(100, (count / self_signed_threshold) * 100)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'SELF_SIGNED_CERTIFICATES',
                    'severity': 'MEDIUM',
                    'severity_score': severity_score,
                    'source_ip': client,
                    'self_signed_count': count,
                    'threshold': self_signed_threshold,
                    'description': f'Self-signed certificates detected: {count} connections'
                })
        
        # Certificate validation failures
        validation_issues = {k: v for k, v in self.validation_status_count.items() 
                           if 'fail' in k.lower() or 'error' in k.lower() or 'invalid' in k.lower()}
        
        for status, count in validation_issues.items():
            if count > 0:
                severity_score = 80
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'CERTIFICATE_VALIDATION_FAILURE',
                    'severity': 'MEDIUM',
                    'severity_score': severity_score,
                    'validation_status': status,
                    'failure_count': count,
                    'description': f'Certificate validation failures: {status} ({count} connections)'
                })
                
        return alerts

    def _detect_suspicious_servers(self) -> List[Dict]:
        """Detect suspicious server names"""
        alerts = []
        
        suspicious_threshold = self.thresholds.get('suspicious_server_count', 3)
        for client, count in self.suspicious_server_names.items():
            if count >= suspicious_threshold:
                severity_score = min(100, (count / suspicious_threshold) * 100)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'SUSPICIOUS_SSL_SERVERS',
                    'severity': 'MEDIUM',
                    'severity_score': severity_score,
                    'source_ip': client,
                    'suspicious_server_count': count,
                    'threshold': suspicious_threshold,
                    'description': f'Suspicious SSL server names detected: {count} connections'
                })
        
        # Detect IP addresses used as server names
        ip_as_sni_count = 0
        for server_name in self.server_name_count.keys():
            if re.match(r'^([0-9]{1,3}\.){3}[0-9]{1,3}$', server_name):
                ip_as_sni_count += self.server_name_count[server_name]
        
        if ip_as_sni_count > 10:
            severity_score = min(100, (ip_as_sni_count / 50) * 100)
            alerts.append({
                'timestamp': datetime.now(),
                'alert_type': 'IP_AS_SERVER_NAME',
                'severity': 'LOW',
                'severity_score': severity_score,
                'ip_sni_count': ip_as_sni_count,
                'description': f'IP addresses used as server names: {ip_as_sni_count} connections'
            })
                
        return alerts

    def _detect_temporal_anomalies(self) -> List[Dict]:
        """Detect temporal patterns in SSL connections"""
        alerts = []
        std_threshold = self.thresholds.get('ssl_beacon_interval_std', 4.0)
        
        for client, timestamps in self.client_temporal_patterns.items():
            if len(timestamps) < 15:  # Minimum samples for SSL analysis
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
                    'alert_type': 'SSL_BEACONING',
                    'severity': 'HIGH',
                    'severity_score': severity,
                    'source_ip': client,
                    'interval_mean': stats['mean'],
                    'interval_stdev': stats['stdev'],
                    'connection_count': len(timestamps),
                    'description': f'Regular SSL beaconing detected ({stats["mean"]:.1f}s ± {stats["stdev"]:.1f}s)'
                })
                
        return alerts

    def _detect_volume_anomalies(self) -> List[Dict]:
        """Detect volume-based anomalies in SSL connections"""
        alerts = []
        if not self.client_ssl_count:
            return alerts
            
        threshold = self.thresholds.get('ssl_connections_per_minute', 100)
        avg_volume = safe_divide(sum(self.client_ssl_count.values()), 
                               max(len(self.client_ssl_count), 1))
        
        for client, count in self.client_ssl_count.items():
            # Absolute threshold
            if count > threshold:
                severity_score = min(100, (count / threshold) * 100)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'HIGH_SSL_VOLUME',
                    'severity': 'MEDIUM',
                    'severity_score': severity_score,
                    'source_ip': client,
                    'ssl_connection_count': count,
                    'threshold': threshold,
                    'description': f'Excessive SSL connections: {count} connections (threshold: {threshold})'
                })
            
            # Relative threshold (4x average)
            elif count > avg_volume * 4 and avg_volume > 5:
                severity_score = min(80, (count / (avg_volume * 4)) * 100)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'ABNORMAL_SSL_VOLUME',
                    'severity': 'MEDIUM',
                    'severity_score': severity_score,
                    'source_ip': client,
                    'ssl_connection_count': count,
                    'average_volume': avg_volume,
                    'description': f'Abnormal SSL connection volume: {count} connections (4x average: {avg_volume:.1f})'
                })
                
        return alerts

    def generate_detailed_report(self) -> Dict:
        """
        Generate comprehensive SSL analysis report
        
        Returns:
            Detailed report dictionary
        """
        # Top servers by SSL connections
        top_servers = dict(sorted(self.server_ssl_count.items(), 
                                key=lambda x: x[1], reverse=True)[:10])
        
        # Top server names
        top_server_names = dict(sorted(self.server_name_count.items(),
                                     key=lambda x: x[1], reverse=True)[:10])
        
        # Most common SSL versions
        ssl_versions = dict(sorted(self.ssl_version_count.items(),
                                 key=lambda x: x[1], reverse=True))
        
        # Most common ciphers
        top_ciphers = dict(sorted(self.cipher_suite_count.items(),
                                key=lambda x: x[1], reverse=True)[:10])
        
        report = {
            'analysis_period': {
                'start_time': self.analysis_start,
                'end_time': datetime.now(),
                'duration_minutes': (datetime.now() - self.analysis_start).total_seconds() / 60
            },
            'metrics': {
                'total_connections': self.metrics.total_connections,
                'unique_clients': self.metrics.unique_clients,
                'unique_servers': self.metrics.unique_servers,
                'unique_server_names': self.metrics.unique_servers_names
            },
            'top_clients': dict(sorted(self.client_ssl_count.items(), 
                                     key=lambda x: x[1], reverse=True)[:10]),
            'top_servers': top_servers,
            'top_server_names': top_server_names,
            'ssl_versions': ssl_versions,
            'top_ciphers': top_ciphers,
            'validation_status': dict(self.validation_status_count),
            'elliptic_curves': dict(self.curve_count),
            'security_issues': {
                'weak_ssl_detected': sum(self.weak_ciphers_detected.values()),
                'self_signed_certs': sum(self.self_signed_certs.values()),
                'suspicious_servers': sum(self.suspicious_server_names.values())
            }
        }
        
        return report
