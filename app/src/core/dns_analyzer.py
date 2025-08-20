# src/core/dns_analyzer.py
import pandas as pd
from collections import defaultdict
from datetime import datetime
import logging
from typing import Dict, List, Tuple, Set
import math
import statistics
from dataclasses import dataclass
from enum import Enum

from ..utils.helpers import calculate_statistics, is_internal_ip, safe_divide

logger = logging.getLogger('DNSAnalyzer')

class AlertSeverity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

@dataclass
class DNSMetrics:
    """Data class for DNS analysis metrics"""
    total_queries: int = 0
    unique_hosts: int = 0
    unique_domains: int = 0
    avg_queries_per_host: float = 0.0
    query_rate_per_minute: float = 0.0

class DNSAnalyzer:
    """
    Professional DNS analysis engine for C2 beacon detection
    with enhanced algorithms and statistical analysis
    """
    
    def __init__(self, config: Dict):
        """
        Initialize DNS analyzer with configuration
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.thresholds = config.get('thresholds', {})
        
        # Initialize data structures
        self.host_query_count = defaultdict(int)
        self.host_unique_domains = defaultdict(set)
        self.domain_entropy = defaultdict(list)
        self.query_types_count = defaultdict(int)
        self.host_temporal_patterns = defaultdict(list)
        self.internal_ips = set()
        self.external_ips = set()
        
        # Statistics
        self.metrics = DNSMetrics()
        self.analysis_start = datetime.now()
        
        logger.info("DNS Analyzer initialized with professional detection algorithms")

    def calculate_entropy(self, domain: str) -> float:
        """
        Calculate Shannon entropy with enhanced domain processing
        
        Args:
            domain: Domain name to analyze
            
        Returns:
            Entropy value between 0 and 8
        """
        if not domain or len(domain.strip()) == 0:
            return 0.0
            
        try:
            # Extract subdomain part for analysis
            domain_part = domain.split('.')[0]
            if len(domain_part) < 3:  # Minimum length for meaningful entropy
                return 0.0
                
            # Normalize domain (lowercase, remove common patterns)
            domain_part = domain_part.lower()
            
            # Calculate character frequency
            freq_dict = {}
            total_chars = len(domain_part)
            
            for char in domain_part:
                freq_dict[char] = freq_dict.get(char, 0) + 1
                
            # Calculate Shannon entropy
            entropy = 0.0
            for count in freq_dict.values():
                probability = count / total_chars
                entropy -= probability * math.log2(probability)
                
            return entropy
            
        except Exception as e:
            logger.error(f"Error calculating entropy for domain '{domain}': {e}")
            return 0.0

    def process_dns_data(self, zeek_parser):
        """
        Process DNS data with enhanced validation and statistics
        
        Args:
            zeek_parser: ZeekLogParser instance with loaded data
        """
        if zeek_parser.df.empty:
            logger.warning("No DNS data to process")
            return
            
        df = zeek_parser.df
        
        try:
            # Basic metrics
            self.metrics.total_queries = len(df)
            self.metrics.unique_hosts = df['id.orig_h'].nunique()
            self.metrics.unique_domains = df['query'].nunique()
            
            # Process each record
            for _, row in df.iterrows():
                host = row['id.orig_h']
                query = str(row['query']) if pd.notna(row['query']) else ''
                qtype = row['qtype_name'] if 'qtype_name' in row and pd.notna(row['qtype_name']) else 'UNKNOWN'
                
                # Update counters
                self.host_query_count[host] += 1
                self.host_unique_domains[host].add(query)
                self.query_types_count[qtype] += 1
                
                # Calculate entropy for suspicious domains
                if len(query) > self.thresholds.get('unusual_domain_length', 50):
                    entropy = self.calculate_entropy(query)
                    self.domain_entropy[host].append(entropy)
                
                # Classify IP addresses
                if is_internal_ip(host):
                    self.internal_ips.add(host)
                else:
                    self.external_ips.add(host)
                
                # Store timestamp for temporal analysis
                if isinstance(row.name, pd.Timestamp):
                    self.host_temporal_patterns[host].append(row.name)
            
            # Calculate derived metrics
            total_hosts = max(len(self.host_query_count), 1)
            self.metrics.avg_queries_per_host = safe_divide(
                sum(self.host_query_count.values()), total_hosts
            )
            
            # Calculate query rate
            time_span = (datetime.now() - self.analysis_start).total_seconds() / 60
            self.metrics.query_rate_per_minute = safe_divide(
                self.metrics.total_queries, max(time_span, 1)
            )
            
            logger.info(f"Processed {self.metrics.total_queries} DNS queries "
                       f"from {self.metrics.unique_hosts} hosts")
                       
        except Exception as e:
            logger.error(f"Error processing DNS data: {e}")
            raise

    def detect_anomalies(self) -> List[Dict]:
        """
        Comprehensive anomaly detection with multiple techniques
        
        Returns:
            List of alert dictionaries
        """
        alerts = []
        
        # Run all detection methods
        alerts.extend(self._detect_volume_anomalies())
        alerts.extend(self._detect_domain_anomalies())
        alerts.extend(self._detect_temporal_anomalies())
        alerts.extend(self._detect_protocol_anomalies())
        
        # Sort alerts by severity
        alerts.sort(key=lambda x: x.get('severity_score', 0), reverse=True)
        
        logger.info(f"Generated {len(alerts)} anomaly alerts")
        return alerts

    def _detect_volume_anomalies(self) -> List[Dict]:
        """Detect volume-based anomalies"""
        alerts = []
        threshold = self.thresholds.get('dns_queries_per_minute', 100)
        avg_volume = self.metrics.avg_queries_per_host
        
        for host, count in self.host_query_count.items():
            # Absolute threshold
            if count > threshold:
                severity_score = min(100, (count / threshold) * 100)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'HIGH_DNS_VOLUME',
                    'severity': 'HIGH',
                    'severity_score': severity_score,
                    'source_ip': host,
                    'query_count': count,
                    'threshold': threshold,
                    'description': f'Excessive DNS queries: {count} queries (threshold: {threshold})'
                })
            
            # Relative threshold (3x average)
            elif count > avg_volume * 3 and avg_volume > 10:
                severity_score = min(90, (count / (avg_volume * 3)) * 100)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'ABNORMAL_QUERY_VOLUME',
                    'severity': 'MEDIUM',
                    'severity_score': severity_score,
                    'source_ip': host,
                    'query_count': count,
                    'average_volume': avg_volume,
                    'description': f'Abnormal query volume: {count} queries (3x average: {avg_volume:.1f})'
                })
                
        return alerts

    def _detect_domain_anomalies(self) -> List[Dict]:
        """Detect domain-based anomalies"""
        alerts = []
        length_threshold = self.thresholds.get('unusual_domain_length', 50)
        entropy_threshold = self.thresholds.get('entropy_threshold', 4.0)
        
        for host, domains in self.host_unique_domains.items():
            long_domains = []
            high_entropy_domains = []
            
            for domain in domains:
                # Check domain length
                if len(domain) > length_threshold:
                    long_domains.append(domain)
                
                # Check domain entropy
                entropy = self.calculate_entropy(domain)
                if entropy > entropy_threshold:
                    high_entropy_domains.append((domain, entropy))
            
            # Generate alerts
            if len(long_domains) > 5:
                severity = min(90, len(long_domains) * 10)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'LONG_DOMAINS',
                    'severity': 'HIGH',
                    'severity_score': severity,
                    'source_ip': host,
                    'domain_count': len(long_domains),
                    'sample_domains': long_domains[:3],
                    'description': f'Multiple long domain names: {len(long_domains)} domains > {length_threshold} chars'
                })
            
            if high_entropy_domains:
                max_entropy = max(entropy for _, entropy in high_entropy_domains)
                severity = min(100, (max_entropy / entropy_threshold) * 100)
                alerts.append({
                    'timestamp': datetime.now(),
                    'alert_type': 'HIGH_ENTROPY_DOMAINS',
                    'severity': 'HIGH',
                    'severity_score': severity,
                    'source_ip': host,
                    'domain_count': len(high_entropy_domains),
                    'max_entropy': max_entropy,
                    'sample_domains': [d[0] for d in high_entropy_domains[:3]],
                    'description': f'High entropy domains detected (max: {max_entropy:.2f})'
                })
                
        return alerts

    def _detect_temporal_anomalies(self) -> List[Dict]:
        """Detect temporal patterns indicating beaconing"""
        alerts = []
        std_threshold = self.thresholds.get('beacon_interval_std', 2.0)
        
        for host, timestamps in self.host_temporal_patterns.items():
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
                    'alert_type': 'DNS_BEACONING',
                    'severity': 'HIGH',
                    'severity_score': severity,
                    'source_ip': host,
                    'interval_mean': stats['mean'],
                    'interval_stdev': stats['stdev'],
                    'query_count': len(timestamps),
                    'description': f'Regular DNS beaconing detected ({stats["mean"]:.1f}s ± {stats["stdev"]:.1f}s)'
                })
                
        return alerts

    def _detect_protocol_anomalies(self) -> List[Dict]:
        """Detect protocol-level anomalies"""
        alerts = []
        unusual_types = ['TXT', 'NULL', 'ANY', 'AXFR', 'IXFR']
        threshold = self.thresholds.get('unusual_type_count', 10)
        
        unusual_activity = []
        for qtype in unusual_types:
            count = self.query_types_count.get(qtype, 0)
            if count > threshold:
                unusual_activity.append((qtype, count))
        
        if unusual_activity:
            total_unusual = sum(count for _, count in unusual_activity)
            severity = min(100, (total_unusual / threshold) * 20)
            alerts.append({
                'timestamp': datetime.now(),
                'alert_type': 'UNUSUAL_DNS_TYPES',
                'severity': 'MEDIUM',
                'severity_score': severity,
                'unusual_types': unusual_activity,
                'total_count': total_unusual,
                'description': f'Unusual DNS record types detected: {total_unusual} queries'
            })
            
        return alerts

    def generate_detailed_report(self) -> Dict:
        """
        Generate comprehensive analysis report
        
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
            'top_querying_hosts': dict(sorted(
                self.host_query_count.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]),
            'most_common_query_types': dict(sorted(
                self.query_types_count.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]),
            'network_analysis': {
                'internal_ips_count': len(self.internal_ips),
                'external_ips_count': len(self.external_ips),
                'total_unique_ips': len(self.internal_ips) + len(self.external_ips)
            }
        }
        
        return report

# Main function remains similar but enhanced
def main():
    """Enhanced main function with better error handling"""
    try:
        from ..utils.logger import setup_logging
        from ..utils.helpers import load_config
        
        # Setup logging
        config = load_config("config.json")
        logger = setup_logging(config)
        
        # Initialize and run analysis
        from .log_parser import ZeekLogParser
        
        zeek_parser = ZeekLogParser("config.json")
        dns_analyzer = DNSAnalyzer(config)
        
        print("Reading DNS logs...")
        if zeek_parser.read_historical(days=1):  # Analyze last 24 hours
            print("Analyzing DNS traffic...")
            dns_analyzer.process_dns_data(zeek_parser)
            
            print("Running detection rules...")
            alerts = dns_analyzer.detect_anomalies()
            
            print(f"\n=== DNS ANALYSIS RESULTS ===")
            print(f"Generated {len(alerts)} alerts")
            
            # Print summary
            for alert in alerts[:5]:  # Show top 5 alerts
                print(f"\n[{alert['severity']}] {alert['alert_type']}")
                print(f"Source: {alert['source_ip']}")
                print(f"Score: {alert['severity_score']:.1f}")
                print(f"Description: {alert['description']}")
            
            # Generate detailed report
            report = dns_analyzer.generate_detailed_report()
            print(f"\n=== STATISTICAL REPORT ===")
            print(f"Total queries: {report['metrics']['total_queries']}")
            print(f"Unique hosts: {report['metrics']['unique_hosts']}")
            print(f"Query rate: {report['metrics']['query_rate_per_minute']:.1f}/min")
            
        else:
            print("Failed to read DNS logs. Please check configuration.")
            
    except Exception as e:
        print(f"Error in DNS analysis: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
