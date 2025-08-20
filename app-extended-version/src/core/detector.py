# src/core/detector.py
#!/usr/bin/env python3
"""
Professional C2 Beacon Detection System
Enhanced with multi-protocol analysis and optimized performance
"""

import json
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import argparse
import signal
import sys
from pathlib import Path
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from .log_parser import ZeekLogParser
from .dns_analyzer import DNSAnalyzer
from .http_analyzer import HTTPAnalyzer
from .conn_analyzer import ConnAnalyzer
from .ssl_analyzer import SSLAnalyzer
from ..utils.logger import setup_logging
from ..utils.helpers import load_config

logger = logging.getLogger('C2Detector')

class C2Detector:
    """
    Professional C2 detection system with multi-protocol analysis
    """
    
    def __init__(self, config_path: str = "config.json"):
        """
        Initialize professional C2 detector with multi-protocol support
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        self.config = load_config(config_path)
        self.alerts: List[Dict] = []
        self.alert_count = 0
        self.start_time = datetime.now()
        self.running = True
        self.last_analysis_time = datetime.now()
        
        # Alert deduplication
        self.alert_signatures: Set[str] = set()
        self.alert_cooldown: Dict[str, datetime] = {}
        
        # Setup signal handling for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Initialize components
        self.zeek_parser = ZeekLogParser(config_path)
        self.analyzers = {
            'dns': DNSAnalyzer(self.config),
            'http': HTTPAnalyzer(self.config),
            'conn': ConnAnalyzer(self.config),
            'ssl': SSLAnalyzer(self.config)
        }
        
        # Thread pool for parallel processing
        self.thread_pool = ThreadPoolExecutor(
            max_workers=self.config.get('system', {}).get('thread_pool_size', 4)
        )
        
        logger.info("Professional C2 Detector initialized with multi-protocol support")

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
        self.thread_pool.shutdown(wait=False)
        self.generate_final_report()
        sys.exit(0)

    def setup_environment(self) -> bool:
        """Setup monitoring environment with validation for all log types"""
        logger.info("Setting up multi-protocol monitoring environment...")
        
        try:
            analysis_config = self.config.get('analysis', {})
            historical_days = analysis_config.get('historical_days', 1)
            
            # Yalnız aktiv olan log tiplərini yüklə
            enabled_logs = self._get_enabled_log_types()
            logger.info(f"Enabled log types: {enabled_logs}")
            
            if not enabled_logs:
                logger.error("No log types enabled in configuration")
                return False
            
            # Load historical data only for enabled log types
            load_results = {}
            for log_type in enabled_logs:
                success = self.zeek_parser.load_log_type(log_type, days=historical_days)
                load_results[log_type] = success
                if success:
                    logger.info(f"Successfully loaded {log_type} logs")
                else:
                    logger.warning(f"Failed to load {log_type} logs")
            
            successful_loads = [log_type for log_type, success in load_results.items() if success]
            logger.info(f"Successfully loaded logs: {successful_loads}")
            
            if not successful_loads:
                logger.error("Failed to load any log data")
                return False
            
            # Process data for baseline analysis in parallel
            futures = {}
            for log_type in successful_loads:
                if log_type in self.analyzers:
                    analyzer = self.analyzers[log_type]
                    future = self.thread_pool.submit(
                        self._process_log_data, analyzer, log_type
                    )
                    futures[future] = log_type
            
            # Wait for all processing to complete
            for future in as_completed(futures):
                log_type = futures[future]
                try:
                    success = future.result()
                    if success:
                        logger.info(f"Baseline analysis completed for {log_type}")
                    else:
                        logger.warning(f"Baseline analysis failed for {log_type}")
                except Exception as e:
                    logger.error(f"Error processing {log_type}: {e}")
            
            # Get overall statistics
            stats = self.zeek_parser.get_stats()
            logger.info(f"Baseline established: {stats['total_records_all_logs']} total records")
            
            return True
            
        except Exception as e:
            logger.error(f"Environment setup failed: {e}")
            return False

    def _get_enabled_log_types(self) -> List[str]:
        """Get list of enabled log types from config"""
        analysis_config = self.config.get('analysis', {})
        enabled_logs = []
        
        for log_type in ['dns', 'http', 'conn', 'ssl']:
            if analysis_config.get(f'enable_{log_type}_analysis', False):
                enabled_logs.append(log_type)
        
        # Əgər heç bir protokol aktiv deyilsə, default olaraq hamısını aktiv et
        if not enabled_logs:
            enabled_logs = ['dns', 'http', 'conn', 'ssl']
            # Config-i də yenilə
            for log_type in enabled_logs:
                self.config['analysis'][f'enable_{log_type}_analysis'] = True
        
        return enabled_logs

    def _process_log_data(self, analyzer, log_type: str) -> bool:
        """Process log data for a specific analyzer"""
        try:
            if hasattr(analyzer, 'process_dns_data'):
                return analyzer.process_dns_data(self.zeek_parser, log_type)
            elif hasattr(analyzer, 'process_http_data'):
                return analyzer.process_http_data(self.zeek_parser, log_type)
            elif hasattr(analyzer, 'process_conn_data'):
                return analyzer.process_conn_data(self.zeek_parser, log_type)
            elif hasattr(analyzer, 'process_ssl_data'):
                return analyzer.process_ssl_data(self.zeek_parser, log_type)
            return False
        except Exception as e:
            logger.error(f"Error processing {log_type} data: {e}")
            return False

    def real_time_callback(self, log_entry: Dict):
        """
        Enhanced real-time processing for all log types
        """
        try:
            log_type = log_entry.get('log_type', 'unknown')
            source_ip = log_entry.get('id.orig_h', 'unknown')
            
            # Route to appropriate analyzer
            if log_type in self.analyzers:
                analyzer = self.analyzers[log_type]
                
                # Process entry for immediate detection
                if log_type == 'dns':
                    immediate_alerts = self._check_immediate_dns_threats(log_entry)
                elif log_type == 'http':
                    immediate_alerts = self._check_immediate_http_threats(log_entry)
                elif log_type == 'conn':
                    immediate_alerts = self._check_immediate_conn_threats(log_entry)
                elif log_type == 'ssl':
                    immediate_alerts = self._check_immediate_ssl_threats(log_entry)
                else:
                    immediate_alerts = []
                
                # Process alerts
                for alert in immediate_alerts:
                    self.raise_alert(alert)
                
                # Update analyzer with real-time data
                if hasattr(analyzer, 'process_real_time_entry'):
                    analyzer_alert = analyzer.process_real_time_entry(log_entry)
                    if analyzer_alert:
                        self.raise_alert(analyzer_alert)
            
            # Performance-optimized logging
            if log_type == 'dns':
                query = log_entry.get('query', '')
                if len(query) > 70:
                    logger.debug(f"DNS: {source_ip} -> {query[:50]}...")
            elif log_type == 'http':
                uri = log_entry.get('uri', '')
                method = log_entry.get('method', '')
                logger.debug(f"HTTP: {source_ip} -> {method} {uri[:30]}...")
                
        except Exception as e:
            logger.error(f"Error in real-time processing: {e}")

    def _check_immediate_dns_threats(self, dns_entry: Dict) -> List[Dict]:
        """Immediate DNS threat detection"""
        alerts = []
        source_ip = dns_entry.get('id.orig_h')
        query = dns_entry.get('query', '')
        qtype = dns_entry.get('qtype_name', '')
        
        # Extreme length detection
        if len(query) > 100:
            alerts.append({
                'timestamp': datetime.now(),
                'alert_type': 'EXTREME_LENGTH_DOMAIN',
                'severity': 'HIGH',
                'severity_score': 95,
                'source_ip': source_ip,
                'domain': query,
                'length': len(query),
                'description': f'Extreme domain length: {len(query)} characters',
                'log_type': 'dns'
            })
        
        # Suspicious query types
        suspicious_types = ['TXT', 'NULL', 'ANY', 'AXFR']
        if qtype in suspicious_types:
            alerts.append({
                'timestamp': datetime.now(),
                'alert_type': 'SUSPICIOUS_QUERY_TYPE',
                'severity': 'MEDIUM',
                'severity_score': 75,
                'source_ip': source_ip,
                'query_type': qtype,
                'domain': query,
                'description': f'Suspicious DNS type: {qtype}',
                'log_type': 'dns'
            })
            
        return alerts

    def _check_immediate_http_threats(self, http_entry: Dict) -> List[Dict]:
        """Immediate HTTP threat detection"""
        alerts = []
        source_ip = http_entry.get('id.orig_h')
        uri = http_entry.get('uri', '')
        method = http_entry.get('method', '')
        status_code = http_entry.get('status_code', '')
        
        # Suspicious HTTP methods
        suspicious_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
        if method in suspicious_methods:
            alerts.append({
                'timestamp': datetime.now(),
                'alert_type': 'SUSPICIOUS_HTTP_METHOD',
                'severity': 'MEDIUM',
                'severity_score': 70,
                'source_ip': source_ip,
                'method': method,
                'uri': uri,
                'description': f'Suspicious HTTP method: {method}',
                'log_type': 'http'
            })
        
        # Error status codes
        if status_code.startswith('5'):
            alerts.append({
                'timestamp': datetime.now(),
                'alert_type': 'SERVER_ERROR',
                'severity': 'LOW',
                'severity_score': 50,
                'source_ip': source_ip,
                'status_code': status_code,
                'uri': uri,
                'description': f'Server error: {status_code}',
                'log_type': 'http'
            })
            
        return alerts

    def _check_immediate_conn_threats(self, conn_entry: Dict) -> List[Dict]:
        """Immediate connection threat detection"""
        alerts = []
        source_ip = conn_entry.get('id.orig_h')
        dest_port = conn_entry.get('id.resp_p', 0)
        conn_state = conn_entry.get('conn_state', '')
        
        # Suspicious ports
        suspicious_ports = self.config.get('conn_analysis', {}).get('suspicious_ports', [])
        if dest_port in suspicious_ports:
            alerts.append({
                'timestamp': datetime.now(),
                'alert_type': 'SUSPICIOUS_PORT',
                'severity': 'HIGH',
                'severity_score': 85,
                'source_ip': source_ip,
                'dest_port': dest_port,
                'description': f'Suspicious port connection: {dest_port}',
                'log_type': 'conn'
            })
            
        return alerts

    def _check_immediate_ssl_threats(self, ssl_entry: Dict) -> List[Dict]:
        """Immediate SSL threat detection"""
        alerts = []
        source_ip = ssl_entry.get('id.orig_h')
        ssl_version = ssl_entry.get('version', '')
        cipher = ssl_entry.get('cipher', '')
        
        # Weak SSL versions
        weak_versions = self.config.get('ssl_analysis', {}).get('weak_ssl_versions', [])
        if ssl_version in weak_versions:
            alerts.append({
                'timestamp': datetime.now(),
                'alert_type': 'WEAK_SSL_VERSION',
                'severity': 'HIGH',
                'severity_score': 90,
                'source_ip': source_ip,
                'ssl_version': ssl_version,
                'description': f'Weak SSL version: {ssl_version}',
                'log_type': 'ssl'
            })
            
        return alerts

    def raise_alert(self, alert: Dict):
        """Professional alert handling with deduplication and rate limiting"""
        alerting_config = self.config.get('alerting', {})
        max_alerts = alerting_config.get('max_alerts_per_hour', 1000)
        
        # Rate limiting
        if self.alert_count >= max_alerts:
            return
            
        # Deduplication
        alert_signature = self._create_alert_signature(alert)
        if alert_signature in self.alert_signatures:
            return
            
        # Cooldown check
        source_ip = alert.get('source_ip')
        if source_ip and source_ip in self.alert_cooldown:
            if datetime.now() - self.alert_cooldown[source_ip] < timedelta(minutes=5):
                return
        
        self.alert_count += 1
        alert['alert_id'] = self.alert_count
        alert['detector_version'] = '2.0.0'
        
        self.alerts.append(alert)
        self.alert_signatures.add(alert_signature)
        
        if source_ip:
            self.alert_cooldown[source_ip] = datetime.now()
        
        # Structured logging
        logger.warning(
            "C2 Alert detected",
            extra={
                'extra_data': {
                    'alert_id': alert['alert_id'],
                    'alert_type': alert['alert_type'],
                    'severity': alert['severity'],
                    'source_ip': alert.get('source_ip'),
                    'description': alert['description']
                }
            }
        )
        
        # Console output
        self._print_enhanced_alert(alert)
        
        # Persistence
        self._save_alert(alert)

    def _create_alert_signature(self, alert: Dict) -> str:
        """Create unique signature for alert deduplication"""
        components = [
            alert.get('alert_type', ''),
            alert.get('source_ip', ''),
            alert.get('log_type', ''),
            str(alert.get('severity_score', 0))
        ]
        return ':'.join(components)

    def _print_enhanced_alert(self, alert: Dict):
        """Professional console alert display"""
        severity = alert['severity']
        log_type = alert.get('log_type', 'unknown')
        
        colors = {
            'HIGH': '\033[91m',     # Red
            'MEDIUM': '\033[93m',   # Yellow
            'LOW': '\033[92m',      # Green
            'INFO': '\033[94m'      # Blue
        }
        color = colors.get(severity, '\033[0m')
        reset = '\033[0m'
        
        print(f"\n{color}╔{'═'*78}╗")
        print(f"║ 🚨 {log_type.upper()} ALERT - {severity} SEVERITY ({alert['severity_score']:.1f})")
        print(f"║ {'─'*76} ║")
        print(f"║ Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"║ Source:  {alert.get('source_ip', 'unknown')}")
        print(f"║ Type:    {alert['alert_type']}")
        print(f"║ ID:      {alert['alert_id']}")
        print(f"║ {'─'*76} ║")
        print(f"║ Description: {alert['description']}")
        
        # Additional details based on log type
        if log_type == 'dns' and 'domain' in alert:
            domain = alert['domain']
            print(f"║ Domain: {domain[:60]}{'...' if len(domain) > 60 else ''}")
        elif log_type == 'http' and 'uri' in alert:
            uri = alert['uri']
            print(f"║ URI: {uri[:60]}{'...' if len(uri) > 60 else ''}")
        elif log_type == 'conn' and 'dest_port' in alert:
            print(f"║ Port: {alert['dest_port']}")
            
        print(f"╚{'═'*78}╝{reset}")

    def _save_alert(self, alert: Dict):
        """Professional alert persistence"""
        try:
            alert_file = self.config.get('alerting', {}).get('log_file', 'data/alerts/c2_alerts.json')
            alert_path = Path(alert_file)
            alert_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Append to alert file
            with open(alert_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(alert, default=str, ensure_ascii=False) + '\n')
                
        except Exception as e:
            logger.error(f"Failed to save alert: {e}")

    def periodic_analysis(self):
        """Scheduled comprehensive multi-protocol analysis"""
        if (datetime.now() - self.last_analysis_time).total_seconds() < 300:  # 5 minutes
            return
            
        logger.info("Starting periodic comprehensive analysis...")
        self.last_analysis_time = datetime.now()
        
        try:
            analysis_config = self.config.get('analysis', {})
            window_minutes = analysis_config.get('window_minutes', 5)
            
            # Run analysis for each enabled log type in parallel
            futures = {}
            for log_type in self._get_enabled_log_types():
                if log_type in self.analyzers:
                    analyzer = self.analyzers[log_type]
                    future = self.thread_pool.submit(
                        self._run_analyzer_detection, analyzer, log_type, window_minutes
                    )
                    futures[future] = log_type
            
            # Process results
            total_alerts = 0
            for future in as_completed(futures):
                log_type = futures[future]
                try:
                    alerts = future.result()
                    for alert in alerts:
                        alert['log_type'] = log_type
                        self.raise_alert(alert)
                    total_alerts += len(alerts)
                    logger.info(f"Periodic analysis for {log_type}: {len(alerts)} alerts")
                except Exception as e:
                    logger.error(f"Periodic analysis failed for {log_type}: {e}")
            
            logger.info(f"Periodic analysis completed: {total_alerts} total alerts")
                
        except Exception as e:
            logger.error(f"Periodic analysis failed: {e}")

    def _run_analyzer_detection(self, analyzer, log_type: str, window_minutes: int) -> List[Dict]:
        """Run detection for a specific analyzer"""
        try:
            # Get recent data
            recent_data = self.zeek_parser.get_recent_entries(log_type, window_minutes)
            
            if recent_data.empty:
                return []
            
            # Create temporary analyzer
            if log_type == 'dns':
                temp_analyzer = DNSAnalyzer(self.config)
                temp_analyzer.process_dns_data(self.zeek_parser, log_type)
            elif log_type == 'http':
                temp_analyzer = HTTPAnalyzer(self.config)
                temp_analyzer.process_http_data(self.zeek_parser, log_type)
            elif log_type == 'conn':
                temp_analyzer = ConnAnalyzer(self.config)
                temp_analyzer.process_conn_data(self.zeek_parser, log_type)
            elif log_type == 'ssl':
                temp_analyzer = SSLAnalyzer(self.config)
                temp_analyzer.process_ssl_data(self.zeek_parser, log_type)
            else:
                return []
            
            # Run detection
            return temp_analyzer.detect_anomalies()
            
        except Exception as e:
            logger.error(f"Detection failed for {log_type}: {e}")
            return []

    def run_realtime_monitoring(self):
        """Professional real-time multi-protocol monitoring"""
        enabled_logs = self._get_enabled_log_types()
        
        logger.info(f"Starting professional real-time monitoring for: {enabled_logs}")
        
        print("\n" + "═" * 80)
        print("🚀 PROFESSIONAL C2 BEACON DETECTOR - MULTI-PROTOCOL MONITORING")
        print("═" * 80)
        print(f"Monitoring enabled protocols: {enabled_logs}")
        print("Press Ctrl+C for graceful shutdown")
        print("═" * 80 + "\n")
        
        try:
            # Main monitoring loop
            while self.running:
                # Yalnız aktiv olan log tiplərini izlə
                for log_type in enabled_logs:
                    self.zeek_parser.tail_log_type(
                        log_type,
                        self.real_time_callback,
                        max_lines=500  # Process in smaller batches
                    )
                    time.sleep(0.1)  # Small delay between log types
                
                # Periodic analysis
                self.periodic_analysis()
                time.sleep(60)  # Check every minute
                
        except KeyboardInterrupt:
            logger.info("Monitoring stopped gracefully by user")
        finally:
            self.generate_final_report()

    def generate_final_report(self):
        """Comprehensive final report with multi-protocol statistics"""
        duration = (datetime.now() - self.start_time).total_seconds() / 60
        
        print("\n" + "═" * 80)
        print("📊 PROFESSIONAL C2 DETECTION - COMPREHENSIVE REPORT")
        print("═" * 80)
        
        print(f"\nMonitoring Duration: {duration:.1f} minutes")
        print(f"Total Alerts Generated: {self.alert_count}")
        
        # Severity and protocol breakdown
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        protocol_counts = {'dns': 0, 'http': 0, 'conn': 0, 'ssl': 0}
        
        for alert in self.alerts:
            severity = alert.get('severity', 'UNKNOWN')
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            log_type = alert.get('log_type', 'unknown')
            if log_type in protocol_counts:
                protocol_counts[log_type] += 1
        
        print(f"\nSeverity Breakdown:")
        for severity, count in severity_counts.items():
            print(f"  {severity}: {count} alerts")
        
        print(f"\nProtocol Breakdown:")
        for protocol, count in protocol_counts.items():
            if count > 0:
                print(f"  {protocol.upper()}: {count} alerts")
        
        # Top sources
        source_counts = {}
        for alert in self.alerts:
            source = alert.get('source_ip', 'unknown')
            source_counts[source] = source_counts.get(source, 0) + 1
        
        if source_counts:
            print(f"\nTop Alerting Sources:")
            for source, count in sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  {source}: {count} alerts")
        
        print(f"\nDetailed alerts saved to: data/alerts/c2_alerts.json")
        print(f"Log file: data/logs/c2_detector.log")
        print("═" * 80)

# src/core/detector.py - main() funksiyasında

def main():
    """Professional main entry point with multi-protocol support"""
    parser = argparse.ArgumentParser(
        description='Professional C2 Beacon Detection System with Multi-Protocol Support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m src.core.detector --test      # Test mode
  python -m src.core.detector --config custom_config.json  # Custom config
  python -m src.core.detector --verbose   # Verbose output
  python -m src.core.detector --protocol dns  # Monitor only DNS
        """
    )
    
    parser.add_argument('--config', default='config.json', help='Path to configuration file')
    parser.add_argument('--test', action='store_true', help='Test mode without real-time monitoring')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--protocol', choices=['dns', 'http', 'conn', 'ssl', 'all'], 
                       default='all', help='Specific protocol to monitor')
    
    args = parser.parse_args()
    
    try:
        # Setup logging
        config = load_config(args.config)
        log_level = 'DEBUG' if args.verbose else config.get('logging', {}).get('level', 'INFO')
        config['logging']['level'] = log_level
        setup_logging(config)
        
        logger.info("Starting Professional C2 Detector with Multi-Protocol Support")
        
        # Protocol seçimini config-ə əlavə et
        if args.protocol != 'all':
            config['analysis'][f'enable_{args.protocol}_analysis'] = True
            # Digər protokolları söndür
            for proto in ['dns', 'http', 'conn', 'ssl']:
                if proto != args.protocol:
                    config['analysis'][f'enable_{proto}_analysis'] = False
        
        # Initialize and run detector
        detector = C2Detector(args.config)
        detector.config = config  # Yenilənmiş config-i təyin et
        
        if detector.setup_environment():
            if args.test:
                logger.info("Running in test mode...")
                detector.periodic_analysis()
                detector.generate_final_report()
            else:
                detector.run_realtime_monitoring()
        else:
            logger.error("Failed to initialize detector environment")
            sys.exit(1)
            
    except Exception as e:
        logger.critical(f"Fatal error in C2 detector: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
