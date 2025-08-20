# src/core/detector.py
#!/usr/bin/env python3
"""
Professional C2 Beacon Detection System
Enhanced with better error handling, performance monitoring, and reporting
"""

import json
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional
import argparse
import signal
import sys
from pathlib import Path

from .log_parser import ZeekLogParser
from .dns_analyzer import DNSAnalyzer
from ..utils.logger import setup_logging
from ..utils.helpers import load_config

logger = logging.getLogger('C2Detector')

class C2Detector:
    """
    Professional C2 detection system with enhanced monitoring and reporting
    """
    
    def __init__(self, config_path: str = "config.json"):
        """
        Initialize professional C2 detector
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        self.config = load_config(config_path)
        self.alerts: List[Dict] = []
        self.alert_count = 0
        self.start_time = datetime.now()
        self.running = True
        
        # Setup signal handling for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Initialize components
        self.zeek_parser = ZeekLogParser(config_path)
        self.dns_analyzer = DNSAnalyzer(self.config)
        
        logger.info("Professional C2 Detector initialized successfully")

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
        self.generate_final_report()
        sys.exit(0)

    def setup_environment(self) -> bool:
        """
        Setup monitoring environment with validation
        
        Returns:
            True if setup successful, False otherwise
        """
        logger.info("Setting up professional monitoring environment...")
        
        try:
            # Read historical data for baseline
            analysis_config = self.config.get('analysis', {})
            historical_days = analysis_config.get('historical_days', 1)
            
            if not self.zeek_parser.read_historical(days=historical_days):
                logger.error("Failed to read historical DNS data")
                return False
            
            if self.zeek_parser.df.empty:
                logger.warning("No historical DNS data found")
                return True
            
            # Process data for baseline analysis
            self.dns_analyzer.process_dns_data(self.zeek_parser)
            
            stats = self.zeek_parser.get_stats()
            logger.info(f"Baseline established: {stats['total_records']} records, "
                       f"{stats['unique_sources']} unique sources")
            
            return True
            
        except Exception as e:
            logger.error(f"Environment setup failed: {e}")
            return False

    def real_time_dns_callback(self, dns_entry: Dict):
        """
        Enhanced real-time DNS processing with performance monitoring
        """
        try:
            source_ip = dns_entry.get('id.orig_h', 'unknown')
            query = dns_entry.get('query', '')
            qtype = dns_entry.get('qtype_name', '')
            
            # Immediate threat detection
            immediate_alerts = self._check_immediate_threats(dns_entry)
            for alert in immediate_alerts:
                self.raise_alert(alert)
            
            # Performance-optimized logging
            if len(query) > 70:
                logger.debug(f"Long query: {source_ip} -> {query[:50]}... ({qtype})")
            else:
                logger.debug(f"Query: {source_ip} -> {query} ({qtype})")
                
        except Exception as e:
            logger.error(f"Error in real-time processing: {e}")

    def _check_immediate_threats(self, dns_entry: Dict) -> List[Dict]:
        """Enhanced immediate threat detection"""
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
                'description': f'Extreme domain length: {len(query)} characters'
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
                'description': f'Suspicious DNS type: {qtype}'
            })
            
        return alerts

    def raise_alert(self, alert: Dict):
        """Professional alert handling with rate limiting"""
        alerting_config = self.config.get('alerting', {})
        max_alerts = alerting_config.get('max_alerts_per_hour', 1000)
        
        # Rate limiting
        if self.alert_count >= max_alerts:
            logger.warning("Alert rate limit reached, suppressing further alerts")
            return
            
        self.alert_count += 1
        alert['alert_id'] = self.alert_count
        alert['detector_version'] = '1.0.0'
        
        self.alerts.append(alert)
        
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

    def _print_enhanced_alert(self, alert: Dict):
        """Professional console alert display"""
        severity = alert['severity']
        colors = {
            'HIGH': '\033[91m',     # Red
            'MEDIUM': '\033[93m',   # Yellow
            'LOW': '\033[92m',      # Green
            'INFO': '\033[94m'      # Blue
        }
        color = colors.get(severity, '\033[0m')
        reset = '\033[0m'
        
        print(f"\n{color}╔{'═'*78}╗")
        print(f"║ 🚨 C2 DETECTION ALERT - {severity} SEVERITY ({alert['severity_score']:.1f})")
        print(f"║ {'─'*76} ║")
        print(f"║ Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"║ Source:  {alert.get('source_ip', 'unknown')}")
        print(f"║ Type:    {alert['alert_type']}")
        print(f"║ ID:      {alert['alert_id']}")
        print(f"║ {'─'*76} ║")
        print(f"║ Description: {alert['description']}")
        
        # Additional details
        if 'query_count' in alert:
            print(f"║ Query Count: {alert['query_count']}")
        if 'domain' in alert:
            domain = alert['domain']
            print(f"║ Domain: {domain[:60]}{'...' if len(domain) > 60 else ''}")
            
        print(f"╚{'═'*78}╝{reset}")

    def _save_alert(self, alert: Dict):
        """Professional alert persistence"""
        try:
            alert_file = self.config.get('alerting', {}).get('log_file', 'data/alerts/c2_alerts.json')
            alert_path = Path(alert_file)
            alert_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Append to alert file
            with open(alert_path, 'a') as f:
                f.write(json.dumps(alert, default=str) + '\n')
                
        except Exception as e:
            logger.error(f"Failed to save alert: {e}")

    def periodic_analysis(self):
        """Scheduled comprehensive analysis"""
        logger.info("Starting periodic comprehensive analysis...")
        
        try:
            analysis_config = self.config.get('analysis', {})
            window_minutes = analysis_config.get('window_minutes', 5)
            
            recent_data = self.zeek_parser.get_recent_entries(minutes=window_minutes)
            
            if not recent_data.empty:
                # Create temporary analyzer for recent data
                temp_analyzer = DNSAnalyzer(self.config)
                self.zeek_parser.df = recent_data
                temp_analyzer.process_dns_data(self.zeek_parser)
                
                # Run detection
                new_alerts = temp_analyzer.detect_anomalies()
                
                # Process new alerts
                for alert in new_alerts:
                    self.raise_alert(alert)
                    
                logger.info(f"Periodic analysis completed: {len(new_alerts)} new alerts")
            else:
                logger.info("No recent data for periodic analysis")
                
        except Exception as e:
            logger.error(f"Periodic analysis failed: {e}")

    def run_realtime_monitoring(self):
        """Professional real-time monitoring"""
        logger.info("Starting professional real-time monitoring...")
        
        print("\n" + "═" * 80)
        print("🚀 PROFESSIONAL C2 BEACON DETECTOR - REAL-TIME MONITORING")
        print("═" * 80)
        print("Monitoring DNS traffic for advanced C2 beaconing and tunneling...")
        print("Press Ctrl+C for graceful shutdown")
        print("═" * 80 + "\n")
        
        try:
            # Main monitoring loop
            while self.running:
                self.zeek_parser.tail_new_entries(
                    self.real_time_dns_callback,
                    max_lines=1000  # Process in batches
                )
                
                # Periodic analysis every 5 minutes
                time.sleep(300)  # 5 minutes
                self.periodic_analysis()
                
        except KeyboardInterrupt:
            logger.info("Monitoring stopped gracefully by user")
        finally:
            self.generate_final_report()

    def generate_final_report(self):
        """Comprehensive final report"""
        duration = (datetime.now() - self.start_time).total_seconds() / 60
        
        print("\n" + "═" * 80)
        print("📊 PROFESSIONAL C2 DETECTION - COMPREHENSIVE REPORT")
        print("═" * 80)
        
        print(f"\nMonitoring Duration: {duration:.1f} minutes")
        print(f"Total Alerts Generated: {self.alert_count}")
        
        # Severity breakdown
        severity_counts = {
            'HIGH': len([a for a in self.alerts if a['severity'] == 'HIGH']),
            'MEDIUM': len([a for a in self.alerts if a['severity'] == 'MEDIUM']),
            'LOW': len([a for a in self.alerts if a['severity'] == 'LOW'])
        }
        
        print(f"\nSeverity Breakdown:")
        for severity, count in severity_counts.items():
            print(f"  {severity}: {count} alerts")
        
        # Top sources
        source_counts = {}
        for alert in self.alerts:
            source = alert.get('source_ip', 'unknown')
            source_counts[source] = source_counts.get(source, 0) + 1
        
        if source_counts:
            print(f"\nTop Alerting Sources:")
            for source, count in sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  {source}: {count} alerts")
        
        # Alert types
        alert_types = {}
        for alert in self.alerts:
            alert_type = alert['alert_type']
            alert_types[alert_type] = alert_types.get(alert_type, 0) + 1
        
        if alert_types:
            print(f"\nAlert Types Distribution:")
            for alert_type, count in alert_types.items():
                print(f"  {alert_type}: {count}")
        
        print(f"\nDetailed alerts saved to: data/alerts/c2_alerts.json")
        print(f"Log file: data/logs/c2_detector.log")
        print("═" * 80)

def main():
    """Professional main entry point"""
    parser = argparse.ArgumentParser(
        description='Professional C2 Beacon Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m src.core.detector --test      # Test mode
  python -m src.core.detector --config custom_config.json  # Custom config
  python -m src.core.detector             # Production mode
        """
    )
    
    parser.add_argument('--config', default='config.json', help='Path to configuration file')
    parser.add_argument('--test', action='store_true', help='Test mode without real-time monitoring')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    try:
        # Setup logging
        config = load_config(args.config)
        log_level = 'DEBUG' if args.verbose else config.get('logging', {}).get('level', 'INFO')
        config['logging']['level'] = log_level
        setup_logging(config)
        
        logger.info("Starting Professional C2 Detector")
        
        # Initialize and run detector
        detector = C2Detector(args.config)
        
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
