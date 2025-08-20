# src/core/log_parser.py
import pandas as pd
from pathlib import Path
import tailer
import time
from datetime import datetime
import json
import logging
from typing import Dict, Optional, Callable, List, Any
import argparse

from ..utils.helpers import load_config

logger = logging.getLogger('ZeekParser')

class ZeekLogParser:
    """
    Professional Zeek DNS log parser with enhanced error handling and performance
    """
    
    # DNS log columns with descriptions
    DNS_COLUMNS = [
        'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 
        'proto', 'trans_id', 'query', 'qclass', 'qclass_name', 'qtype', 
        'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD', 'RA', 'Z', 
        'answers', 'TTLs', 'rejected'
    ]
    
    # Column descriptions for documentation
    COLUMN_DESCRIPTIONS = {
        'ts': 'Timestamp of the DNS query',
        'id.orig_h': 'Source IP address',
        'id.resp_h': 'Responder IP address',
        'query': 'DNS query name',
        'qtype_name': 'Query type (A, AAAA, TXT, etc.)',
        'rcode_name': 'Response code name'
    }
    
    def __init__(self, config_path: str = "config.json"):
        """
        Initialize Zeek log parser with configuration
        
        Args:
            config_path: Path to configuration file
        """
        self.config = load_config(config_path)
        zeek_config = self.config.get('zeek', {})
        
        self.zeek_log_dir = Path(zeek_config.get('log_dir', '/opt/zeek/logs/current'))
        self.dns_log_path = self.zeek_log_dir / 'dns.log'
        self.monitor_interfaces = zeek_config.get('monitor_interfaces', ['eth0'])
        
        self.df = pd.DataFrame()
        self.last_position = 0
        self.processed_count = 0
        
        logger.info(f"ZeekLogParser initialized for DNS logs")
        logger.info(f"Monitoring directory: {self.zeek_log_dir}")

    def _validate_log_file(self) -> bool:
        """
        Validate that the DNS log file exists and is accessible
        
        Returns:
            True if valid, False otherwise
        """
        if not self.dns_log_path.exists():
            logger.error(f"DNS log file not found: {self.dns_log_path}")
            return False
        
        if not self.dns_log_path.is_file():
            logger.error(f"DNS log path is not a file: {self.dns_log_path}")
            return False
            
        try:
            # Test file accessibility
            with open(self.dns_log_path, 'r'):
                pass
            return True
        except IOError as e:
            logger.error(f"Cannot access DNS log file: {e}")
            return False

    def read_historical(self, days: Optional[int] = None) -> bool:
        """
        Read historical DNS data with optional time window
        
        Args:
            days: Number of days to look back (None for all available)
            
        Returns:
            True if successful, False otherwise
        """
        if not self._validate_log_file():
            return False

        try:
            # Read the entire log file
            self.df = pd.read_csv(
                self.dns_log_path, 
                comment='#', 
                sep='\t', 
                names=self.DNS_COLUMNS, 
                low_memory=False,
                na_values=['-'],  # Handle missing values
                keep_default_na=False
            )
            
            logger.info(f"Read {len(self.df)} historical records from dns.log")
            
            # Convert and validate timestamp
            if 'ts' in self.df.columns:
                self.df['ts'] = pd.to_datetime(self.df['ts'], unit='s', errors='coerce')
                valid_timestamps = self.df['ts'].notna()
                if not valid_timestamps.all():
                    invalid_count = (~valid_timestamps).sum()
                    logger.warning(f"Found {invalid_count} records with invalid timestamps")
                    self.df = self.df[valid_timestamps]
                
                self.df.set_index('ts', inplace=True)
                
                # Filter by time window if specified
                if days is not None:
                    cutoff_time = datetime.now() - pd.Timedelta(days=days)
                    self.df = self.df[self.df.index >= cutoff_time]
                    logger.info(f"Filtered to {len(self.df)} records from last {days} days")
            
            # Basic data validation
            self._validate_data_quality()
            
            return True
                
        except Exception as e:
            logger.error(f"Failed to read historical data: {e}")
            self.df = pd.DataFrame()
            return False

    def _validate_data_quality(self):
        """Perform basic data quality checks"""
        if self.df.empty:
            return
            
        # Check for missing critical columns
        critical_columns = ['id.orig_h', 'query', 'qtype_name']
        missing_columns = [col for col in critical_columns if col not in self.df.columns]
        if missing_columns:
            logger.warning(f"Missing critical columns: {missing_columns}")
        
        # Check data completeness
        total_records = len(self.df)
        for col in critical_columns:
            if col in self.df.columns:
                missing_count = self.df[col].isna().sum()
                if missing_count > 0:
                    logger.warning(f"Column {col} has {missing_count} missing values ({missing_count/total_records:.1%})")

    def tail_new_entries(self, callback_func: Callable, max_lines: Optional[int] = None):
        """
        Tail DNS log file and process new entries in real-time
        
        Args:
            callback_func: Function to call for each new entry
            max_lines: Maximum number of lines to process (None for unlimited)
        """
        if not self._validate_log_file():
            return

        try:
            logger.info("Starting real-time DNS log monitoring...")
            
            with open(self.dns_log_path, 'r') as f:
                # Skip to end of file if this is the first run
                if self.last_position == 0:
                    f.seek(0, 2)  # Seek to end
                
                for line in tailer.follow(f):
                    if line.startswith('#'):
                        continue
                    
                    try:
                        fields = line.strip().split('\t')
                        if len(fields) == len(self.DNS_COLUMNS):
                            entry = dict(zip(self.DNS_COLUMNS, fields))
                            
                            # Convert timestamp
                            try:
                                entry['ts'] = pd.to_datetime(float(entry['ts']), unit='s')
                            except (ValueError, TypeError):
                                entry['ts'] = None
                            
                            # Process the entry
                            callback_func(entry)
                            self.processed_count += 1
                            
                            # Log progress periodically
                            if self.processed_count % 1000 == 0:
                                logger.info(f"Processed {self.processed_count} real-time entries")
                            
                        else:
                            logger.warning(f"Field count mismatch: {len(fields)} vs {len(self.DNS_COLUMNS)}")
                        
                        # Check max lines limit
                        if max_lines is not None:
                            max_lines -= 1
                            if max_lines <= 0:
                                break
                                
                    except Exception as e:
                        logger.error(f"Error processing line: {e}")
                        continue
                        
                    # Small sleep to prevent CPU overload
                    time.sleep(0.001)
                    
        except KeyboardInterrupt:
            logger.info("DNS log monitoring stopped by user")
        except Exception as e:
            logger.error(f"Error in tailing process: {e}")

    def get_recent_entries(self, minutes: int = 60) -> pd.DataFrame:
        """
        Get DNS entries from the last N minutes
        
        Args:
            minutes: Number of minutes to look back
            
        Returns:
            Filtered DataFrame with recent DNS entries
        """
        if self.df.empty or not isinstance(self.df.index, pd.DatetimeIndex):
            return self.df
        
        cutoff_time = datetime.now() - pd.Timedelta(minutes=minutes)
        recent_data = self.df[self.df.index >= cutoff_time]
        
        logger.debug(f"Retrieved {len(recent_data)} entries from last {minutes} minutes")
        return recent_data

    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the loaded data
        
        Returns:
            Dictionary with data statistics
        """
        if self.df.empty:
            return {"total_records": 0, "time_range": "No data"}
        
        stats = {
            "total_records": len(self.df),
            "time_range": f"{self.df.index.min()} to {self.df.index.max()}",
            "duration_hours": (self.df.index.max() - self.df.index.min()).total_seconds() / 3600,
            "unique_sources": self.df['id.orig_h'].nunique() if 'id.orig_h' in self.df.columns else 0,
            "unique_domains": self.df['query'].nunique() if 'query' in self.df.columns else 0
        }
        
        return stats

def print_dns_entry(entry):
    """Print DNS entry for testing purposes"""
    print(f"DNS Query: {entry.get('id.orig_h', 'N/A')} -> {entry.get('query', 'N/A')} ({entry.get('qtype_name', 'N/A')})")

def main():
    """Main function to demonstrate the parser functionality"""
    parser = argparse.ArgumentParser(description='Zeek DNS Log Parser for C2 Detection')
    parser.add_argument('--config', type=str, help='Path to configuration file')
    parser.add_argument('--test', action='store_true', help='Run in test mode')
    args = parser.parse_args()

    zeek_parser = ZeekLogParser(config_path=args.config)
    
    if args.test:
        print("Running in test mode for DNS logs...")
        zeek_parser.read_historical()
        
        if not zeek_parser.df.empty:
            print(f"\nDNS Log Statistics:")
            print(f"Total records: {len(zeek_parser.df)}")
            print(f"Time range: {zeek_parser.df.index.min()} to {zeek_parser.df.index.max()}")
            print(f"Unique source hosts: {zeek_parser.df['id.orig_h'].nunique()}")
            print(f"Unique domains queried: {zeek_parser.df['query'].nunique()}")
            
            print("\nSample DNS queries:")
            print(zeek_parser.df[['id.orig_h', 'query', 'qtype_name']].head(3).to_string())
    else:
        print("Starting to tail DNS logs. Press Ctrl+C to stop.")
        zeek_parser.tail_new_entries(print_dns_entry)

if __name__ == "__main__":
    main()
