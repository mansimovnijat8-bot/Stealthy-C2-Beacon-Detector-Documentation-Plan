# src/core/log_parser.py
import pandas as pd
from pathlib import Path
import tailer
import time
from datetime import datetime
import json
import logging
from typing import Dict, Optional, Callable, List, Any, Tuple, Set
import argparse
import re
import glob

from ..utils.helpers import load_config

logger = logging.getLogger('ZeekParser')

class ZeekLogParser:
    """
    Professional Zeek log parser with support for all log types and dynamic column detection
    """
    
    # Common Zeek log types and their typical columns
    COMMON_LOG_TYPES = {
        'conn': ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 
                'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 
                'conn_state', 'local_orig', 'local_resp', 'missed_bytes', 
                'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 
                'tunnel_parents'],
        'dns': ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 
               'proto', 'trans_id', 'query', 'qclass', 'qclass_name', 'qtype', 
               'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD', 'RA', 'Z', 
               'answers', 'TTLs', 'rejected'],
        'http': ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 
                'trans_depth', 'method', 'host', 'uri', 'referrer', 'user_agent', 
                'request_body_len', 'response_body_len', 'status_code', 'status_msg', 
                'info_code', 'info_msg', 'tags', 'username', 'password', 'proxied', 
                'orig_fuids', 'orig_filenames', 'orig_mime_types', 'resp_fuids', 
                'resp_filenames', 'resp_mime_types'],
        'ssl': ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 
               'version', 'cipher', 'curve', 'server_name', 'resumed', 'established', 
               'cert_chain_fuids', 'client_cert_chain_fuids', 'subject', 'issuer', 
               'validation_status'],
        'files': ['ts', 'fuid', 'tx_hosts', 'rx_hosts', 'conn_uids', 'source', 
                 'depth', 'analyzers', 'mime_type', 'filename', 'duration', 
                 'local_orig', 'is_orig', 'seen_bytes', 'total_bytes', 'missing_bytes', 
                 'overflow_bytes', 'timedout', 'parent_fuid', 'md5', 'sha1', 'sha256'],
        'ssh': ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 
               'version', 'auth_success', 'auth_attempts', 'direction', 'client', 
               'server', 'cipher_alg', 'mac_alg', 'compression_alg', 'kex_alg', 
               'host_key_alg']
    }
    
    def __init__(self, config_path: str = "config.json"):
        """
        Initialize Zeek log parser with configuration
        
        Args:
            config_path: Path to configuration file
        """
        self.config = load_config(config_path)
        zeek_config = self.config.get('zeek', {})
        
        self.zeek_log_dir = Path(zeek_config.get('log_dir', '/opt/zeek/logs'))
        self.monitor_interfaces = zeek_config.get('monitor_interfaces', ['eth0'])
        
        self.available_logs = self._discover_log_files()
        self.active_log_types: Set[str] = set()
        self.log_dataframes: Dict[str, pd.DataFrame] = {}
        self.log_columns: Dict[str, List[str]] = {}
        self.last_positions: Dict[str, int] = {}
        self.processed_counts: Dict[str, int] = {}
        
        logger.info(f"ZeekLogParser initialized for all log types")
        logger.info(f"Monitoring directory: {self.zeek_log_dir}")
        logger.info(f"Available log types: {list(self.available_logs.keys())}")

    def _discover_log_files(self) -> Dict[str, Path]:
        """
        Discover all available Zeek log files in the directory
        
        Returns:
            Dictionary mapping log types to their file paths
        """
        log_files = {}
        pattern = self.zeek_log_dir / '*.log'
        
        for log_path in glob.glob(str(pattern)):
            log_name = Path(log_path).stem  # Remove .log extension
            log_files[log_name] = Path(log_path)
            
        return log_files

    def _extract_columns_from_header(self, log_path: Path) -> Optional[List[str]]:
        """
        Extract column names from Zeek log header
        
        Args:
            log_path: Path to the log file
            
        Returns:
            List of column names or None if extraction fails
        """
        try:
            with open(log_path, 'r') as f:
                for line in f:
                    if line.startswith('#fields'):
                        # Extract columns from #fields line
                        columns = line.strip().split('\t')[1:]  # Skip '#fields'
                        return columns
                    elif line.startswith('#') and not line.startswith('#separator'):
                        continue
                    else:
                        break
        except Exception as e:
            logger.error(f"Failed to extract columns from {log_path}: {e}")
        
        return None

    def _validate_log_file(self, log_type: str) -> bool:
        """
        Validate that a specific log file exists and is accessible
        
        Args:
            log_type: Type of log to validate (e.g., 'dns', 'conn')
            
        Returns:
            True if valid, False otherwise
        """
        if log_type not in self.available_logs:
            logger.error(f"Log type '{log_type}' not found in available logs")
            return False
            
        log_path = self.available_logs[log_type]
        
        if not log_path.exists():
            logger.error(f"Log file not found: {log_path}")
            return False
        
        if not log_path.is_file():
            logger.error(f"Log path is not a file: {log_path}")
            return False
            
        try:
            # Test file accessibility
            with open(log_path, 'r'):
                pass
            return True
        except IOError as e:
            logger.error(f"Cannot access log file {log_path}: {e}")
            return False

    def get_available_log_types(self) -> List[str]:
        """
        Get list of available log types
        
        Returns:
            List of available log type names
        """
        return list(self.available_logs.keys())

    def load_log_type(self, log_type: str, days: Optional[int] = None) -> bool:
        """
        Load historical data for a specific log type
        
        Args:
            log_type: Type of log to load (e.g., 'dns', 'conn')
            days: Number of days to look back (None for all available)
            
        Returns:
            True if successful, False otherwise
        """
        if not self._validate_log_file(log_type):
            return False

        try:
            log_path = self.available_logs[log_type]
            
            # Extract columns from log header
            columns = self._extract_columns_from_header(log_path)
            if not columns:
                # Fallback to known columns if header extraction fails
                columns = self.COMMON_LOG_TYPES.get(log_type, [])
                logger.warning(f"Using fallback columns for {log_type}: {columns}")
            
            self.log_columns[log_type] = columns
            
            # Read the log file
            df = pd.read_csv(
                log_path, 
                comment='#', 
                sep='\t', 
                names=columns, 
                low_memory=False,
                na_values=['-'],  # Handle missing values
                keep_default_na=False
            )
            
            logger.info(f"Read {len(df)} historical records from {log_type}.log")
            
            # Convert and validate timestamp if present
            if 'ts' in df.columns:
                df['ts'] = pd.to_datetime(df['ts'], unit='s', errors='coerce')
                valid_timestamps = df['ts'].notna()
                if not valid_timestamps.all():
                    invalid_count = (~valid_timestamps).sum()
                    logger.warning(f"Found {invalid_count} records with invalid timestamps in {log_type}")
                    df = df[valid_timestamps]
                
                df.set_index('ts', inplace=True)
                
                # Filter by time window if specified
                if days is not None:
                    cutoff_time = datetime.now() - pd.Timedelta(days=days)
                    df = df[df.index >= cutoff_time]
                    logger.info(f"Filtered {log_type} to {len(df)} records from last {days} days")
            
            self.log_dataframes[log_type] = df
            self.active_log_types.add(log_type)
            self.processed_counts[log_type] = 0
            
            # Basic data validation
            self._validate_data_quality(log_type)
            
            return True
                
        except Exception as e:
            logger.error(f"Failed to read historical data for {log_type}: {e}")
            return False

    def load_all_logs(self, days: Optional[int] = None) -> Dict[str, bool]:
        """
        Load all available log types
        
        Args:
            days: Number of days to look back (None for all available)
            
        Returns:
            Dictionary mapping log types to success status
        """
        results = {}
        for log_type in self.available_logs.keys():
            results[log_type] = self.load_log_type(log_type, days)
        
        return results

    def _validate_data_quality(self, log_type: str):
        """Perform basic data quality checks for a specific log type"""
        if log_type not in self.log_dataframes or self.log_dataframes[log_type].empty:
            return
            
        df = self.log_dataframes[log_type]
        
        # Check for missing critical columns based on log type
        critical_columns = self._get_critical_columns(log_type)
        missing_columns = [col for col in critical_columns if col not in df.columns]
        if missing_columns:
            logger.warning(f"Missing critical columns in {log_type}: {missing_columns}")
        
        # Check data completeness
        total_records = len(df)
        for col in critical_columns:
            if col in df.columns:
                missing_count = df[col].isna().sum()
                if missing_count > 0:
                    logger.warning(f"Column {col} in {log_type} has {missing_count} missing values ({missing_count/total_records:.1%})")

    def _get_critical_columns(self, log_type: str) -> List[str]:
        """Get critical columns for a specific log type"""
        critical_columns_map = {
            'conn': ['id.orig_h', 'id.resp_h', 'proto', 'conn_state'],
            'dns': ['id.orig_h', 'query', 'qtype_name', 'rcode_name'],
            'http': ['id.orig_h', 'host', 'uri', 'method', 'status_code'],
            'ssl': ['id.orig_h', 'server_name', 'version'],
            'files': ['tx_hosts', 'filename', 'mime_type'],
            'ssh': ['id.orig_h', 'auth_success', 'client']
        }
        
        return critical_columns_map.get(log_type, ['ts'])

    def tail_log_type(self, log_type: str, callback_func: Callable, max_lines: Optional[int] = None):
        """
        Tail a specific log file and process new entries in real-time
        
        Args:
            log_type: Type of log to tail
            callback_func: Function to call for each new entry
            max_lines: Maximum number of lines to process (None for unlimited)
        """
        if not self._validate_log_file(log_type):
            return

        try:
            log_path = self.available_logs[log_type]
            columns = self.log_columns.get(log_type, [])
            
            if not columns:
                logger.error(f"No columns defined for log type {log_type}")
                return
            
            logger.info(f"Starting real-time monitoring for {log_type} logs...")
            
            with open(log_path, 'r') as f:
                # Skip to end of file if this is the first run
                if self.last_positions.get(log_type, 0) == 0:
                    f.seek(0, 2)  # Seek to end
                
                for line in tailer.follow(f):
                    if line.startswith('#'):
                        continue
                    
                    try:
                        fields = line.strip().split('\t')
                        if len(fields) == len(columns):
                            entry = dict(zip(columns, fields))
                            entry['log_type'] = log_type  # Add log type identifier
                            
                            # Convert timestamp if present
                            if 'ts' in entry and entry['ts']:
                                try:
                                    entry['ts'] = pd.to_datetime(float(entry['ts']), unit='s')
                                except (ValueError, TypeError):
                                    entry['ts'] = None
                            
                            # Process the entry
                            callback_func(entry)
                            self.processed_counts[log_type] = self.processed_counts.get(log_type, 0) + 1
                            
                            # Log progress periodically
                            if self.processed_counts[log_type] % 1000 == 0:
                                logger.info(f"Processed {self.processed_counts[log_type]} real-time entries for {log_type}")
                            
                        else:
                            logger.warning(f"Field count mismatch in {log_type}: {len(fields)} vs {len(columns)}")
                        
                        # Check max lines limit
                        if max_lines is not None:
                            max_lines -= 1
                            if max_lines <= 0:
                                break
                                
                    except Exception as e:
                        logger.error(f"Error processing line in {log_type}: {e}")
                        continue
                        
                    # Small sleep to prevent CPU overload
                    time.sleep(0.001)
                    
        except KeyboardInterrupt:
            logger.info(f"{log_type} log monitoring stopped by user")
        except Exception as e:
            logger.error(f"Error in tailing process for {log_type}: {e}")

    def tail_all_logs(self, callback_func: Callable, max_lines_per_log: Optional[int] = None):
        """
        Tail all available log files concurrently (using threading in production)
        
        Args:
            callback_func: Function to call for each new entry
            max_lines_per_log: Maximum number of lines to process per log
        """
        # In a production environment, you would use threading here
        # For simplicity, this implementation processes logs sequentially
        # Consider using threading or asyncio for concurrent processing
        
        for log_type in self.active_log_types:
            self.tail_log_type(log_type, callback_func, max_lines_per_log)

    def get_recent_entries(self, log_type: str, minutes: int = 60) -> pd.DataFrame:
        """
        Get entries from the last N minutes for a specific log type
        
        Args:
            log_type: Type of log to query
            minutes: Number of minutes to look back
            
        Returns:
            Filtered DataFrame with recent entries
        """
        if (log_type not in self.log_dataframes or 
            self.log_dataframes[log_type].empty or 
            not isinstance(self.log_dataframes[log_type].index, pd.DatetimeIndex)):
            return pd.DataFrame()
        
        df = self.log_dataframes[log_type]
        cutoff_time = datetime.now() - pd.Timedelta(minutes=minutes)
        recent_data = df[df.index >= cutoff_time]
        
        logger.debug(f"Retrieved {len(recent_data)} {log_type} entries from last {minutes} minutes")
        return recent_data

    def get_log_data(self, log_type: str) -> pd.DataFrame:
        """
        Get the complete DataFrame for a specific log type
        
        Args:
            log_type: Type of log to retrieve
            
        Returns:
            DataFrame with all loaded data for the log type
        """
        return self.log_dataframes.get(log_type, pd.DataFrame())

    def get_stats(self, log_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Get statistics about the loaded data
        
        Args:
            log_type: Specific log type to get stats for (None for all)
            
        Returns:
            Dictionary with data statistics
        """
        if log_type:
            return self._get_single_log_stats(log_type)
        else:
            return self._get_all_logs_stats()

    def _get_single_log_stats(self, log_type: str) -> Dict[str, Any]:
        """Get statistics for a single log type"""
        if log_type not in self.log_dataframes or self.log_dataframes[log_type].empty:
            return {"log_type": log_type, "total_records": 0, "status": "No data loaded"}
        
        df = self.log_dataframes[log_type]
        
        stats = {
            "log_type": log_type,
            "total_records": len(df),
            "time_range": f"{df.index.min()} to {df.index.max()}" if not df.empty else "No data",
            "duration_hours": (df.index.max() - df.index.min()).total_seconds() / 3600 if len(df) > 1 else 0,
            "columns": list(df.columns),
            "memory_usage_mb": df.memory_usage(deep=True).sum() / 1024 / 1024
        }
        
        # Add log-specific statistics
        if log_type == 'dns' and 'query' in df.columns:
            stats.update({
                "unique_domains": df['query'].nunique(),
                "unique_sources": df['id.orig_h'].nunique() if 'id.orig_h' in df.columns else 0
            })
        elif log_type == 'conn' and 'id.orig_h' in df.columns:
            stats.update({
                "unique_sources": df['id.orig_h'].nunique(),
                "unique_destinations": df['id.resp_h'].nunique() if 'id.resp_h' in df.columns else 0
            })
        
        return stats

    def _get_all_logs_stats(self) -> Dict[str, Any]:
        """Get statistics for all loaded log types"""
        stats = {
            "total_log_types": len(self.active_log_types),
            "active_log_types": list(self.active_log_types),
            "log_stats": {}
        }
        
        for log_type in self.active_log_types:
            stats["log_stats"][log_type] = self._get_single_log_stats(log_type)
        
        total_records = sum(stats["log_stats"][lt]["total_records"] for lt in self.active_log_types)
        stats["total_records_all_logs"] = total_records
        
        return stats

    def query_across_logs(self, query_func: Callable, log_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Execute a query function across multiple log types
        
        Args:
            query_func: Function that takes a DataFrame and returns results
            log_types: List of log types to query (None for all active logs)
            
        Returns:
            Dictionary mapping log types to query results
        """
        if log_types is None:
            log_types = list(self.active_log_types)
        
        results = {}
        for log_type in log_types:
            if log_type in self.log_dataframes:
                try:
                    results[log_type] = query_func(self.log_dataframes[log_type])
                except Exception as e:
                    results[log_type] = f"Error: {e}"
        
        return results
