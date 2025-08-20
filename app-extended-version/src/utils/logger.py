# src/utils/logger.py
import logging
import logging.handlers
import json
from pathlib import Path
from typing import Dict, Any, Optional
import sys
from datetime import datetime

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging with enhanced fields"""
    
    def format(self, record):
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'process_id': record.process,
            'thread_id': record.thread
        }
        
        # Add extra data if present
        if hasattr(record, 'extra_data') and record.extra_data:
            log_data['extra_data'] = record.extra_data
            
        # Add exception information
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
            
        return json.dumps(log_data, ensure_ascii=False)

def setup_logging(config: Dict[str, Any]) -> logging.Logger:
    """
    Setup advanced logging configuration with multi-logger support
    
    Args:
        config: Logging configuration dictionary
        
    Returns:
        Configured root logger instance
    """
    log_config = config.get('logging', {})
    level = getattr(logging, log_config.get('level', 'INFO').upper())
    log_file = log_config.get('file', 'data/logs/c2_detector.log')
    max_size = log_config.get('max_size_mb', 100) * 1024 * 1024
    backup_count = log_config.get('backup_count', 5)
    console_output = log_config.get('console_output', True)
    json_format = log_config.get('json_format', False)
    
    # Create log directory
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        str(log_path), maxBytes=max_size, backupCount=backup_count, encoding='utf-8'
    )
    
    if json_format:
        file_handler.setFormatter(JSONFormatter())
    else:
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
    
    # Console handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
    
    root_logger.addHandler(file_handler)
    
    # Set specific loggers
    loggers = [
        'C2Detector', 'ZeekParser', 'DNSAnalyzer', 'HTTPAnalyzer', 
        'ConnAnalyzer', 'SSLAnalyzer', 'Helpers'
    ]
    
    for logger_name in loggers:
        logger = logging.getLogger(logger_name)
        logger.setLevel(level)
        logger.propagate = True  # Propagate to root logger
    
    # Capture warnings
    logging.captureWarnings(True)
    
    root_logger.info("Logging system initialized successfully")
    root_logger.info(f"Log level: {level}")
    root_logger.info(f"Log file: {log_path}")
    root_logger.info(f"JSON format: {json_format}")
    
    return root_logger

def get_logger(name: str) -> logging.Logger:
    """
    Get a named logger with consistent configuration
    
    Args:
        name: Logger name
        
    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)

def log_performance(start_time: datetime, operation: str, 
                   details: Optional[Dict] = None) -> None:
    """
    Log performance metrics for operations
    
    Args:
        start_time: Operation start time
        operation: Name of the operation
        details: Additional performance details
    """
    duration = (datetime.now() - start_time).total_seconds()
    logger = get_logger('Performance')
    
    log_data = {
        'operation': operation,
        'duration_seconds': round(duration, 4),
        'timestamp': datetime.now().isoformat()
    }
    
    if details:
        log_data.update(details)
    
    logger.info(f"Performance - {operation}", extra={'extra_data': log_data})

def setup_alert_logging(config: Dict[str, Any]) -> logging.Handler:
    """
    Setup separate logging for alerts
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Alert file handler
    """
    alert_config = config.get('alerting', {})
    alert_file = alert_config.get('log_file', 'data/alerts/c2_alerts.json')
    
    # Create alert directory
    alert_path = Path(alert_file)
    alert_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Alert file handler
    alert_handler = logging.handlers.RotatingFileHandler(
        str(alert_path), maxBytes=10 * 1024 * 1024, backupCount=10, encoding='utf-8'
    )
    alert_handler.setFormatter(JSONFormatter())
    alert_handler.setLevel(logging.WARNING)
    
    # Create alert logger
    alert_logger = logging.getLogger('Alerts')
    alert_logger.addHandler(alert_handler)
    alert_logger.propagate = False  # Don't propagate to root logger
    
    return alert_handler
