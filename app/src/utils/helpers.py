# src/utils/helpers.py
import json
from pathlib import Path
from typing import Dict, Any, List
import ipaddress
import statistics
from datetime import datetime, timedelta

def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from JSON file
    
    Args:
        config_path: Path to config file
        
    Returns:
        Configuration dictionary
    """
    config_path = Path(config_path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    with open(config_path, 'r') as f:
        return json.load(f)

def is_internal_ip(ip_address: str) -> bool:
    """
    Check if IP address is internal/private
    
    Args:
        ip_address: IP address to check
        
    Returns:
        True if internal, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private
    except ValueError:
        return False

def calculate_statistics(data: List[float]) -> Dict[str, float]:
    """
    Calculate statistical measures for data
    
    Args:
        data: List of numerical values
        
    Returns:
        Dictionary with statistical measures
    """
    if not data:
        return {}
    
    return {
        'mean': statistics.mean(data),
        'median': statistics.median(data),
        'stdev': statistics.stdev(data) if len(data) > 1 else 0,
        'min': min(data),
        'max': max(data),
        'count': len(data)
    }

def format_timestamp(timestamp: datetime) -> str:
    """
    Format timestamp for consistent output
    
    Args:
        timestamp: Datetime object
        
    Returns:
        Formatted timestamp string
    """
    return timestamp.isoformat()

def safe_divide(numerator: float, denominator: float) -> float:
    """
    Safe division with zero handling
    
    Args:
        numerator: Numerator value
        denominator: Denominator value
        
    Returns:
        Division result or 0.0 if denominator is 0
    """
    return numerator / denominator if denominator != 0 else 0.0
