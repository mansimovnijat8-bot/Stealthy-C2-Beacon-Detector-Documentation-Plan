# src/utils/helpers.py
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import ipaddress
import statistics
from datetime import datetime, timedelta
import logging

logger = logging.getLogger('Helpers')

def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from JSON file with enhanced error handling
    
    Args:
        config_path: Path to config file
        
    Returns:
        Configuration dictionary
        
    Raises:
        FileNotFoundError: If config file not found
        JSONDecodeError: If config file is invalid JSON
    """
    config_path = Path(config_path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        logger.info(f"Configuration loaded successfully from {config_path}")
        return config
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in config file: {e}")
        raise
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        raise

def is_internal_ip(ip_address: str) -> bool:
    """
    Check if IP address is internal/private with enhanced validation
    
    Args:
        ip_address: IP address to check
        
    Returns:
        True if internal, False otherwise
    """
    if not ip_address or not isinstance(ip_address, str):
        return False
    
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private
    except ValueError:
        return False

def calculate_statistics(data: List[float]) -> Dict[str, float]:
    """
    Calculate statistical measures for data with robust error handling
    
    Args:
        data: List of numerical values
        
    Returns:
        Dictionary with statistical measures
    """
    if not data or not isinstance(data, list):
        return {}
    
    try:
        # Filter out non-numeric values
        numeric_data = [x for x in data if isinstance(x, (int, float))]
        
        if not numeric_data:
            return {}
        
        stats = {
            'mean': statistics.mean(numeric_data),
            'median': statistics.median(numeric_data),
            'min': min(numeric_data),
            'max': max(numeric_data),
            'count': len(numeric_data),
            'sum': sum(numeric_data)
        }
        
        # Standard deviation requires at least 2 values
        if len(numeric_data) > 1:
            stats['stdev'] = statistics.stdev(numeric_data)
        else:
            stats['stdev'] = 0.0
            
        return stats
        
    except (statistics.StatisticsError, ValueError) as e:
        logger.warning(f"Statistics calculation failed: {e}")
        return {}

def format_timestamp(timestamp: datetime) -> str:
    """
    Format timestamp for consistent output with timezone support
    
    Args:
        timestamp: Datetime object
        
    Returns:
        Formatted timestamp string
    """
    try:
        if timestamp.tzinfo is None:
            return timestamp.isoformat() + 'Z'  # UTC by default
        else:
            return timestamp.isoformat()
    except (AttributeError, TypeError):
        logger.warning("Invalid timestamp provided")
        return ""

def safe_divide(numerator: float, denominator: float) -> float:
    """
    Safe division with zero handling and type validation
    
    Args:
        numerator: Numerator value
        denominator: Denominator value
        
    Returns:
        Division result or 0.0 if denominator is 0
    """
    try:
        numerator = float(numerator)
        denominator = float(denominator)
        
        if denominator == 0:
            return 0.0
        return numerator / denominator
    except (ValueError, TypeError):
        return 0.0

def validate_ip_address(ip_address: str) -> bool:
    """
    Validate if string is a valid IP address
    
    Args:
        ip_address: IP address string to validate
        
    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def get_time_window(minutes: int) -> Dict[str, datetime]:
    """
    Get start and end times for a time window
    
    Args:
        minutes: Number of minutes for the window
        
    Returns:
        Dictionary with start_time and end_time
    """
    end_time = datetime.now()
    start_time = end_time - timedelta(minutes=minutes)
    
    return {
        'start_time': start_time,
        'end_time': end_time
    }

def normalize_string(input_string: str, max_length: int = 100) -> str:
    """
    Normalize string for safe logging and processing
    
    Args:
        input_string: String to normalize
        max_length: Maximum length to truncate to
        
    Returns:
        Normalized string
    """
    if not isinstance(input_string, str):
        return ""
    
    # Remove extra whitespace
    normalized = ' '.join(input_string.strip().split())
    
    # Truncate if too long
    if len(normalized) > max_length:
        normalized = normalized[:max_length] + '...'
    
    return normalized

def merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """
    Merge two dictionaries with conflict resolution
    
    Args:
        dict1: First dictionary
        dict2: Second dictionary
        
    Returns:
        Merged dictionary
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    
    return result

def format_bytes(size_bytes: int) -> str:
    """
    Convert bytes to human readable format
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Human readable string
    """
    if size_bytes == 0:
        return "0B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size = float(size_bytes)
    
    while size >= 1024 and i < len(size_names) - 1:
        size /= 1024
        i += 1
        
    return f"{size:.2f}{size_names[i]}"
