# 07. Utils Modulu - helpers module

## 📋 Helpers Modulunun Təyinatı

Helpers modulu C2 aşkarlama sistemi üçün köməkçi funksiyalar və utiliti siniflər təmin edir. Bu modul konfiqurasiya idarəetməsi, IP ünvanı analizi, statistik hesablamalar və digər köməkçi funksiyaları ehtiva edir.

## 🏗️ Modul Strukturu

```python
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
    pass

def is_internal_ip(ip_address: str) -> bool:
    """
    Check if IP address is internal/private
    
    Args:
        ip_address: IP address to check
        
    Returns:
        True if internal, False otherwise
    """
    pass

def calculate_statistics(data: List[float]) -> Dict[str, float]:
    """
    Calculate statistical measures for data
    
    Args:
        data: List of numerical values
        
    Returns:
        Dictionary with statistical measures
    """
    pass

def format_timestamp(timestamp: datetime) -> str:
    """
    Format timestamp for consistent output
    
    Args:
        timestamp: Datetime object
        
    Returns:
        Formatted timestamp string
    """
    pass

def safe_divide(numerator: float, denominator: float) -> float:
    """
    Safe division with zero handling
    
    Args:
        numerator: Numerator value
        denominator: Denominator value
        
    Returns:
        Division result or 0.0 if denominator is 0
    """
    pass
```

## 🔧 Əsas Funksiyalar

### 1. `load_config` Funksiyası

```python
def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from JSON file
    
    Args:
        config_path: Path to config file
        
    Returns:
        Configuration dictionary
    """
    default_config = {
        "zeek": {
            "log_dir": "/opt/zeek/logs/current",
            "log_types": ["dns"],
            "monitor_interfaces": ["eth0"]
        },
        "analysis": {
            "window_minutes": 60,
            "real_time_interval": 30,
            "historical_days": 7
        },
        "thresholds": {
            "dns_queries_per_minute": 100,
            "unusual_domain_length": 50,
            "entropy_threshold": 4.0
        }
    }
    
    config_path = Path(config_path)
    if not config_path.exists():
        return default_config
    
    try:
        with open(config_path, 'r') as f:
            user_config = json.load(f)
        
        # Deep merge with default config
        def deep_update(default, user):
            for key, value in user.items():
                if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                    deep_update(default[key], value)
                else:
                    default[key] = value
            return default
        
        return deep_update(default_config, user_config)
            
    except Exception as e:
        print(f"Config load error: {e}")
        return default_config
```

**Xüsusiyyətlər:**
- Default konfiqurasiya ilə işləyir
- Deep merge funksionallığı
- Avtomatik xəta idarəetmə

### 2. `is_internal_ip` Funksiyası

```python
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
```

**Dəstəklənən Private Ünvanlar:**
- `10.0.0.0/8`
- `172.16.0.0/12` 
- `192.168.0.0/16`
- `127.0.0.0/8` (loopback)
- `::1/128` (IPv6 loopback)

### 3. `calculate_statistics` Funksiyası

```python
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
    
    try:
        return {
            'mean': statistics.mean(data),
            'median': statistics.median(data),
            'stdev': statistics.stdev(data) if len(data) > 1 else 0.0,
            'min': min(data),
            'max': max(data),
            'count': len(data)
        }
    except statistics.StatisticsError:
        return {}
```

**Hesablanan Statistikalar:**
- Orta dəyər (mean)
- Median dəyər
- Standart sapma
- Minimum dəyər
- Maksimum dəyər
- Element sayı

### 4. `format_timestamp` Funksiyası

```python
def format_timestamp(timestamp: datetime) -> str:
    """
    Format timestamp for consistent output
    
    Args:
        timestamp: Datetime object
        
    Returns:
        Formatted timestamp string
    """
    return timestamp.isoformat(sep=' ', timespec='milliseconds')
```

**Çıxış Formatı:** `2024-01-15 14:30:22.123`

### 5. `safe_divide` Funksiyası

```python
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
```

**Tətbiq:** Sıfıra bölmə xətalarının qarşısını alır

## 🎯 İstifadə Nümunələri

### Əsas İstifadə

```python
from src.utils.helpers import load_config, is_internal_ip, calculate_statistics

# Konfiqurasiyanı yüklə
config = load_config("config.json")
print(f"Log directory: {config['zeek']['log_dir']}")

# IP yoxlaması
ip = "192.168.1.105"
print(f"{ip} is internal: {is_internal_ip(ip)}")

# Statistik hesablama
data = [10.5, 20.3, 15.7, 30.1]
stats = calculate_statistics(data)
print(f"Mean: {stats['mean']:.2f}, Stdev: {stats['stdev']:.2f}")
```

### Konfiqurasiya İdarəetməsi

```python
def get_detection_thresholds(config_path):
    """Aşkarlama həddlərini almaq"""
    config = load_config(config_path)
    thresholds = config.get('thresholds', {})
    
    return {
        'dns_volume': thresholds.get('dns_queries_per_minute', 100),
        'domain_length': thresholds.get('unusual_domain_length', 50),
        'entropy': thresholds.get('entropy_threshold', 4.0)
    }

# İstifadə
thresholds = get_detection_thresholds("config.json")
print(f"DNS volume threshold: {thresholds['dns_volume']}")
```

### Şəbəkə Analizi

```python
def analyze_network_traffic(ip_list):
    """Şəbəkə trafikinin təhlili"""
    internal_ips = []
    external_ips = []
    
    for ip in ip_list:
        if is_internal_ip(ip):
            internal_ips.append(ip)
        else:
            external_ips.append(ip)
    
    return {
        'internal_count': len(internal_ips),
        'external_count': len(external_ips),
        'internal_ratio': safe_divide(len(internal_ips), len(ip_list)),
        'unique_ips': len(set(ip_list))
    }

# İstifadə
ip_list = ["192.168.1.105", "8.8.8.8", "192.168.1.106", "1.1.1.1"]
analysis = analyze_network_traffic(ip_list)
print(f"Daxili IP nisbəti: {analysis['internal_ratio']:.1%}")
```

## 🔧 Tənzimlənə Bilən Parametrlər

### Konfiqurasiya Strukturu

```json
{
  "zeek": {
    "log_dir": "/opt/zeek/logs/current",
    "log_types": ["dns", "http", "ssl"],
    "monitor_interfaces": ["eth0", "eth1"]
  },
  "analysis": {
    "window_minutes": 30,
    "real_time_interval": 15,
    "historical_days": 3
  },
  "thresholds": {
    "dns_queries_per_minute": 200,
    "unusual_domain_length": 75,
    "entropy_threshold": 4.5,
    "beacon_interval_std": 1.5
  }
}
```

### Dinamik Konfiqurasiya

```python
def update_config_dynamically(config_path, new_settings):
    """Konfiqurasiyanı dinamik olaraq yenilə"""
    config = load_config(config_path)
    
    # Deep update
    def deep_update(target, source):
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                deep_update(target[key], value)
            else:
                target[key] = value
    
    deep_update(config, new_settings)
    
    # Yenidən yadda saxla
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    return config

# Dinamik yeniləmə
new_settings = {
    "thresholds": {
        "dns_queries_per_minute": 150,
        "entropy_threshold": 4.2
    }
}
updated_config = update_config_dynamically("config.json", new_settings)
```

## 💡 Əlavə Qeydlər

### 1. Validation Funksiyaları

```python
def validate_config(config):
    """Konfiqurasiyanın etibarlılığını yoxla"""
    errors = []
    
    # Zəbur məcburi parametrlər
    required_fields = [
        'zeek.log_dir',
        'analysis.window_minutes', 
        'thresholds.dns_queries_per_minute'
    ]
    
    for field in required_fields:
        parts = field.split('.')
        current = config
        for part in parts:
            if part not in current:
                errors.append(f"Missing required field: {field}")
                break
            current = current[part]
    
    # Dəyər validation
    if config['thresholds']['dns_queries_per_minute'] <= 0:
        errors.append("DNS queries threshold must be positive")
    
    return errors
```

### 2. Performans Utilitesi

```python
def timing_decorator(func):
    """Funksiya icra müddətini ölçən dekorator"""
    from functools import wraps
    import time
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        
        print(f"{func.__name__} executed in {end_time - start_time:.4f} seconds")
        return result
    
    return wrapper

# İstifadə
@timing_decorator
def process_large_dataset(data):
    # Böyük məlumat dəstinin emalı
    pass
```

### 3. Cache Utilitesi

```python
def cached_function(func):
    """Nəticələri cache-ləyən dekorator"""
    from functools import wraps
    cache = {}
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        cache_key = str(args) + str(kwargs)
        
        if cache_key not in cache:
            cache[cache_key] = func(*args, **kwargs)
        
        return cache[cache_key]
    
    return wrapper

# İstifadə
@cached_function
def calculate_entropy(domain):
    # CPU intensiv hesablama
    pass
```

---

**Növbəti:** [08. Configuration Guide](/doc/08_Configuration_Guide.md)

Bu sənəd helpers modulunun detallı işləmə prinsipini izah edir. Növbəti sənəddə konfiqurasiya bələdçisinə keçəcəyik.
