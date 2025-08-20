# 06. Utils Modulu - logger module

## 📋 Logger Modulunun Təyinatı

Logger modulu C2 aşkarlama sistemi üçün professional loqlaşdırma funksionallığı təmin edir. Bu modul həm konsola, həm də fayla strukturlaşdırılmış loq yazmağı, həmçinin loq fayllarının rotationunu avtomatik idarə etməyi təmin edir.

## 🏗️ Modul Strukturu

```python
# src/utils/logger.py
import logging
import logging.handlers
import json
from pathlib import Path
from typing import Dict, Any
import sys

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record):
        # JSON formatında loq yaratmaq
        pass

def setup_logging(config: Dict[str, Any]) -> logging.Logger:
    """
    Setup advanced logging configuration
    
    Args:
        config: Logging configuration dictionary
        
    Returns:
        Configured logger instance
    """
```

## 🔧 Əsas Komponentlər

### 1. JSONFormatter Sinifi

```python
class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record):
        log_data = {
            'timestamp': self.formatTime(record),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        if hasattr(record, 'extra_data'):
            log_data.update(record.extra_data)
            
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
            
        return json.dumps(log_data)
```

**Xüsusiyyətlər:**
- JSON formatında strukturlaşdırılmış loq
- Avtomatik timestamp
- Exception məlumatları
- Əlavə metadata dəstəyi

### 2. setup_logging Funksiyası

```python
def setup_logging(config: Dict[str, Any]) -> logging.Logger:
    """
    Setup advanced logging configuration
    
    Args:
        config: Logging configuration dictionary
        
    Returns:
        Configured logger instance
    """
    log_config = config.get('logging', {})
    level = getattr(logging, log_config.get('level', 'INFO'))
    log_file = log_config.get('file', 'c2_detector.log')
    max_size = log_config.get('max_size_mb', 100) * 1024 * 1024
    backup_count = log_config.get('backup_count', 5)
```

**Konfiqurasiya Parametrləri:**
- `level`: Loq səviyyəsi (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `file`: Loq faylının yolu
- `max_size_mb`: Maksimum fayl ölçüsü (MB)
- `backup_count`: Saxlanılacaq backup fayl sayı

## 🔧 Qurulum Prosesi

### 1. Loq Qovluğunun Yaradılması

```python
# Create log directory
log_path = Path(log_file)
log_path.parent.mkdir(parents=True, exist_ok=True)
```

**Funksiya:** Loq faylının qovluğunu yaradır

### 2. Logger-in Yaradılması

```python
# Create logger
logger = logging.getLogger('C2Detector')
logger.setLevel(level)
```

**Funksiya:** Əsas logger instance-ni yaradır

### 3. Əvvəlki Handler-larin Təmizlənməsi

```python
# Clear existing handlers
logger.handlers.clear()
```

**Funksiya:** Əlavə edilmiş bütün handler-ləri təmizləyir

### 4. Fayl Handler-inin Qurulması

```python
# File handler with rotation
file_handler = logging.handlers.RotatingFileHandler(
    log_file, maxBytes=max_size, backupCount=backup_count
)
file_handler.setFormatter(JSONFormatter())
```

**Xüsusiyyətlər:**
- Avtomatik fayl rotationu
- JSON formatında loq
- Fayl ölçüsü məhdudiyyəti

### 5. Konsol Handler-inin Qurulması

```python
# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
))
```

**Xüsusiyyətlər:**
- Stdout-a çıxış
- Oxuna bilən format
- Rəngli çıxış (terminal dəstəkləyirsə)

### 6. Handler-lərin Əlavə Edilməsi

```python
# Add handlers
logger.addHandler(file_handler)
logger.addHandler(console_handler)
```

**Funksiya:** Handler-ləri logger-ə əlavə edir

## 🎯 İstifadə Nümunələri

### Əsas Qurulum

```python
from src.utils.logger import setup_logging

# Konfiqurasiya
config = {
    "logging": {
        "level": "INFO",
        "file": "logs/c2_detector.log",
        "max_size_mb": 100,
        "backup_count": 5
    }
}

# Logger-i qur
logger = setup_logging(config)

# İstifadə
logger.info("Sistem işə salındı")
logger.warning("Şübhəli fəaliyyət aşkar edildi")
```

### Ətraflı Loqlaşdırma

```python
# Strukturlaşdırılmış loq
logger.info(
    "DNS sorğusu emal edildi",
    extra={
        'extra_data': {
            'source_ip': '192.168.1.105',
            'query': 'example.com',
            'query_type': 'A',
            'response_code': 'NOERROR'
        }
    }
)

# Xəta loqu
try:
    # Kod burada
    pass
except Exception as e:
    logger.error(
        "DNS emalı zamanı xəta",
        exc_info=True,
        extra={
            'extra_data': {
                'operation': 'dns_processing',
                'error_type': type(e).__name__
            }
        }
    )
```

### Performans Loqlaşdırma

```python
import time
from functools import wraps

def log_execution_time(logger):
    """Funksiya icra müddətini loqlaşdırma dekoratoru"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            
            logger.debug(
                f"{func.__name__} icra müddəti",
                extra={
                    'extra_data': {
                        'function': func.__name__,
                        'execution_time_seconds': execution_time,
                        'module': func.__module__
                    }
                }
            )
            return result
        return wrapper
    return decorator

# İstifadə
@log_execution_time(logger)
def process_dns_data(data):
    # DNS məlumatlarının emalı
    pass
```

## 🔧 Tənzimlənə Bilən Parametrlər

### Loq Konfiqurasiyası

```json
{
  "logging": {
    "level": "DEBUG",
    "file": "data/logs/c2_detector.log",
    "max_size_mb": 100,
    "backup_count": 10,
    "console_output": true,
    "file_output": true,
    "json_format": true
  }
}
```

### Dinamik Loq Səviyyəsi

```python
def dynamic_log_level(logger, system_load):
    """Sistem yükünə görə loq səviyyəsini tənzimlə"""
    if system_load > 80:  # Yüksək yük
        logger.setLevel(logging.WARNING)  # Yalnız xəbərdarlıq və xətalar
    else:
        logger.setLevel(logging.DEBUG)    # Ətraflı loq
```

## 📊 Loq Nümunələri

### JSON Loq Formatı

```json
{
  "timestamp": "2024-01-15 14:30:22,123",
  "level": "WARNING",
  "logger": "C2Detector",
  "message": "Yüksək DNS həcmi aşkar edildi",
  "module": "detector",
  "function": "raise_alert",
  "line": 42,
  "extra_data": {
    "source_ip": "192.168.1.105",
    "query_count": 250,
    "threshold": 100
  }
}
```

### Konsol Çıxışı

```
2024-01-15 14:30:22,123 - C2Detector - WARNING - Yüksək DNS həcmi aşkar edildi
```

## 💡 Əlavə Qeydlər

### 1. Audit Loqlaşdırma

```python
def audit_log(logger, event_type, user, resource, status):
    """Audit loqu yaratmaq"""
    logger.info(
        "Audit event",
        extra={
            'extra_data': {
                'event_type': event_type,
                'user': user,
                'resource': resource,
                'status': status,
                'timestamp': datetime.now().isoformat()
            }
        }
    )
```

### 2. Distributed Loqlaşdırma

```python
def setup_distributed_logging(config, service_name):
    """Paylanmış sistemlər üçün loqlaşdırma"""
    logger = setup_logging(config)
    
    # Xidmət adını əlavə et
    old_factory = logging.getLogRecordFactory()
    
    def record_factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        record.service = service_name
        return record
    
    logging.setLogRecordFactory(record_factory)
    
    return logger
```

### 3. Loq Analizi

```python
def analyze_logs(log_file, pattern):
    """Loq fayllarının avtomatik təhlili"""
    import re
    
    with open(log_file, 'r') as f:
        logs = f.readlines()
    
    # Pattern axtarışı
    matches = []
    for log in logs:
        if re.search(pattern, log):
            matches.append(log)
    
    return matches
```

---

**Növbəti:** [07. Utils Modulu - helpers module](/doc/utils/07_helpers_module.md)

Bu sənəd logger modulunun detallı işləmə prinsipini izah edir. Növbəti sənəddə helpers moduluna keçəcəyik.
