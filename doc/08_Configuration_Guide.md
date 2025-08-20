# 08. Configuration Guide

## 📋 Konfiqurasiya Faylının Strukturu

C2 Detector sistemi JSON formatlı konfiqurasiya faylı ilə işləyir. Bu bələdçi bütün konfiqurasiya parametrlərini və onların istifadəsini izah edir.

## 🏗️ Əsas Konfiqurasiya Strukturu

```json
{
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
    "dns_queries_per_minute": 150,
    "unusual_domain_length": 60,
    "entropy_threshold": 4.2,
    "beacon_interval_std": 2.0,
    "unusual_type_count": 10
  },
  "alerting": {
    "log_file": "data/alerts/c2_alerts.json",
    "max_alerts_per_hour": 1000,
    "severity_levels": {
      "HIGH": 90,
      "MEDIUM": 70,
      "LOW": 50
    }
  },
  "logging": {
    "level": "INFO",
    "file": "data/logs/c2_detector.log",
    "max_size_mb": 100,
    "backup_count": 5
  }
}
```

## 🔧 Zeek Konfiqurasiyası

### `zeek.log_dir`
**Təyinat:** Zeek log fayllarının yeri  
**Default:** `/opt/zeek/logs/current`  
**Nümunə:** `"/var/log/zeek"`

### `zeek.log_types`  
**Təyinat:** İzləniləcək log növləri  
**Default:** `["dns"]`  
**Seçimlər:** `["dns", "http", "ssl", "conn"]`

### `zeek.monitor_interfaces`
**Təyinat:** Monitor ediləcək şəbəkə interfeysləri  
**Default:** `["eth0"]`  
**Nümunə:** `["eth0", "eth1", "wlan0"]`

## 📊 Analiz Konfiqurasiyası

### `analysis.window_minutes`
**Təyinat:** Real-time analiz pəncərəsi (dəqiqə)  
**Default:** `60`  
**Tövsiyə:** `5-120` (performansa görə)

### `analysis.real_time_interval`
**Təyinat:** Dövri analiz intervalları (saniyə)  
**Default:** `30`  
**Tövsiyə:** `30-300`

### `analysis.historical_days`
**Təyinat:** Tarixi məlumatların neçə günlük oxunacağı  
**Default:** `7`  
**Tövsiyə:** `1-30`

## ⚠️ Aşkarlama Həddləri

### `thresholds.dns_queries_per_minute`
**Təyinat:** Həddən artıq DNS sorğu sayı  
**Default:** `150`  
**Tövsiyə:** `100-500` (şəbəkə ölçüsündən asılı)

### `thresholds.unusual_domain_length`
**Təyinat:** Qeyri-adi uzunluqda domain həddi  
**Default:** `60`  
**Tövsiyə:** `50-100`

### `thresholds.entropy_threshold`
**Təyinat:** Şübhəli domainlər üçün entropiya həddi  
**Default:** `4.2`  
**Tövsiyə:** `3.8-4.5`

### `thresholds.beacon_interval_std`
**Təyinat:** Beaconing üçün standart sapma həddi  
**Default:** `2.0`  
**Tövsiyə:** `1.5-3.0`

### `thresholds.unusual_type_count`
**Təyinat:** Qeyri-adi DNS növləri sayı  
**Default:** `10`  
**Tövsiyə:** `5-20`

## 🚨 Xəbərdarlıq Konfiqurasiyası

### `alerting.log_file`
**Təyinat:** Xəbərdarlıq log faylının yeri  
**Default:** `"data/alerts/c2_alerts.json"`

### `alerting.max_alerts_per_hour`
**Təyinat:** Saatda maksimum xəbərdarlıq sayı  
**Default:** `1000`  
**Tövsiyə:** `500-5000`

### `alerting.severity_levels`
**Təyinat:** Risk səviyyəsi həddləri  
**Default:** `{"HIGH": 90, "MEDIUM": 70, "LOW": 50}`

## 📝 Log Konfiqurasiyası

### `logging.level`
**Təyinat:** Loq səviyyəsi  
**Default:** `"INFO"`  
**Seçimlər:** `"DEBUG"`, `"INFO"`, `"WARNING"`, `"ERROR"`

### `logging.file`
**Təyinat:** Loq faylının yeri  
**Default:** `"data/logs/c2_detector.log"`

### `logging.max_size_mb`
**Təyinat:** Maksimum loq faylı ölçüsü (MB)  
**Default:** `100`  
**Tövsiyə:** `50-500`

### `logging.backup_count`
**Təyinat:** Saxlanılacaq backup fayl sayı  
**Default:** `5`  
**Tövsiyə:** `3-10`

## 🎯 Konfiqurasiya Nümunələri

### Kiçik Şəbəkə Üçün
```json
{
  "thresholds": {
    "dns_queries_per_minute": 100,
    "unusual_domain_length": 50,
    "entropy_threshold": 4.0
  },
  "analysis": {
    "window_minutes": 30,
    "historical_days": 3
  }
}
```

### Böyük Şəbəkə Üçün
```json
{
  "thresholds": {
    "dns_queries_per_minute": 300,
    "unusual_domain_length": 70,
    "entropy_threshold": 4.5
  },
  "analysis": {
    "window_minutes": 120,
    "historical_days": 14
  },
  "alerting": {
    "max_alerts_per_hour": 5000
  }
}
```

### Yüksək Təhlükəsizlik Üçün
```json
{
  "thresholds": {
    "dns_queries_per_minute": 50,
    "unusual_domain_length": 40,
    "entropy_threshold": 3.8,
    "beacon_interval_std": 1.5
  },
  "logging": {
    "level": "DEBUG"
  }
}
```

## 🔧 Dinamik Konfiqurasiya

### Proqramlaşdırma Üsulu
```python
from src.utils.helpers import load_config

# Konfiqurasiyanı yüklə
config = load_config("config.json")

# Dinamik olaraq dəyiş
config['thresholds']['dns_queries_per_minute'] = 200
config['analysis']['window_minutes'] = 45

# Yeni parametrlər əlavə et
config['new_feature'] = {
    "enabled": true,
    "sensitivity": 0.8
}
```

### Command Line Üsulu
```bash
# JSONPath ilə dəyişiklik
python -c "
import json
with open('config.json', 'r') as f:
    config = json.load(f)
config['thresholds']['dns_queries_per_minute'] = 200
with open('config.json', 'w') as f:
    json.dump(config, f, indent=2)
"
```

## ⚠️ Ümumi Xətalar və Həlləri

### Fayl Tapılmır
**Xəta:** `Config file not found: custom_config.json`  
**Həll:** Default konfiqurasiya avtomatik yüklənir

### JSON Format Xətası
**Xəta:** `JSONDecodeError`  
**Həll:** Konfiqurasiya faylının formatını yoxlayın

### Validation Xətaları
**Xəta:** `KeyError` - Çatışmayan parametr  
**Həll:** Default dəyərlər avtomatik təyin edilir

## 💡 Əlavə Tövsiyələr

### Performans Optimizasiyası
```json
{
  "analysis": {
    "window_minutes": 30,
    "real_time_interval": 60
  },
  "logging": {
    "level": "INFO",
    "max_size_mb": 50
  }
}
```

### Təhlükəsizlik Üçün
```json
{
  "thresholds": {
    "entropy_threshold": 4.0,
    "beacon_interval_std": 1.8
  },
  "alerting": {
    "max_alerts_per_hour": 2000
  }
}
```

### Development Üçün
```json
{
  "logging": {
    "level": "DEBUG",
    "max_size_mb": 10
  },
  "analysis": {
    "historical_days": 1
  }
}
```

---

**Növbəti:** [09. Installation Guide](/doc/09_Installation_Guide.md)

Bu sənəd bütün konfiqurasiya parametrlərini və onların istifadə qaydalarını izah edir. Növbəti sənəddə quraşdırma bələdçisinə keçəcəyik.
