# 05. Detector Modulu - C2Detector Class

## 📋 `C2Detector` Sinfinin Təyinatı

`C2Detector` sinfi bütün C2 aşkarlama sisteminin əsas koordinatorudur. Bu sinif log parser, DNS analizator və digər komponentləri birləşdirərək tam işləyən bir monitoring sistemi təmin edir.

## 🏗️ Sinif Strukturu

```python
class C2Detector:
    """
    Professional C2 detection system that coordinates all components.
    Enhanced with better error handling, performance monitoring, and reporting.
    """
```

## 🔧 Konstruktor Metodu

### `__init__(self, config_path: str = "config.json")`

**Vəzifəsi:** C2 detektorunun ilkin konfiqurasiyasını və bütün komponentləri hazırlamaq

**Parametrlər:**
- `config_path` (str): Konfiqurasiya faylının yolu (default: "config.json")

**Daxili İşləmə:**

#### 1. Konfiqurasiyanın Yüklənməsi
```python
self.config_path = config_path
self.config = load_config(config_path)
```

**Funksiya:** JSON konfiqurasiya faylını yükləyir

#### 2. Signal Handler Qurulması
```python
self.running = True
signal.signal(signal.SIGINT, self._signal_handler)
signal.signal(signal.SIGTERM, self._signal_handler)
```

**Funksiya:** Graceful shutdown üçün signal handler qurur

#### 3. Komponentlərin İnitializasiyası
```python
self.zeek_parser = ZeekLogParser(config_path)
self.dns_analyzer = DNSAnalyzer(self.config)
```

**Funksiya:** Zeek parser və DNS analizatorunu yaradır

#### 4. Monitoring Dəyişənləri
```python
self.alerts: List[Dict] = []
self.alert_count = 0
self.start_time = datetime.now()
```

**Data Strukturları:**
- `alerts`: Aşkarlanan bütün xəbərdarlıqlar
- `alert_count`: Ümumi xəbərdarlıq sayı
- `start_time`: Sistemin başlama vaxtı

## 🎯 Əsas Metodlar

### 1. `setup_environment(self) -> bool`
**Vəzifə:** Monitoring mühitini qurur və tarixi məlumatları yükləyir

### 2. `real_time_dns_callback(self, dns_entry: Dict)`
**Vəzifə:** Real-time DNS girişlərini emal edir

### 3. `raise_alert(self, alert: Dict)`
**Vəzifə:** Yeni xəbərdarlıq yaradır və idarə edir

### 4. `periodic_analysis(self)`
**Vəzifə:** Dövri tam analiz həyata keçirir

### 5. `run_realtime_monitoring(self)`
**Vəzifə:** Real-time monitoringu işə salır

### 6. `generate_final_report(self)`
**Vəzifə:** Son hesabat yaradır

## ⚠️ Signal Əlaqələndirmə

### `_signal_handler(self, signum, frame)`
```python
def _signal_handler(self, signum, frame):
    """Handle shutdown signals gracefully"""
    logger.info(f"Received signal {signum}, shutting down...")
    self.running = False
    self.generate_final_report()
    sys.exit(0)
```

**Idarə Olunan Signallar:**
- `SIGINT` (Ctrl+C) - İstifadəçi tərəfindən dayandırma
- `SIGTERM` - Sistem tərəfindən dayandırma

## 📊 İlkin Vəziyyət

Konstruktor işini bitirdikdən sonra:

```python
detector = C2Detector("config.json")

print(detector.config_path)    # "config.json"
print(len(detector.alerts))    # 0
print(detector.alert_count)    # 0
print(detector.running)        # True
```

## 🚀 İstifadə Nümunələri

### Əsas İstifadə
```python
# Default konfiqurasiya ilə
detector = C2Detector()

# Xüsusi konfiqurasiya ilə
detector = C2Detector("production_config.json")

# Test rejimində
detector = C2Detector("test_config.json")
```

### Ətraflı Konfiqurasiya
```python
def initialize_detector_with_retry(config_path, max_retries=3):
    """Yenidən cəhd ilə detektor işə salma"""
    for attempt in range(max_retries):
        try:
            detector = C2Detector(config_path)
            if detector.setup_environment():
                return detector
        except Exception as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            time.sleep(2)
    
    raise Exception("Failed to initialize detector after retries")

# İşə salma
detector = initialize_detector_with_retry("config.json")
```

## 🔧 Tənzimlənə Bilən Parametrlər

### Konfiqurasiya Strukturu
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
  }
}
```

### Dinamik Konfiqurasiya
```python
def update_detector_config(detector, new_config):
    """İş zamanı konfiqurasiyanı yenilə"""
    detector.config.update(new_config)
    detector.dns_analyzer = DNSAnalyzer(detector.config)  # Yenidən yüklə
```

## 💡 Əlavə Qeydlər

### 1. Thread Safety
```python
# Sinif thread-safe dizayn edilib
# Signal handler ilə təhlükəsiz dayandırma
```

### 2. Resource Management
```python
# Avtomatik resource idarəetmə
# Fayl descriptorları avtomatik bağlanır
```

### 3. Error Recovery
```python
# Avtomatik bərpa mexanizmləri
# Xəta halında graceful degradation
```

### 4. Performance Monitoring
```python
# Daxili performans metrikaları
# Real-time monitorinq imkanı
```

---

**Növbəti:** [05. Detector Modulu - environment setup](/doc/core/05_detector/02_environment_setup.md)

Bu sənəd `C2Detector` sinfinin konstruktor metodunun detallı işləmə prinsipini izah edir. Növbəti sənəddə mühit qurulumu metoduna keçəcəyik.
