# 05. Detector Modulu - environment setup

## 📋 `setup_environment` Metodunun Təyinatı

`setup_environment` metodu C2 aşkarlama sisteminin işləməsi üçün lazım olan mühiti qurur, tarixi məlumatları yükləyir və baseline analizini həyata keçirir.

## 🏗️ Metod İmzası

```python
def setup_environment(self) -> bool:
```

**Parametrlər:** Heç bir parametr qəbul etmir

**Qaytarır:** `bool` - Qurulumun uğurlu olub-olmadığını göstərir

## 🔧 Metodun Daxili İşləməsi

### 1. Mühit Qurulumunun Başladılması

```python
logger.info("Setting up professional monitoring environment...")
```

**Funksiya:** Qurulum prosesinin başladığını loglayır

### 2. Analiz Konfiqurasiyasının Alınması

```python
analysis_config = self.config.get('analysis', {})
historical_days = analysis_config.get('historical_days', 1)
```

**Konfiqurasiya Parametrləri:**
- `analysis_window_minutes`: Real-time analiz pəncərəsi (default: 60)
- `real_time_interval`: Dövri analiz intervalı (default: 30)
- `historical_days`: Tarixi məlumatların neçə günlük oxunacağı (default: 1)

### 3. Tarixi Məlumatların Oxunması

```python
if not self.zeek_parser.read_historical(days=historical_days):
    logger.error("Failed to read historical DNS data")
    return False
```

**Funksiya:** Zeek loglarından tarixi DNS məlumatlarını oxuyur

**Parametr:** `days` - Neçə günlük məlumat oxunacağı

### 4. Boş Məlumat Yoxlaması

```python
if self.zeek_parser.df.empty:
    logger.warning("No historical DNS data found")
    return True
```

**Funksiya:** Əgər heç bir məlumat tapılmasa, xəbərdarlıq verir lakin True qaytarır

### 5. Baseline Analizinın Həyata Keçirilməsi

```python
self.dns_analyzer.process_dns_data(self.zeek_parser)
```

**Funksiya:** DNS məlumatlarını emal edərək baseline statistikaları hesablayır

### 6. Statistik Məlumatların Loglanması

```python
stats = self.zeek_parser.get_stats()
logger.info(f"Baseline established: {stats['total_records']} records, "
           f"{stats['unique_sources']} unique sources")
```

**Loglanan Statistikalar:**
- Ümumi qeyd sayı
- Unikal mənbə sayı
- Məlumatların vaxt aralığı

### 7. Uğur Mesajı

```python
return True
```

**Funksiya:** Qurulumun uğurla başa çatdığını göstərir

## ⚠️ Xəta Əlaqələndirmə

Metod aşağıdakı xətaları idarə edir:

1. **Konfiqurasiya xətaları** - Default dəyərlər istifadə edir
2. **Fayl oxuma xətaları** - Xəta loglanır və False qaytarılır
3. **Boş məlumat** - Xəbərdarlıq verilir lakin True qaytarılır
4. **Data emal xətaları** - Xəta loglanır və False qaytarılır

## 🎯 İstifadə Nümunələri

### Əsas İstifadə
```python
detector = C2Detector("config.json")

if detector.setup_environment():
    print("Mühit uğurla quruldu")
    print(f"Yüklənən qeydlər: {len(detector.zeek_parser.df)}")
else:
    print("Mühit qurulumu uğursuz oldu")
```

### Ətraflı Qurulum
```python
def comprehensive_setup(detector, max_retries=3):
    """Yenidən cəhd ilə tam mühit qurulumu"""
    for attempt in range(max_retries):
        try:
            success = detector.setup_environment()
            if success:
                # Əlavə validasiyalar
                if validate_environment(detector):
                    return True
        except Exception as e:
            print(f"Qurulum cəhdi {attempt + 1} uğursuz: {e}")
            time.sleep(5)
    
    return False

def validate_environment(detector):
    """Mühitin düzgün qurulduğunu yoxla"""
    if detector.zeek_parser.df.empty:
        print("Xəbərdarlıq: Boş məlumat dəsti")
        return True  # Hələ də uğurlu sayılır
    
    # Data keyfiyyətini yoxla
    stats = detector.zeek_parser.get_stats()
    if stats['unique_sources'] == 0:
        print("Xəta: Heç bir mənbə tapılmadı")
        return False
    
    return True
```

### Real-time Monitorinq Üçün
```python
def initialize_detector_with_fallback(config_path):
    """Əsas və ehtiyat konfiqurasiya ilə işə salma"""
    try:
        # Əsas konfiqurasiya ilə cəhd et
        detector = C2Detector(config_path)
        if detector.setup_environment():
            return detector
    except Exception as e:
        print(f"Əsas konfiqurasiya uğursuz: {e}")
    
    try:
        # Ehtiyat konfiqurasiya ilə cəhd et
        detector = C2Detector("default_config.json")
        if detector.setup_environment():
            return detector
    except Exception as e:
        print(f"Ehtiyat konfiqurasiya uğursuz: {e}")
    
    return None
```

## 🔧 Konfiqurasiya Seçimləri

### Tarixi Məlumat Konfiqurasiyası
```json
{
  "analysis": {
    "historical_days": 7,
    "analysis_window_minutes": 60,
    "real_time_interval": 30
  }
}
```

### Fərdiləşdirilmiş Qurulum
```python
def custom_environment_setup(detector, options):
    """Fərdi seçimlərlə mühit qurulumu"""
    # Konfiqurasiyanı dinamik olaraq dəyiş
    if 'historical_days' in options:
        detector.config['analysis']['historical_days'] = options['historical_days']
    
    if 'log_dir' in options:
        detector.config['zeek']['log_dir'] = options['log_dir']
    
    # Qurulumu işə sal
    return detector.setup_environment()

# Fərdi seçimlərlə işə sal
options = {
    'historical_days': 3,
    'log_dir': '/var/log/zeek/current'
}
success = custom_environment_setup(detector, options)
```

## 📊 Qurulum Statistikaları

### Performans Metrikaları
```python
def measure_setup_performance(detector):
    """Qurulum performansının ölçülməsi"""
    start_time = time.time()
    
    success = detector.setup_environment()
    elapsed_time = time.time() - start_time
    
    stats = {
        'success': success,
        'elapsed_time': elapsed_time,
        'data_size': len(detector.zeek_parser.df),
        'memory_usage': get_memory_usage()
    }
    
    return stats

def get_memory_usage():
    """Yaddaş istifadəsinin ölçülməsi"""
    import psutil
    process = psutil.Process()
    return process.memory_info().rss / 1024 / 1024  # MB
```

### Qurulum Hesabatı
```python
def generate_setup_report(detector):
    """Ətraflı qurulum hesabatı"""
    report = {
        'timestamp': datetime.now(),
        'config_file': detector.config_path,
        'environment_status': 'success' if detector.setup_environment() else 'failed',
        'zeek_status': 'available' if detector.zeek_parser._validate_log_file() else 'unavailable'
    }
    
    if report['environment_status'] == 'success':
        stats = detector.zeek_parser.get_stats()
        report.update({
            'data_metrics': stats,
            'analysis_ready': True,
            'baseline_established': True
        })
    else:
        report.update({
            'data_metrics': {},
            'analysis_ready': False,
            'baseline_established': False,
            'error_message': 'Environment setup failed'
        })
    
    return report
```

## 💡 Əlavə Qeydlər

### 1. Validation Funksiyaları
```python
def validate_zeek_environment(parser):
    """Zeek mühitinin doğrulanması"""
    checks = {
        'log_file_exists': parser._validate_log_file(),
        'log_directory_exists': parser.zeek_log_dir.exists(),
        'has_read_permission': os.access(str(parser.dns_log_path), os.R_OK)
    }
    
    return all(checks.values()), checks
```

### 2. Fallback Strategiyası
```python
def setup_with_fallback_strategy(detector):
    """Çoxmərhəli fallback strategiyası"""
    # 1. Əsas konfiqurasiya ilə cəhd
    if detector.setup_environment():
        return True
    
    # 2. Default log qovluğu ilə cəhd
    detector.config['zeek']['log_dir'] = '/opt/zeek/logs/current'
    if detector.setup_environment():
        return True
    
    # 3. Yalnız real-time modda işə sal
    print("Xəbərdarlıq: Yalnız real-time modda işləyir")
    return True  # Hələ də uğurlu say
```

### 3. Resource Monitoring
```python
def monitor_setup_resources():
    """Qurulum zamanı resource istifadəsinin monitorinqi"""
    resource_stats = {
        'cpu_percent': psutil.cpu_percent(),
        'memory_usage': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent
    }
    
    if any(usage > 90 for usage in resource_stats.values()):
        print("Xəbərdarlıq: Yüksək resource istifadəsi")
        return False
    
    return True
```

---

**Növbəti:** [05. Detector Modulu - real-time processing](/doc/core/05_detector/03_real_time_processing.md)

Bu sənəd `setup_environment` metodunun detallı işləmə prinsipini izah edir. Növbəti sənəddə real-time emal metoduna keçəcəyik.
