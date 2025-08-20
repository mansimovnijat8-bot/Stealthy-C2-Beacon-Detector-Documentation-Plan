# 05. Detector Modulu - periodic analysis

## 📋 `periodic_analysis` Metodunun Təyinatı

`periodic_analysis` metodu müəyyən intervallarla tam DNS təhlilini həyata keçirərək real-time aşkarlamanı tamamlayır. Bu metod dərin təhlil və tarixi pattern aşkarlama üçün nəzərdə tutulub.

## 🏗️ Metod İmzası

```python
def periodic_analysis(self):
```

**Parametrlər:** Heç bir parametr qəbul etmir

**Qaytarır:** `None` - Nəticələr birbaşa emal olunur

## 🔧 Metodun Daxili İşləməsi

### 1. Analizin Başladılması

```python
logger.info("Starting periodic comprehensive analysis...")
```

**Funksiya:** Dövri analizin başladığını loglayır

### 2. Analiz Konfiqurasiyasının Alınması

```python
analysis_config = self.config.get('analysis', {})
window_minutes = analysis_config.get('window_minutes', 5)
```

**Konfiqurasiya Parametrləri:**
- `window_minutes`: Analiz pəncərəsi (dəqiqə) - default: 5
- `real_time_interval`: Analiz intervalları - default: 30

### 3. Son Məlumatların Alınması

```python
recent_data = self.zeek_parser.get_recent_entries(minutes=window_minutes)
```

**Funksiya:** Son N dəqiqəlik DNS məlumatlarını gətirir

**Data Mənbəyi:** `zeek_parser.get_recent_entries()`

### 4. Boş Məlumat Yoxlaması

```python
if not recent_data.empty:
    # Tam analiz prosesi
else:
    logger.info("No recent data for periodic analysis")
```

**Funksiya:** Məlumat olmaması halında prosesi dayandırır

### 5. Müvəqqəti Analizatorun Yaradılması

```python
temp_analyzer = DNSAnalyzer(self.config)
self.zeek_parser.df = recent_data
temp_analyzer.process_dns_data(self.zeek_parser)
```

**Funksiya:** Yeni analizator ilə məlumatları emal edir

**Optimizasiya:** Köhnə məlumatları saxlamır

### 6. Anomaliya Aşkarlama

```python
new_alerts = temp_analyzer.detect_anomalies()
```

**Funksiya:** Yeni anomaliyaları aşkar edir

**Aşkarlama Növləri:**
- Həcm anomaliyaları
- Domain anomaliyaları
- Vaxt anomaliyaları
- Protokol anomaliyaları

### 7. Xəbərdarlıqların Emal Edilməsi

```python
for alert in new_alerts:
    self.raise_alert(alert)
```

**Funksiya:** Yeni xəbərdarlıqları sistemə əlavə edir

### 8. Nəticənin Loglanması

```python
logger.info(f"Periodic analysis completed. Found {len(new_alerts)} new alerts")
```

**Funksiya:** Analiz nəticələrini loglayır

## ⚠️ Xəta Əlaqələndirmə

Metod aşağıdakı xətaları idarə edir:

1. **Boş məlumat** - Səssizcə dayanır, xəta yaratmır
2. **Analiz xətaları** - Xəta loglanır, proses davam edir
3. **Konfiqurasiya xətaları** - Default dəyərlər istifadə olunur

## 🎯 İstifadə Nümunələri

### Əsas İstifadə
```python
# Əl ilə dövri analiz icrası
detector.periodic_analysis()

# Nəticələrin yoxlanması
print(f"Son analizdə {len(detector.alerts)} yeni xəbərdarlıq aşkar edildi")
```

### Avtomatik Dövri Analiz
```python
def start_periodic_analysis(detector, interval_minutes=5):
    """Avtomatik dövri analiz başlatma"""
    while detector.running:
        try:
            detector.periodic_analysis()
            time.sleep(interval_minutes * 60)
        except Exception as e:
            print(f"Dövri analiz xətası: {e}")
            time.sleep(60)  # Xəta halında 1 dəqiqə gözlə

# Arxa planda işə sal
import threading
analysis_thread = threading.Thread(
    target=start_periodic_analysis, 
    args=(detector, 5),
    daemon=True
)
analysis_thread.start()
```

### Ətraflı Analiz Hesabatı
```python
def comprehensive_periodic_analysis(detector, detailed_report=False):
    """Ətraflı dövri analiz və hesabat"""
    start_time = time.time()
    
    # Analizi icra et
    detector.periodic_analysis()
    
    # Performans metrikaları
    duration = time.time() - start_time
    new_alerts = len(detector.alerts)
    
    # Ətraflı hesabat
    if detailed_report:
        report = {
            'timestamp': datetime.now(),
            'duration_seconds': duration,
            'new_alerts': new_alerts,
            'total_alerts': detector.alert_count,
            'data_processed': len(detector.zeek_parser.df)
        }
        print(f"Dövri analiz tamamlandı: {report}")
    
    return new_alerts
```

## 🔧 Tənzimlənə Bilən Parametrlər

### Analiz Konfiqurasiyası
```json
{
  "analysis": {
    "window_minutes": 5,
    "real_time_interval": 30,
    "historical_days": 7,
    "enable_periodic_analysis": true,
    "analysis_thoroughness": "normal"
  }
}
```

### Dinamik Parametr Tənzimləməsi
```python
def configure_periodic_analysis(detector, network_conditions):
    """Şəbəkə şəraitinə görə analiz parametrlərini tənzimlə"""
    config = detector.config['analysis']
    
    if network_conditions['is_peak_hours']:
        # Qısa və tez analiz
        config['window_minutes'] = 2
        config['analysis_thoroughness'] = 'fast'
    else:
        # Uzun və ətraflı analiz
        config['window_minutes'] = 10
        config['analysis_thoroughness'] = 'detailed'
```

## 📊 Performans Optimizasiyaları

### 1. Yaddaş İdarəetmə
```python
# Müvəqqəti analizator - aşağı yaddaş istifadəsi
# Data hissə-hissə emalı - böyük məlumat dəstləri üçün
```

### 2. CPU Optimizasiyası
```python
# Analiz intervallarının optimallaşdırılması
# Resource əsaslı tənzimləmə
```

### 3. Disk İstifadəsi
```python
# Keşləmə strategiyası
# Fayl rotationu
```

## 💡 Əlavə Qeydlər

### 1. Adaptiv Analiz Intervalları
```python
def adaptive_analysis_interval(detector, alert_rate):
    """Xəbərdarlıq dərəcəsinə görə analiz intervallarını tənzimlə"""
    base_interval = 300  # 5 dəqiqə
    
    if alert_rate > 10:  # Yüksək xəbərdarlıq dərəcəsi
        return base_interval // 2  # Daha tez analiz
    else:
        return base_interval
```

### 2. Çoxmərhəli Analiz
```python
def multi_stage_periodic_analysis(detector):
    """Çoxmərhəli dövri analiz"""
    # 1. Sürətli analiz
    fast_alerts = detector._quick_analysis()
    
    # 2. Dərin analiz (əgər lazımsa)
    if fast_alerts:
        detailed_alerts = detector._detailed_analysis()
        return fast_alerts + detailed_alerts
    
    return fast_alerts
```

### 3. Machine Learning İnteqrasiyası
```python
def ml_enhanced_periodic_analysis(detector, ml_model):
    """ML ilə gücləndirilmiş dövri analiz"""
    # Ənənəvi analiz
    traditional_alerts = detector.periodic_analysis()
    
    # ML əsaslı analiz
    ml_features = extract_ml_features(detector.zeek_parser.df)
    ml_predictions = ml_model.predict(ml_features)
    ml_alerts = convert_predictions_to_alerts(ml_predictions)
    
    return traditional_alerts + ml_alerts
```

---

**Növbəti:** [05. Detector Modulu - reporting system](/doc/core/05_detector/05_reporting_system.md)

Bu sənəd `periodic_analysis` metodunun detallı işləmə prinsipini izah edir. Növbəti sənəddə hesabat sisteminə keçəcəyik.
