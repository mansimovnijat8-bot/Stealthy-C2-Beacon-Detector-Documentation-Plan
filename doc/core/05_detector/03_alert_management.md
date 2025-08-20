# 05. Detector Modulu - alert management

## 📋 `raise_alert` Metodunun Təyinatı

`raise_alert` metodu aşkarlanan təhdidlər üçün xəbərdarlıq yaradır, idarə edir və müxtəlif çıxışlara göndərir. Bu metod C2 aşkarlama sisteminin əsas xəbərdarlıq mühərrikidir.

## 🏗️ Metod İmzası

```python
def raise_alert(self, alert: Dict):
```

**Parametrlər:**
- `alert` (Dict): Aşkarlanan təhdid məlumatları

**Qaytarır:** `None` - Nəticələr birbaşa emal olunur

## 🔧 Metodun Daxili İşləməsi

### 1. Rate Limiting Yoxlaması

```python
alerting_config = self.config.get('alerting', {})
max_alerts = alerting_config.get('max_alerts_per_hour', 1000)

if self.alert_count >= max_alerts:
    logger.warning("Alert rate limit reached, suppressing further alerts")
    return
```

**Funksiya:** Saatda maksimum xəbərdarlıq sayını yoxlayır

**Default Dəyər:** 1000 xəbərdarlıq/saat

### 2. Xəbərdarlıq ID və Metadata Əlavəsi

```python
self.alert_count += 1
alert['alert_id'] = self.alert_count
alert['detector_version'] = '1.0.0'
```

**Metadata:**
- `alert_id`: Unikal xəbərdarlıq identifikatoru
- `detector_version`: Detektor versiyası
- `timestamp`: Xəbərdarlıq zamanı (avtomatik əlavə olunur)

### 3. Xəbərdarlığın Saxlanması

```python
self.alerts.append(alert)
```

**Funksiya:** Xəbərdarlığı daxili siyahıya əlavə edir

**Data Strukturu:** `List[Dict]` - Bütün xəbərdarlıqların tarixi

### 4. Strukturlaşdırılmış Loglama

```python
logger.warning(
    "C2 Alert detected",
    extra={
        'extra_data': {
            'alert_id': alert['alert_id'],
            'alert_type': alert['alert_type'],
            'severity': alert['severity'],
            'source_ip': alert.get('source_ip'),
            'description': alert['description']
        }
    }
)
```

**Log Formatı:** JSON strukturlaşdırılmış log

**Loglanan Məlumatlar:**
- Xəbərdarlıq ID və növü
- Risk səviyyəsi
- Mənbə IP ünvanı
- Təsvir

### 5. Konsol Çıxışı

```python
self._print_enhanced_alert(alert)
```

**Funksiya:** Rəngli və formatlı konsol çıxışı yaradır

### 6. Davamlı Saxlama

```python
self._save_alert(alert)
```

**Funksiya:** Xəbərdarlığı fayl sisteminə yazır

## 🎯 Xəbərdarlıq Formatı

### Əsas Xəbərdarlıq Strukturu

```python
{
    'alert_id': 42,
    'timestamp': '2024-01-15T14:30:22.123456',
    'alert_type': 'HIGH_DNS_VOLUME',
    'severity': 'HIGH',
    'severity_score': 95.5,
    'source_ip': '192.168.1.105',
    'query_count': 250,
    'threshold': 100,
    'description': 'Excessive DNS queries: 250 queries (threshold: 100)',
    'detector_version': '1.0.0'
}
```

### Təhlükə Səviyyələri

| Severity | Score Range | Təsvir | Rəng |
|----------|-------------|---------|-------|
| **HIGH** | 80-100 | Yüksək təhlükə | 🔴 Qırmızı |
| **MEDIUM** | 50-79 | Orta təhlükə | 🟡 Sarı |
| **LOW** | 20-49 | Aşağı təhlükə | 🔵 Mavi |
| **INFO** | 0-19 | Məlumat | ⚪ Ağ |

## ⚠️ Rate Limiting Strategiyası

### 1. Sabit Limit
```python
# Konfiqurasiya faylında
"max_alerts_per_hour": 1000
```

### 2. Adaptiv Limit
```python
def adaptive_rate_limiting(detector, current_load):
    """Şəbəkə yükünə görə rate limiting"""
    base_limit = 1000
    
    if current_load > 1000:  # Yüksək yük
        return base_limit // 2  # Limitı yarıya endir
    else:
        return base_limit
```

### 3. Prioritet əsaslı Limit
```python
def priority_based_limiting(alert, current_count, max_limit):
    """Xəbərdarlıq prioritetinə görə limit"""
    if alert['severity'] == 'HIGH':
        return True  # Həmişə qəbul et
    else:
        return current_count < max_limit
```

## 🎯 İstifadə Nümunələri

### Əsas İstifadə
```python
# Xəbərdarlıq yaratmaq
alert = {
    'alert_type': 'DNS_BEACONING',
    'severity': 'HIGH',
    'source_ip': '192.168.1.105',
    'interval_mean': 60.2,
    'interval_stdev': 1.8,
    'description': 'Regular DNS beaconing detected'
}

detector.raise_alert(alert)
```

### Xüsusi Xəbərdarlıq Formatı
```python
def create_custom_alert(alert_type, severity, source_ip, **kwargs):
    """Xüsusi xəbərdarlıq formatı yaratmaq"""
    alert = {
        'alert_type': alert_type,
        'severity': severity,
        'source_ip': source_ip,
        'timestamp': datetime.now(),
        'description': kwargs.get('description', ''),
        'custom_data': kwargs
    }
    
    # Əlavə metadata
    if 'query_count' in kwargs:
        alert['query_count'] = kwargs['query_count']
    if 'domain' in kwargs:
        alert['domain'] = kwargs['domain']
    
    return alert

# Xüsusi xəbərdarlıq yaratmaq
custom_alert = create_custom_alert(
    'CUSTOM_ANOMALY',
    'MEDIUM',
    '192.168.1.106',
    query_count=150,
    domain='suspicious-domain.com',
    reason='Unusual pattern detected'
)

detector.raise_alert(custom_alert)
```

## 🚀 Performans Optimizasiyaları

### 1. Yaddaş İdarəetmə
```python
# Alert siyahısının ölçüsünü məhdudlaşdırma
def trim_alert_history(detector, max_history=10000):
    """Köhnə xəbərdarlıqları təmizlə"""
    if len(detector.alerts) > max_history:
        detector.alerts = detector.alerts[-max_history:]
```

### 2. Batch Yazma
```python
def batch_alert_saving(detector, batch_size=100):
    """Xəbərdarlıqları toplu şəkildə yazmaq"""
    if len(detector.alerts) % batch_size == 0:
        detector._save_alerts_batch(detector.alerts[-batch_size:])
```

### 3. Asinxron Emal
```python
async def async_raise_alert(detector, alert):
    """Asinxron xəbərdarlıq emalı"""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, detector.raise_alert, alert)
```

## 🔧 Tənzimlənə Bilən Parametrlər

### Xəbərdarlıq Konfiqurasiyası
```json
{
  "alerting": {
    "max_alerts_per_hour": 1000,
    "log_file": "data/alerts/c2_alerts.json",
    "severity_levels": {
      "HIGH": 90,
      "MEDIUM": 70,
      "LOW": 50
    },
    "console_output": true,
    "file_output": true,
    "json_format": true
  }
}
```

### Dinamik Konfiqurasiya
```python
def configure_alerting(detector, settings):
    """İş zamanı xəbərdarlıq konfiqurasiyası"""
    detector.config['alerting'].update(settings)
    
    # Real-time tənzimləmələr
    if 'max_alerts_per_hour' in settings:
        detector.alert_rate_limit = settings['max_alerts_per_hour']
```

## 💡 Əlavə Qeydlər

### 1. Xəbərdarlıq Korrelyasiyası
```python
def correlate_alerts(detector, time_window=300):
    """Müəyyən vaxt pəncərəsindəki xəbərdarlıqları korrelyasiya et"""
    recent_alerts = [a for a in detector.alerts 
                    if datetime.now() - a['timestamp'] < timedelta(seconds=time_window)]
    
    # Eyni IP ünvanına görə qruplaşdır
    alerts_by_ip = {}
    for alert in recent_alerts:
        ip = alert.get('source_ip')
        if ip:
            if ip not in alerts_by_ip:
                alerts_by_ip[ip] = []
            alerts_by_ip[ip].append(alert)
    
    return alerts_by_ip
```

### 2. False Positive Filtering
```python
def filter_false_positives(detector, whitelist):
    """Ağ siyahı əsasında false positive'ləri filtrlə"""
    filtered_alerts = []
    false_positives = 0
    
    for alert in detector.alerts:
        if alert.get('source_ip') in whitelist:
            false_positives += 1
        else:
            filtered_alerts.append(alert)
    
    detector.alerts = filtered_alerts
    return false_positives
```

### 3. Xəbərdarlıq Exportu
```python
def export_alerts(detector, format='json', filename=None):
    """Xəbərdarlıqları müxtəlif formatlarda eksport et"""
    if format == 'json':
        data = json.dumps(detector.alerts, default=str, indent=2)
    elif format == 'csv':
        data = alerts_to_csv(detector.alerts)
    elif format == 'html':
        data = generate_html_report(detector.alerts)
    
    if filename:
        with open(filename, 'w') as f:
            f.write(data)
    
    return data
```

---

**Növbəti:** [05. Detector Modulu - periodic analysis](/doc/core/05_detector/04_periodic_analysis.md)

Bu sənəd `raise_alert` metodunun detallı işləmə prinsipini izah edir. Növbəti sənəddə dövri analiz metoduna keçəcəyik.
