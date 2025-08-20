Mükəmməl! İndi bizim tam sənədləşdirmə strukturumuz var. Gəlin növbəti sənəd olan **05. Detector Modulu - real-time processing** yaradaq:

# 05. Detector Modulu - real-time processing

## 📋 `real_time_dns_callback` Metodunun Təyinatı

`real_time_dns_callback` metodu Zeek-dən gələn real-time DNS log girişlərini emal edən əsas funksiyadır. Bu metod hər yeni DNS sorğusu üçün çağırılır və ani təhdid aşkarlaması həyata keçirir.

## 🏗️ Metod İmzası

```python
def real_time_dns_callback(self, dns_entry: Dict):
```

**Parametrlər:**
- `dns_entry` (Dict): Zeek-dən gələn emal edilmiş DNS girişi

**Qaytarır:** `None` - Nəticələr birbaşa emal olunur

## 🔧 Metodun Daxili İşləməsi

### 1. Giriş Məlumatlarının Çıxarılması

```python
source_ip = dns_entry.get('id.orig_h', 'unknown')
query = dns_entry.get('query', '')
qtype = dns_entry.get('qtype_name', '')
```

**Çıxarılan Məlumatlar:**
- `source_ip`: Sorğunun mənbə IP ünvanı
- `query`: DNS sorğu adı (domain)
- `qtype`: DNS sorğu növü (A, AAAA, TXT, və s.)

### 2. Ani Təhdid Aşkarlaması

```python
immediate_alerts = self._check_immediate_threats(dns_entry)
if immediate_alerts:
    for alert in immediate_alerts:
        self.raise_alert(alert)
```

**Funksiya:** Əlavə analiz gözləmədən ani təhdidləri aşkar edir

### 3. Performans Optimizasiyası ilə Loglama

```python
if len(query) > 70:
    logger.debug(f"Long query: {source_ip} -> {query[:50]}... ({qtype})")
else:
    logger.debug(f"Query: {source_ip} -> {query} ({qtype})")
```

**Loglama Strategiyası:**
- Uzun sorğular qısaldılır
- Normal sorğular tam göstərilir
- Debug səviyyəli loglama

### 4. Xəta Əlaqələndirmə

```python
except Exception as e:
    logger.error(f"Error in real-time processing: {e}")
```

**Funksiya:** Real-time emalda baş verən xətaları idarə edir

## 🎯 Ani Təhdid Aşkarlama

### `_check_immediate_threats` Metodu

```python
def _check_immediate_threats(self, dns_entry: Dict) -> List[Dict]:
    alerts = []
    source_ip = dns_entry.get('id.orig_h')
    query = dns_entry.get('query', '')
    qtype = dns_entry.get('qtype_name', '')
    
    # Ekstrem uzunluq aşkarlaması
    if len(query) > 100:
        alerts.append({
            'timestamp': datetime.now(),
            'alert_type': 'EXTREME_LENGTH_DOMAIN',
            'severity': 'HIGH',
            'severity_score': 95,
            'source_ip': source_ip,
            'domain': query,
            'length': len(query),
            'description': f'Extreme domain length: {len(query)} characters'
        })
    
    # Şübhəli sorğu növləri
    suspicious_types = ['TXT', 'NULL', 'ANY', 'AXFR']
    if qtype in suspicious_types:
        alerts.append({
            'timestamp': datetime.now(),
            'alert_type': 'SUSPICIOUS_QUERY_TYPE',
            'severity': 'MEDIUM',
            'severity_score': 75,
            'source_ip': source_ip,
            'query_type': qtype,
            'domain': query,
            'description': f'Suspicious DNS type: {qtype}'
        })
            
    return alerts
```

## 📊 Real-time İşləmə Xüsusiyyətləri

### Performans Optimizasiyaları

```python
# Optimized logging - uzun stringlərin qısaldılması
# Exception handling - prosesin davam etməsi
# Minimal yaddaş istifadəsi - yerli dəyişənlər
```

### Emal Sırası

1. **Giriş validasiyası** - Məlumatların çıxarılması
2. **Ani təhdid aşkarlama** - Əlavə analiz gözləmədən
3. **Loglama** - Debug məlumatlarının qeydə alınması
4. **Xəta idarəetmə** - prosesin davam etdirilməsi

## ⚠️ Xəta Əlaqələndirmə

Metod aşağıdakı xətaları idarə edir:

1. **Çatışmayan məlumat** - `get()` ilə default dəyərlər
2. **Format xətaları** - Exception handling ilə
3. **Null dəyərlər** - Boş string defaultları

## 🎯 İstifadə Nümunələri

### Əsas İstifadə
```python
# Callback funksiyasının təyin edilməsi
def custom_callback(dns_entry):
    print(f"Yeni DNS sorğusu: {dns_entry.get('query')}")

# Real-time monitorinqin başladılması
parser.tail_new_entries(custom_callback)
```

### Ətraflı Real-time Analiz
```python
def advanced_real_time_analysis(detector):
    """Real-time analiz üçün xüsusi callback"""
    def analysis_callback(dns_entry):
        # Ani təhdid aşkarlama
        immediate_threats = detector._check_immediate_threats(dns_entry)
        for threat in immediate_threats:
            detector.raise_alert(threat)
        
        # Əlavə analiz məntiqi
        perform_additional_analysis(dns_entry)
    
    return analysis_callback

# Xüsusi callback ilə işə salma
custom_callback = advanced_real_time_analysis(detector)
parser.tail_new_entries(custom_callback)
```

### Çoxmiqyaslı Real-time Emal
```python
def scalable_real_time_processing(detector, batch_size=1000):
    """Böyük miqyaslı real-time emal"""
    batch = []
    
    def batch_callback(dns_entry):
        nonlocal batch
        batch.append(dns_entry)
        
        if len(batch) >= batch_size:
            process_batch(batch)
            batch = []
    
    def process_batch(batch):
        """Toplu emal funksiyası"""
        for entry in batch:
            immediate_threats = detector._check_immediate_threats(entry)
            for threat in immediate_threats:
                detector.raise_alert(threat)
    
    return batch_callback
```

## 🚀 Performans Optimizasiyaları

### 1. Yaddaş İdarəetmə
```python
# Yerli dəyişənlər - aşağı yaddaş footprinti
# Batch processing - böyük miqyaslı emal
# String optimizasiyası - uzun sorğuların qısaldılması
```

### 2. CPU Optimizasiyası
```python
# Səmərəli data strukturları
# Minimal hesablama
# Asinxron emal imkanı
```

### 3. Şəbəkə Optimizasiyası
```python
# Lokal emal - şəbəkə trafiksiz
# Sıxışdırılmış loglama
# Adaptive sampling
```

## 🔧 Tənzimlənə Bilən Parametrlər

### Real-time Konfiqurasiya
```json
{
  "real_time_processing": {
    "max_query_length_log": 70,
    "immediate_thresholds": {
      "max_domain_length": 100,
      "suspicious_types": ["TXT", "NULL", "ANY", "AXFR"]
    },
    "performance": {
      "batch_size": 1000,
      "sleep_interval": 0.001
    }
  }
}
```

### Dinamik Tənzimləmə
```python
def adjust_real_time_parameters(detector, network_load):
    """Şəbəkə yükünə görə real-time parametrləri tənzimlə"""
    if network_load > 80:  # Yüksək yük
        detector.config['real_time_processing']['batch_size'] = 500
        detector.config['real_time_processing']['sleep_interval'] = 0.005
    else:  # Normal yük
        detector.config['real_time_processing']['batch_size'] = 1000
        detector.config['real_time_processing']['sleep_interval'] = 0.001
```

## 💡 Əlavə Qeydlər

### 1. Quality of Service (QoS)
```python
def implement_qos_strategy(detector):
    """Real-time emal üçün QoS strategiyası"""
    # Prioritizasiya: Ani təhdidlər > Loglama > Statistikalar
    # Adaptive rate limiting
    # Resource-based throttling
```

### 2. Machine Learning İnteqrasiyası
```python
def ml_enhanced_processing(dns_entry, ml_model):
    """ML əsaslı real-time emal"""
    # Real-time feature extraction
    # ML model inference
    # Anomaly scoring
```

### 3. Distributed Processing
```python
def distributed_real_time_processing(dns_entry, message_queue):
    """Paylanmış real-time emal"""
    # Message queue-ya göndərmə
    # Worker processes ilə emal
    # Nəticələrin birləşdirilməsi
```

---

**Növbəti:** [05. Detector Modulu - alert management](/doc/core/05_detector/03_alert_management.md)

Bu sənəd `real_time_dns_callback` metodunun detallı işləmə prinsipini izah edir. Növbəti sənəddə xəbərdarlıq idarəetmə sisteminə keçəcəyik.
