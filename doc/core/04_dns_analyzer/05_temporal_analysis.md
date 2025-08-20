# 04. DNS Analyzer Modulu - temporal analysis

## 📋 `_detect_temporal_anomalies` Metodunun Təyinatı

`_detect_temporal_anomalies` metodu DNS sorğularının zamanla dəyişmə patternlərini analiz edərək C2 beaconing fəaliyyətini aşkar edir. Bu metod müntəzəm intervalarla təkrarlanan DNS sorğularını identifikasiya edir.

## 🏗️ Metod İmzası

```python
def _detect_temporal_anomalies(self) -> List[Dict]:
```

**Parametrlər:** Heç bir parametr qəbul etmir

**Qaytarır:** `List[Dict]` - Vaxt əsaslı anomaliya xəbərdarlıqlarının siyahısı

## 🔧 Metodun Daxili İşləməsi

### 1. İlkin Dəyişənlərin Təyin Edilməsi

```python
alerts = []
std_threshold = self.thresholds.get('beacon_interval_std', 2.0)
```

**Funksiya:** Xəbərdarlıq siyahısını və standart sapma həddini təyin edir

**Default Dəyər:** `beacon_interval_std = 2.0` (saniyə)

### 2. Hər Host Üçün Vaxt Məlumatlarının Analizi

```python
for host, timestamps in self.host_temporal_patterns.items():
```

**Funksiya:** Hər bir hostun DNS sorğu zamanlarını iterasiya edir

**Data Mənbəyi:** `self.host_temporal_patterns` defaultdict(list)

### 3. Minimum Nümunə Sayı Yoxlaması

```python
if len(timestamps) < 10:  # Minimum samples for analysis
    continue
```

**Funksiya:** Statistik analiz üçün kifayət qədər nümunə olub-olmadığını yoxlayır

**Minimum Tələb:** 10 sorğu (statistik etibarlılıq üçün)

### 4. Zaman Damğalarının Çeşidlənməsi

```python
timestamps.sort()
```

**Funksiya:** Sorğu zamanlarını kronoloji ardıcıllıqla çeşidləyir

**Əhəmiyyəti:** Interval hesablamaları üçün vacibdir

### 5. Interval Hesablamaları

```python
intervals = [(timestamps[i] - timestamps[i-1]).total_seconds() 
           for i in range(1, len(timestamps))]
```

**Funksiya:** Ardıcıl sorğular arasındakı intervalları saniyələrlə hesablayır

**Nümunə:** `[60.2, 59.8, 60.1, 59.9]` (saniyə)

### 6. Statistik Hesablamalar

```python
if not intervals:
    continue

stats = calculate_statistics(intervals)
```

**Statistik Ölçmələr:**
- `mean`: Orta interval
- `stdev`: Standart sapma (dəyişkənlik)
- `min`: Minimum interval
- `max`: Maksimum interval

### 7. Beaconing Pattern Aşkarlama

```python
if stats['stdev'] < std_threshold and stats['mean'] > 0:
    severity = min(100, (std_threshold / max(stats['stdev'], 0.1)) * 20)
    alerts.append({
        'timestamp': datetime.now(),
        'alert_type': 'DNS_BEACONING',
        'severity': 'HIGH',
        'severity_score': severity,
        'source_ip': host,
        'interval_mean': stats['mean'],
        'interval_stdev': stats['stdev'],
        'query_count': len(timestamps),
        'description': f'Regular DNS beaconing detected ({stats["mean"]:.1f}s ± {stats["stdev"]:.1f}s)'
    })
```

**Aşkarlama Kriteriyaları:**
- Aşağı standart sapma (< 2.0s)
- Müsbət orta interval (> 0)
- Müntəzəm təkrarlanma patterni

## 🎯 Aşkarlama Nümunələri

### Klassik Beaconing Nümunəsi
```python
# Intervals: [60.0, 60.1, 59.9, 60.0, 60.2] (saniyə)
# Mean: 60.04s, Stdev: 0.11s
# Severity: min(100, (2.0 / 0.11) * 20) ≈ 100

{
    'alert_type': 'DNS_BEACONING',
    'severity': 'HIGH',
    'severity_score': 100,
    'source_ip': '192.168.1.105',
    'interval_mean': 60.04,
    'interval_stdev': 0.11,
    'query_count': 32,
    'description': 'Regular DNS beaconing detected (60.0s ± 0.1s)'
}
```

### Qeyri-Müntəzəm Pattern Nümunəsi
```python
# Intervals: [45.2, 78.9, 32.1, 120.5, 15.8] (saniyə)  
# Mean: 58.5s, Stdev: 38.2s
# Stdev > 2.0s, aşkarlanmır
```

## 📊 Statistik Hesablamalar

### Interval Statistikaları
```python
def calculate_statistics(intervals):
    """Interval statistikalarının hesablanması"""
    if not intervals:
        return {}
    
    return {
        'mean': statistics.mean(intervals),
        'median': statistics.median(intervals),
        'stdev': statistics.stdev(intervals) if len(intervals) > 1 else 0,
        'min': min(intervals),
        'max': max(intervals),
        'count': len(intervals)
    }
```

### Severity Score Hesablanması
```python
severity = min(100, (std_threshold / max(stats['stdev'], 0.1)) * 20)
```

**Düstur:** `severity = (2.0 / stdev) * 20` (maksimum 100)

**Məntiq:** Aşağı stdev → Yüksək severity

## ⚠️ Xəta Əlaqələndirmə

Metod aşağıdakı xətaları idarə edir:

1. **Boş interval siyahısı** - `continue` ilə keçir
2. **Statistik hesablama xətaları** - `statistics` modulu avtomatik idarə edir
3. **Vaxt formatı xətaları** - `total_seconds()` etibarlı metod

## 🎯 İstifadə Nümunələri

### Əsas İstifadə
```python
analyzer = DNSAnalyzer(config)
analyzer.process_dns_data(zeek_parser)

temporal_alerts = analyzer._detect_temporal_anomalies()

print(f"Vaxt anomaliyaları: {len(temporal_alerts)}")
for alert in temporal_alerts:
    print(f"Beaconing: {alert['source_ip']} - {alert['interval_mean']:.1f}s ± {alert['interval_stdev']:.1f}s")
```

### Real-time Monitorinq
```python
def monitor_temporal_anomalies(analyzer, check_interval=300):
    """Dövri vaxt anomaliyası monitorinqi"""
    while True:
        alerts = analyzer._detect_temporal_anomalies()
        
        for alert in alerts:
            print(f"🚨 BEACONING: {alert['source_ip']}")
            print(f"   Interval: {alert['interval_mean']:.1f}s ± {alert['interval_stdev']:.1f}s")
            print(f"   Sorğu sayı: {alert['query_count']}")
        
        time.sleep(check_interval)

# Monitorinqi işə sal
monitor_temporal_anomalies(analyzer)
```

### Statistik Təhlil
```python
def temporal_statistics(analyzer):
    """Vaxt statistikalarının ətraflı təhlili"""
    stats = {}
    
    for host, timestamps in analyzer.host_temporal_patterns.items():
        if len(timestamps) >= 2:
            intervals = [(timestamps[i] - timestamps[i-1]).total_seconds() 
                       for i in range(1, len(timestamps))]
            
            if intervals:
                host_stats = calculate_statistics(intervals)
                stats[host] = host_stats
    
    return stats
```

## 🚀 Performans Optimizasiyaları

### 1. Səmərəli Data Strukturları
```python
# defaultdict istifadəsi ilə sürətli giriş
# List comprehensions ilə sürətli hesablama
```

### 2. Əvvəlcədən Hesablanmış Statistikalar
```python
# calculate_statistics funksiyası sürətli statistik hesablamalar edir
# Pandas-dan asılı deyil, təmiz Python
```

### 3. Minimal Yaddaş İstifadəsi
```python
# Yalnız timestamp siyahılarını saxlayır
# Böyük data dəstləri üçün optimallaşdırılıb
```

## 🔧 Tənzimlənə Bilən Parametrlər

### Standart Sapma Həddi
```python
# config.json faylında
{
  "alert_thresholds": {
    "beacon_interval_std": 2.0,
    "dns_queries_per_minute": 150,
    "entropy_threshold": 4.2
  }
}

# Real-time tənzimləmə
analyzer.beacon_std_threshold = 1.5  # Daha sərt hədd
```

### Minimum Nümunə Sayı
```python
def adaptive_minimum_samples(analyzer, confidence_level=0.95):
    """Etibarlılıq səviyyəsinə görə minimum nümunə sayını tənzimlə"""
    if confidence_level > 0.9:
        return 15  # Yüksək etibarlılıq
    else:
        return 8   # Aşağı etibarlılıq
```

## 📈 İnkişaf Etmiş Analiz

### Çoxlu Interval Analizi
```python
def multiple_interval_analysis(timestamps):
    """Müxtəlif interval ölçüləri üçün analiz"""
    analyses = {}
    
    # Qısa müddətli patternlər
    short_intervals = [(timestamps[i] - timestamps[i-1]).total_seconds() 
                      for i in range(1, min(20, len(timestamps)))]
    
    # Uzun müddətli patternlər  
    long_intervals = [(timestamps[i] - timestamps[i-1]).total_seconds()
                     for i in range(1, len(timestamps))]
    
    analyses['short_term'] = calculate_statistics(short_intervals)
    analyses['long_term'] = calculate_statistics(long_intervals)
    
    return analyses
```

### Trend Analizi
```python
def interval_trend_analysis(intervals):
    """Intervalların zamanla dəyişmə trendi"""
    trends = []
    
    # Sürüşən pəncərə analizi
    window_size = 10
    for i in range(len(intervals) - window_size + 1):
        window = intervals[i:i + window_size]
        window_stats = calculate_statistics(window)
        
        trends.append({
            'start_index': i,
            'mean': window_stats['mean'],
            'stdev': window_stats['stdev'],
            'trend': 'stable' if window_stats['stdev'] < 2.0 else 'unstable'
        })
    
    return trends
```

## 💡 Əlavə Qeydlər

### 1. Jitter Analizi
```python
def analyze_jitter_patterns(intervals):
    """Jitter (dəyişkənlik) patternlərinin təhlili"""
    jitter_stats = {
        'absolute_jitter': max(intervals) - min(intervals),
        'relative_jitter': (statistics.stdev(intervals) / statistics.mean(intervals)) * 100,
        'jitter_threshold': 5.0  # 5% jitter həddi
    }
    
    return jitter_stats
```

### 2. Çoxlu Beaconing Patternləri
```python
def detect_multiple_beacons(timestamps):
    """Eyni hostda çoxlu beaconing patternlərinin aşkarlanması"""
    # Vaxt sıralamasını analiz et
    # Birdən çox sabit interval tapmağa çalış
    # Hər pattern üçün ayrı xəbərdarlıq yarat
    pass
```

### 3. Machine Learning İnteqrasiyası
```python
def ml_enhanced_temporal_detection(timestamps, ml_model):
    """ML əsaslı vaxt patterni aşkarlama"""
    # Özül xüsusiyyətləri çıxar
    features = extract_temporal_features(timestamps)
    
    # ML modeli ilə proqnozlaşdır
    prediction = ml_model.predict([features])
    
    return prediction
```

---

**Növbəti:** [04. DNS Analyzer Modulu - report generation](/doc/core/04_dns_analyzer/06_report_generation.md)

Bu sənəd `_detect_temporal_anomalies` metodunun detallı işləmə prinsipini izah edir. Növbəti sənəddə hesabat generasiyası metoduna keçəcəyik.
