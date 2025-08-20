# 04. DNS Analyzer Modulu - volume analysis

## 📋 `_detect_volume_anomalies` Metodunun Təyinatı

`_detect_volume_anomalies` metodu DNS sorğularının həcmi əsasında anomaliyaları aşkar edir. Bu metod həddən artıq DNS trafikini və potensial C2 beaconing fəaliyyətini identifikasiya edir.

## 🏗️ Metod İmzası

```python
def _detect_volume_anomalies(self) -> List[Dict]:
```

**Parametrlər:** Heç bir parametr qəbul etmir

**Qaytarır:** `List[Dict]` - Həcm əsaslı anomaliya xəbərdarlıqlarının siyahısı

## 🔧 Metodun Daxili İşləməsi

### 1. Boş Data Yoxlaması

```python
alerts = []
threshold = self.volume_threshold
```

**Funksiya:** İlkin dəyişənləri təyin edir və boş xəbərdarlıq siyahısı yaradır

### 2. Hər Host Üçün Sorğu Sayının Analizi

```python
for host, count in self.host_query_count.items():
```

**Funksiya:** Hər bir IP ünvanının DNS sorğu sayını iterasiya edir

**Data Mənbəyi:** `self.host_query_count` defaultdict(int)

### 3. Mütləq Hədd Yoxlaması

```python
if count > threshold:
    severity_score = min(100, (count / threshold) * 100)
    alerts.append({
        'timestamp': datetime.now(),
        'alert_type': 'HIGH_DNS_VOLUME',
        'severity': 'HIGH',
        'severity_score': severity_score,
        'source_ip': host,
        'query_count': count,
        'threshold': threshold,
        'description': f'Excessive DNS queries: {count} queries (threshold: {threshold})'
    })
```

**Mütləq Hədd Alqoritmi:**
- Sorğu sayı > konfiqurasiya həddi (default: 100/dəq)
- Severity score: (count / threshold) * 100 (maksimum 100)
- Yüksək risk kateqoriyası

### 4. Nisbi Hədd Yoxlaması

```python
elif count > self.avg_query_volume * 3 and self.avg_query_volume > 10:
    severity_score = min(90, (count / (self.avg_query_volume * 3)) * 100)
    alerts.append({
        'timestamp': datetime.now(),
        'alert_type': 'ABNORMAL_QUERY_VOLUME',
        'severity': 'MEDIUM', 
        'severity_score': severity_score,
        'source_ip': host,
        'query_count': count,
        'average_volume': self.avg_query_volume,
        'description': f'Abnormal query volume: {count} queries (3x average: {self.avg_query_volume:.1f})'
    })
```

**Nisbi Hədd Alqoritmi:**
- Sorğu sayı > orta dəyər * 3
- Minimum orta dəyər tələbi: > 10 sorğu
- Orta risk kateqoriyası
- Daha incə aşkarlama (statistik anomaliya)

## 🎯 Aşkarlama Nümunələri

### Mütləq Hədd Nümunəsi
```python
# Konfiqurasiya: volume_threshold = 100
# Host sorğu sayı: 250
# Severity: min(100, (250/100)*100) = 100

{
    'alert_type': 'HIGH_DNS_VOLUME',
    'severity': 'HIGH',
    'severity_score': 100,
    'source_ip': '192.168.1.105',
    'query_count': 250,
    'threshold': 100,
    'description': 'Excessive DNS queries: 250 queries (threshold: 100)'
}
```

### Nisbi Hədd Nümunəsi  
```python
# Orta sorğu: 30, Host sorğu: 100
# Severity: min(90, (100/90)*100) ≈ 90

{
    'alert_type': 'ABNORMAL_QUERY_VOLUME',
    'severity': 'MEDIUM',
    'severity_score': 90,
    'source_ip': '192.168.1.106', 
    'query_count': 100,
    'average_volume': 30.0,
    'description': 'Abnormal query volume: 100 queries (3x average: 30.0)'
}
```

## 📊 Statistik Hesablamalar

### Orta Sorğu Həcminin Hesablanması
```python
# self.avg_query_volume necə hesablanır:
total_queries = sum(self.host_query_count.values())
total_hosts = len(self.host_query_count)
self.avg_query_volume = total_queries / max(total_hosts, 1)
```

**Düstur:** `ortalama = ümumi_sorğular / host_sayı`

**Nümunə:** 1000 sorğu / 20 host = 50 sorğu/host

### Severity Score Hesablanması
```python
# Mütləq hədd üçün
severity = min(100, (actual_count / threshold) * 100)

# Nisbi hədd üçün  
severity = min(90, (actual_count / (avg_volume * 3)) * 100)
```

**Severity Şkalası:** 0-100 (100 = maksimum risk)

## ⚠️ Xəta Əlaqələndirmə

Metod aşağıdakı xətaları idarə edir:

1. **Boş data** - `host_query_count` boş olduqda avtomatik olaraq boş siyahı qaytarır
2. **Sıfıra bölmə** - `max(total_hosts, 1)` ilə qarşısı alınır
3. **Data tipi** - Bütün dəyərlər avtomatik konvertasiya olunur

## 🎯 İstifadə Nümunələri

### Əsas İstifadə
```python
analyzer = DNSAnalyzer(config)
analyzer.process_dns_data(zeek_parser)

volume_alerts = analyzer._detect_volume_anomalies()

print(f"Həcm anomaliyaları: {len(volume_alerts)}")
for alert in volume_alerts:
    print(f"{alert['severity']}: {alert['source_ip']} - {alert['query_count']} sorğu")
```

### Real-time Monitorinq
```python
def monitor_volume_anomalies(analyzer, check_interval=60):
    """Dövri həcm anomaliyası monitorinqi"""
    while True:
        alerts = analyzer._detect_volume_anomalies()
        
        for alert in alerts:
            if alert['severity'] == 'HIGH':
                print(f"🚨 YÜKSƏK RİSK: {alert['source_ip']} - {alert['query_count']} sorğu")
            elif alert['severity'] == 'MEDIUM':
                print(f"⚠️ ORTA RİSK: {alert['source_ip']} - {alert['query_count']} sorğu")
        
        time.sleep(check_interval)

# Monitorinqi işə sal
monitor_volume_anomalies(analyzer)
```

### Statistik Təhlil
```python
def volume_statistics(analyzer):
    """Həcm statistikalarının ətraflı təhlili"""
    stats = {
        'total_queries': sum(analyzer.host_query_count.values()),
        'unique_hosts': len(analyzer.host_query_count),
        'avg_queries_per_host': analyzer.avg_query_volume,
        'max_queries': max(analyzer.host_query_count.values()) if analyzer.host_query_count else 0,
        'min_queries': min(analyzer.host_query_count.values()) if analyzer.host_query_count else 0
    }
    
    # Sorğu paylanması
    query_distribution = {}
    for count in analyzer.host_query_count.values():
        range_key = f"{(count // 10) * 10}-{(count // 10) * 10 + 9}"
        query_distribution[range_key] = query_distribution.get(range_key, 0) + 1
    
    stats['query_distribution'] = query_distribution
    return stats
```

## 🚀 Performans Optimizasiyaları

### 1. Səmərəli Iterasiya
```python
# defaultdict iterasiyası O(n) mürəkkəblik
# Çox sürətli, böyük data dəstləri üçün uyğun
```

### 2. Əvvəlcədən Hesablanmış Statistikalar
```python
# avg_query_volume əvvəlcədən hesablanır
# Hər çağırışda yenidən hesablama yoxdur
```

### 3. Minimal Yaddaş İstifadəsi
```python
# Yalnız zəruri məlumatları saxlayır
# Böyük data dəstləri üçün optimallaşdırılıb
```

## 🔧 Tənzimlənə Bilən Parametrlər

### Hədd Konfiqurasiyası
```python
# config.json faylında
{
  "alert_thresholds": {
    "dns_queries_per_minute": 150,
    "unusual_domain_length": 60,
    "entropy_threshold": 4.2
  }
}

# Real-time tənzimləmə
analyzer.volume_threshold = 200  # Dinamik olaraq dəyişdirilə bilər
```

### Risk Səviyyəsi Tənzimləməsi
```python
def adjust_severity_calculation(analyzer, risk_factor=1.0):
    """Risk faktoruna görə severity hesablamasını tənzimlə"""
    # Mütləq hədd severity
    absolute_severity = min(100, (count / analyzer.volume_threshold) * 100 * risk_factor)
    
    # Nisbi hədd severity
    relative_severity = min(90, (count / (analyzer.avg_query_volume * 3)) * 100 * risk_factor)
```

## 📈 İnkişaf Etmiş Analiz

### Trend Analizi
```python
def volume_trend_analysis(analyzer, historical_data):
    """Sorğu həcminin zamanla dəyişmə trendi"""
    trends = []
    
    for timestamp, volume_data in historical_data:
        current_volume = sum(volume_data.values())
        avg_volume = current_volume / max(len(volume_data), 1)
        
        trends.append({
            'timestamp': timestamp,
            'total_queries': current_volume,
            'avg_per_host': avg_volume,
            'peak_host': max(volume_data.values()) if volume_data else 0
        })
    
    return trends
```

### Anomaliya Korrelyasiyası
```python
def correlate_volume_with_other_anomalies(volume_alerts, other_alerts):
    """Həcm anomaliyalarını digər anomaliyalarla korrelyasiya et"""
    correlated_alerts = []
    
    for volume_alert in volume_alerts:
        ip = volume_alert['source_ip']
        
        # Eyni IP üçün digər anomaliyaları tap
        related_alerts = [a for a in other_alerts if a.get('source_ip') == ip]
        
        if related_alerts:
            volume_alert['related_anomalies'] = related_alerts
            volume_alert['severity_score'] = min(100, volume_alert['severity_score'] + 10)
        
        correlated_alerts.append(volume_alert)
    
    return correlated_alerts
```

## 💡 Əlavə Qeydlər

### 1. False Positive Aradan Qaldırma
```python
def filter_legitimate_high_volume(volume_alerts, whitelist_services):
    """Qanuni yüksək həcmi filtrlə"""
    filtered = []
    
    for alert in volume_alerts:
        ip = alert['source_ip']
        
        # DNS serverları və digər qanunu yüksək həcmləri aradan qaldır
        if ip not in whitelist_services and alert['query_count'] < 1000:
            filtered.append(alert)
    
    return filtered
```

### 2. Dinamik Hədd Tənzimləməsi
```python
def adaptive_volume_threshold(analyzer, network_conditions):
    """Şəbəkə vəziyyətinə görə həddi avtomatik tənzimlə"""
    base_threshold = 100
    
    if network_conditions['is_business_hours']:
        return base_threshold * 1.5  # İş saatlarında daha yüksək hədd
    elif network_conditions['is_weekend']:
        return base_threshold * 0.7  # Həftə sonu daha aşağı hədd
    else:
        return base_threshold
```

### 3. Dərin Məlumat Təhlili
```python
def analyze_volume_patterns(analyzer):
    """Sorğu həcminin dərin təhlili"""
    volume_stats = {
        'total': sum(analyzer.host_query_count.values()),
        'by_protocol': {},  # DNS sorğu növlərinə görə
        'by_time': {},      # Saatlıq paylanma
        'by_domain': {}     # Domain növlərinə görə
    }
    
    # Əlavə təhlil məntiqi burada...
    return volume_stats
```

---

**Növbəti:** [04. DNS Analyzer Modulu - temporal analysis](/doc/core/04_dns_analyzer/05_temporal_analysis.md)

Bu sənəd `_detect_volume_anomalies` metodunun detallı işləmə prinsipini izah edir. Növbəti sənəddə vaxt əsaslı analiz metoduna keçəcəyik.
