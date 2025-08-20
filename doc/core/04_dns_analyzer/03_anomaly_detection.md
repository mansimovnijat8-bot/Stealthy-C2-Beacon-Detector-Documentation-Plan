# 04. DNS Analyzer Modulu - anomaly detection

## 📋 `detect_anomalies` Metodunun Təyinatı

`detect_anomalies` metodu DNS məlumatlarında müxtəlif növ anomaliyaları aşkar etmək üçün bütün aşkarlama alqoritmlərini koordinasiya edir. Bu metod proyektin əsas C2 aşkarlama mühərrikidir.

## 🏗️ Metod İmzası

```python
def detect_anomalies(self) -> List[Dict]:
```

**Parametrlər:** Heç bir parametr qəbul etmir

**Qaytarır:** `List[Dict]` - Aşkarlanan anomaliyaların siyahısı

## 🔧 Metodun Daxili İşləməsi

### 1. Bütün Aşkarlama Metodlarının İşə Salınması

```python
alerts = []

# Bütün aşkarlama metodlarını işə sal
alerts.extend(self._detect_volume_anomalies())
alerts.extend(self._detect_suspicious_domains())
alerts.extend(self._detect_temporal_anomalies())
alerts.extend(self._detect_protocol_anomalies())
```

**Funksiya:** Hər bir aşkarlama metodunu çağırır və nəticələri birləşdirir

### 2. Xəbərdarlıqların Çeşidlənməsi

```python
# Severity-yə görə çeşidləmə
alerts.sort(key=lambda x: x.get('severity_score', 0), reverse=True)
```

**Funksiya:** Xəbərdarlıqları risk səviyyəsinə görə sıralayır

**Çeşidləmə Qaydası:** Yüksək risk → Aşağı risk

### 3. Nəticənin Loglanması

```python
logger.info(f"Generated {len(alerts)} anomaly alerts")
```

**Funksiya:** Aşkarlanan anomaliyaların sayını loglayır

## 🎯 Aşkarlama Növləri

### 1. Həcm Əsaslı Anomaliyalar (`_detect_volume_anomalies`)
**Təyinat:** Həddən artıq DNS sorğularını aşkar edir

**Növləri:**
- Mütləq həddi aşan sorğular
- Nisbi olaraq orta dəyərdən kənara çıxan sorğular

### 2. Şübhəli Domainlər (`_detect_suspicious_domains`)  
**Təyinat:** Təsadüfi görünən və ya həddən uzun domainləri aşkar edir

**Növləri:**
- Yüksək entropiyalı domainlər
- Qeyri-adi uzunluqda domainlər

### 3. Vaxt Əsaslı Anomaliyalar (`_detect_temporal_anomalies`)
**Təyinat:** Müntəzəm beaconing patternlərini aşkar edir

**Növləri:**
- Dəqiq intervalarla təkrarlanan sorğular
- Aşağı standart sapma ilə təkrarlanan sorğular

### 4. Protokol Əsaslı Anomaliyalar (`_detect_protocol_anomalies`)
**Təyinat:** Qeyri-adi DNS qeyd növlərini aşkar edir

**Növləri:**
- Nadir DNS sorğu növləri (TXT, NULL, ANY)
- Data ötürmə üçün istifadə olunan sorğu növləri

## 📊 Aşkarlama Alqoritmləri

### Həcm Əsaslı Aşkarlama
```python
def _detect_volume_anomalies(self) -> List[Dict]:
    alerts = []
    threshold = self.volume_threshold
    
    for host, count in self.host_query_count.items():
        # Mütləq hədd
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
        
        # Nisbi hədd (3x orta)
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
                
    return alerts
```

### Domain Əsaslı Aşkarlama
```python
def _detect_suspicious_domains(self) -> List[Dict]:
    alerts = []
    
    for host, domains in self.host_unique_domains.items():
        long_domains = []
        high_entropy_domains = []
        
        for domain in domains:
            # Uzun domainlər
            if len(domain) > self.length_threshold:
                long_domains.append(domain)
            
            # Yüksək entropiyalı domainlər
            entropy = self.calculate_entropy(domain)
            if entropy > self.entropy_threshold:
                high_entropy_domains.append((domain, entropy))
        
        # Uzun domain alertləri
        if len(long_domains) > 5:
            severity = min(90, len(long_domains) * 10)
            alerts.append({
                'timestamp': datetime.now(),
                'alert_type': 'LONG_DOMAINS',
                'severity': 'HIGH', 
                'severity_score': severity,
                'source_ip': host,
                'domain_count': len(long_domains),
                'sample_domains': long_domains[:3],
                'description': f'Multiple long domain names: {len(long_domains)} domains > {self.length_threshold} chars'
            })
        
        # Yüksək entropiya alertləri
        if high_entropy_domains:
            max_entropy = max(entropy for _, entropy in high_entropy_domains)
            severity = min(100, (max_entropy / self.entropy_threshold) * 100)
            alerts.append({
                'timestamp': datetime.now(),
                'alert_type': 'HIGH_ENTROPY_DOMAINS',
                'severity': 'HIGH',
                'severity_score': severity,
                'source_ip': host,
                'domain_count': len(high_entropy_domains),
                'max_entropy': max_entropy,
                'sample_domains': [d[0] for d in high_entropy_domains[:3]],
                'description': f'High entropy domains detected (max: {max_entropy:.2f})'
            })
                
    return alerts
```

## ⚠️ Xəta Əlaqələndirmə

Metod aşağıdakı xətaları idarə edir:

1. **Boş məlumat** - Data strukturları boş olduqda səssizcə boş siyahı qaytarır
2. **Hesablama xətaları** - Statistik hesablamalarda baş verən xətalar
3. **Data tipi xətaları** - Yanlış data formaları

**Xəta handling strategiyası:** Səssiz uğursuzluq - xətalar loglanır lakin proses davam edir

## 🎯 İstifadə Nümunələri

### Əsas İstifadə
```python
analyzer = DNSAnalyzer(config)
analyzer.process_dns_data(zeek_parser)

# Bütün anomaliyaları aşkar et
anomalies = analyzer.detect_anomalies()

print(f"Aşkarlanan anomaliyalar: {len(anomalies)}")
for alert in anomalies[:5]:  # İlk 5 xəbərdarlıq
    print(f"{alert['severity']}: {alert['alert_type']} - {alert['source_ip']}")
```

### Xüsusi Aşkarlama Növləri
```python
# Fərdi aşkarlama metodlarını birbaşa çağırmaq
volume_alerts = analyzer._detect_volume_anomalies()
domain_alerts = analyzer._detect_suspicious_domains()
temporal_alerts = analyzer._detect_temporal_anomalies()

print(f"Həcm anomaliyaları: {len(volume_alerts)}")
print(f"Domain anomaliyaları: {len(domain_alerts)}") 
print(f"Vaxt anomaliyaları: {len(temporal_alerts)}")
```

### Real-time Monitorinq
```python
def continuous_monitoring(analyzer, interval_minutes=5):
    """Davamlı anomaliya monitorinqi"""
    while True:
        anomalies = analyzer.detect_anomalies()
        
        if anomalies:
            print(f"\n[{datetime.now()}] Yeni anomaliyalar aşkar edildi:")
            for alert in anomalies:
                print(f"  {alert['severity']}: {alert['description']}")
        
        time.sleep(interval_minutes * 60)

# Monitorinqi işə sal
continuous_monitoring(analyzer)
```

## 📈 Statistik Təhlil

### Aşkarlama Effektivliyi
```python
def detection_effectiveness(anomalies):
    """Aşkarlama statistikalarının hesablanması"""
    severity_counts = {
        'HIGH': 0,
        'MEDIUM': 0, 
        'LOW': 0
    }
    
    alert_types = {}
    
    for alert in anomalies:
        severity = alert['severity']
        alert_type = alert['alert_type']
        
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        alert_types[alert_type] = alert_types.get(alert_type, 0) + 1
    
    return {
        'total_alerts': len(anomalies),
        'severity_distribution': severity_counts,
        'alert_type_distribution': alert_types
    }
```

### Trend Analizi
```python
def anomaly_trend_analysis(historical_anomalies):
    """Anomaliyaların zamanla dəyişmə trendi"""
    trends = []
    
    for anomalies in historical_anomalies:
        stats = detection_effectiveness(anomalies)
        trends.append({
            'timestamp': datetime.now(),
            'total_alerts': stats['total_alerts'],
            'high_severity': stats['severity_distribution']['HIGH']
        })
    
    return trends
```

## 🚀 Performans Optimizasiyaları

### 1. Parallel Aşkarlama
```python
from concurrent.futures import ThreadPoolExecutor

def parallel_detection(analyzer):
    """Paralel anomaliya aşkarlama"""
    with ThreadPoolExecutor() as executor:
        results = []
        results.append(executor.submit(analyzer._detect_volume_anomalies))
        results.append(executor.submit(analyzer._detect_suspicious_domains))
        results.append(executor.submit(analyzer._detect_temporal_anomalies))
        results.append(executor.submit(analyzer._detect_protocol_anomalies))
        
        alerts = []
        for future in results:
            alerts.extend(future.result())
    
    return alerts
```

### 2. Incremental Aşkarlama
```python
def incremental_detection(analyzer, new_data):
    """Yeni məlumatlar üçün incremental aşkarlama"""
    # Yalnız yeni məlumatları işlə
    # Köhnə nəticələri cache-lə
    pass
```

## 🔧 Tənzimlənə Bilən Parametrlər

### Hədd Tənzimləməsi
```python
# Real-time hədd tənzimləməsi
def adjust_detection_thresholds(analyzer, current_load):
    """Yükə görə aşkarlama həddlərini tənzimləmə"""
    if current_load > 1000:  # Yüksək yük
        analyzer.volume_threshold *= 1.5
        analyzer.entropy_threshold += 0.2
    else:  # Normal yük
        analyzer.volume_threshold = 100
        analyzer.entropy_threshold = 4.0
```

### Aşkarlama Seçimləri
```python
# Müxtəlif aşkarlama metodlarını aktiv/deaktiv etmək
detection_config = {
    'enable_volume_detection': True,
    'enable_domain_detection': True, 
    'enable_temporal_detection': True,
    'enable_protocol_detection': False
}
```

## 💡 Əlavə Qeydlər

### 1. False Positive Aradan Qaldırma
```python
def filter_false_positives(alerts, whitelist):
    """Ağ siyahı əsasında false positive'ləri filtrlə"""
    filtered = []
    for alert in alerts:
        if alert['source_ip'] not in whitelist:
            filtered.append(alert)
    return filtered
```

### 2. Machine Learning İnteqrasiyası
```python
# ML əsaslı anomaliya aşkarlama
def ml_enhanced_detection(analyzer, ml_model):
    """ML modeli ilə gelişmiş aşkarlama"""
    # Ənənəvi aşkarlama
    traditional_alerts = analyzer.detect_anomalies()
    
    # ML əsaslı aşkarlama
    ml_alerts = ml_model.predict(analyzer.df)
    
    return traditional_alerts + ml_alerts
```

### 3. Real-time Adaptasiya
```python
# Dinamik aşkarlama strategiyası
def adaptive_detection_strategy(analyzer, network_conditions):
    """Şəbəkə vəziyyətinə görə aşkarlama strategiyasını tənzimlə"""
    if network_conditions['is_peak_hours']:
        # Qısamüddətli aşkarlama
        return analyzer._detect_volume_anomalies() + analyzer._detect_temporal_anomalies()
    else:
        # Tam aşkarlama
        return analyzer.detect_anomalies()
```

---

**Növbəti:** [04. DNS Analyzer Modulu - volume analysis](/doc/core/04_dns_analyzer/04_volume_analysis.md)

Bu sənəd `detect_anomalies` metodunun detallı işləmə prinsipini izah edir. Növbəti sənəddə həcm analizi metoduna keçəcəyik.
