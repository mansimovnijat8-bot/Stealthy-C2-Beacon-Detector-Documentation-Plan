# 05. Detector Modulu - reporting system

## 📋 `generate_final_report` Metodunun Təyinatı

`generate_final_report` metodu C2 aşkarlama sisteminin işləməsi boyunca toplanan bütün məlumatları əhatə edən ətraflı son hesabat yaradır. Bu hesabat performans göstəriciləri, aşkarlanan təhdidlər və statistik məlumatları ehtiva edir.

## 🏗️ Metod İmzası

```python
def generate_final_report(self):
```

**Parametrlər:** Heç bir parametr qəbul etmir

**Qaytarır:** `None` - Hesabat birbaşa çıxışa göndərilir

## 🔧 Metodun Daxili İşləməsi

### 1. Hesabatın Başladılması

```python
duration = (datetime.now() - self.start_time).total_seconds() / 60
```

**Funksiya:** Ümumi işləmə müddətini hesablayır

**Çıxış:** Dəqiqə ilə müddət (float)

### 2. Ümumi Statistikaların Çap Edilməsi

```python
print("\n" + "═" * 80)
print("📊 PROFESSIONAL C2 DETECTION - COMPREHENSIVE REPORT")
print("═" * 80)
        
print(f"\nMonitoring Duration: {duration:.1f} minutes")
print(f"Total Alerts Generated: {self.alert_count}")
```

**Format:** Professional konsol çıxışı

**Statistikalar:**
- Ümumi monitorinq müddəti
- Yaradılan xəbərdarlıqların ümumi sayı

### 3. Risk Səviyyəsi Paylanması

```python
high_alerts = [a for a in self.alerts if a['severity'] == 'HIGH']
medium_alerts = [a for a in self.alerts if a['severity'] == 'MEDIUM']
low_alerts = [a for a in self.alerts if a['severity'] == 'LOW']

print(f"\nSeverity Breakdown:")
print(f"  HIGH: {len(high_alerts)} alerts")
print(f"  MEDIUM: {len(medium_alerts)} alerts") 
print(f"  LOW: {len(low_alerts)} alerts")
```

**Risk Səviyyələri:**
- **HIGH**: Yüksək riskli xəbərdarlıqlar
- **MEDIUM**: Orta riskli xəbərdarlıqlar  
- **LOW**: Aşağı riskli xəbərdarlıqlar

### 4. Top Mənbə Analizi

```python
source_counts = {}
for alert in self.alerts:
    source = alert.get('source_ip', 'unknown')
    source_counts[source] = source_counts.get(source, 0) + 1

if source_counts:
    print(f"\nTop Alerting Sources:")
    for source, count in sorted(source_counts.items(), 
                              key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {source}: {count} alerts")
```

**Analiz:** Ən çox xəbərdarlıq yaradan ilk 5 IP ünvanı

### 5. Xəbərdarlıq Növü Paylanması

```python
alert_types = {}
for alert in self.alerts:
    alert_type = alert['alert_type']
    alert_types[alert_type] = alert_types.get(alert_type, 0) + 1

if alert_types:
    print(f"\nAlert Types Distribution:")
    for alert_type, count in alert_types.items():
        print(f"  {alert_type}: {count}")
```

**Paylanma:** Müxtəlif xəbərdarlıq növlərinin sayı

### 6. Fayl Çıxış Məlumatları

```python
print(f"\nDetailed alerts saved to: data/alerts/c2_alerts.json")
print(f"Log file: data/logs/c2_detector.log")
print("═" * 80)
```

**Fayl Yolları:**
- Xəbərdarlıq faylı: `data/alerts/c2_alerts.json`
- Log faylı: `data/logs/c2_detector.log`

## 📊 Hesabat Nümunəsi

### Tam Hesabat Çıxışı

```
════════════════════════════════════════════════════════════════════════════════
📊 PROFESSIONAL C2 DETECTION - COMPREHENSIVE REPORT
════════════════════════════════════════════════════════════════════════════════

Monitoring Duration: 125.5 minutes
Total Alerts Generated: 42

Severity Breakdown:
  HIGH: 15 alerts
  MEDIUM: 18 alerts
  LOW: 9 alerts

Top Alerting Sources:
  192.168.1.105: 12 alerts
  192.168.1.110: 8 alerts
  192.168.1.120: 5 alerts
  192.168.1.130: 3 alerts
  192.168.1.140: 2 alerts

Alert Types Distribution:
  HIGH_DNS_VOLUME: 15
  DNS_BEACONING: 10
  HIGH_ENTROPY_DOMAINS: 8
  LONG_DOMAINS: 5
  UNUSUAL_DNS_TYPES: 4

Detailed alerts saved to: data/alerts/c2_alerts.json
Log file: data/logs/c2_detector.log
════════════════════════════════════════════════════════════════════════════════
```

## 🎯 İstifadə Nümunələri

### Əsas İstifadə

```python
# Əsas hesabat generasiyası
detector.generate_final_report()

# Fayla yazmaq üçün
def save_report_to_file(detector, filename="final_report.txt"):
    """Hesabatı fayla yaz"""
    import sys
    from io import StringIO
    
    # Çıxışı yönləndir
    old_stdout = sys.stdout
    sys.stdout = captured_output = StringIO()
    
    # Hesabatı generasiya et
    detector.generate_final_report()
    
    # Çıxışı bərpa et
    sys.stdout = old_stdout
    
    # Fayla yaz
    with open(filename, 'w') as f:
        f.write(captured_output.getvalue())
    
    print(f"Hesabat {filename} faylına yazıldı")

save_report_to_file(detector)
```

### Ətraflı Statistik Analiz

```python
def detailed_statistical_analysis(detector):
    """Hesabat üzərində ətraflı statistik analiz"""
    report_data = {
        'total_duration': (datetime.now() - detector.start_time).total_seconds() / 60,
        'total_alerts': detector.alert_count,
        'alerts_by_severity': {},
        'alerts_by_type': {},
        'top_sources': []
    }
    
    # Risk səviyyəsi üzrə statistikalar
    for severity in ['HIGH', 'MEDIUM', 'LOW']:
        report_data['alerts_by_severity'][severity] = len(
            [a for a in detector.alerts if a['severity'] == severity]
        )
    
    # Xəbərdarlıq növü üzrə statistikalar
    for alert in detector.alerts:
        alert_type = alert['alert_type']
        report_data['alerts_by_type'][alert_type] = report_data['alerts_by_type'].get(alert_type, 0) + 1
    
    # Top mənbələr
    source_counts = {}
    for alert in detector.alerts:
        source = alert.get('source_ip', 'unknown')
        source_counts[source] = source_counts.get(source, 0) + 1
    
    report_data['top_sources'] = sorted(
        source_counts.items(), key=lambda x: x[1], reverse=True
    )[:10]
    
    return report_data

# Statistik analiz
stats = detailed_statistical_analysis(detector)
print(f"Orta xəbərdarlıq dərəcəsi: {stats['total_alerts']/stats['total_duration']:.2f}/dəq")
```

## 🔧 Tənzimlənə Bilən Parametrlər

### Hesabat Konfiqurasiyası

```json
{
  "reporting": {
    "detail_level": "detailed",
    "include_top_sources": 10,
    "include_alert_types": true,
    "include_severity_breakdown": true,
    "output_format": "text",
    "save_to_file": true,
    "file_path": "reports/detection_report.txt"
  }
}
```

### Dinamik Hesabat Formatı

```python
def configure_reporting(detector, options):
    """Hesabat formatını dinamik olaraq tənzimlə"""
    reporting_config = detector.config.get('reporting', {})
    
    if 'detail_level' in options:
        reporting_config['detail_level'] = options['detail_level']
    
    if 'output_format' in options:
        reporting_config['output_format'] = options['output_format']
    
    # Real-time tənzimləmə
    detector.config['reporting'] = reporting_config

# Fərdi hesabat formatı
options = {
    'detail_level': 'summary',
    'output_format': 'json'
}
configure_reporting(detector, options)
```

## 💡 Əlavə Qeydlər

### 1. Müxtəlif Format Dəstəyi

```python
def export_report_multiple_formats(detector):
    """Hesabatı müxtəlif formatlarda eksport et"""
    formats = ['text', 'json', 'html', 'csv']
    
    for format in formats:
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
        
        if format == 'text':
            detector.generate_final_report()
            # ... fayla yazma məntiqi
        elif format == 'json':
            export_json_report(detector, filename)
        elif format == 'html':
            export_html_report(detector, filename)
        elif format == 'csv':
            export_csv_report(detector, filename)
```

### 2. Trend Analizi

```python
def analyze_alert_trends(detector):
    """Xəbərdarlıq trendlərinin təhlili"""
    trends = {
        'alert_rate': detector.alert_count / ((datetime.now() - detector.start_time).total_seconds() / 60),
        'peak_periods': [],
        'common_patterns': []
    }
    
    # Vaxt üzrə paylanma
    hourly_distribution = [0] * 24
    for alert in detector.alerts:
        hour = alert['timestamp'].hour
        hourly_distribution[hour] += 1
    
    trends['hourly_distribution'] = hourly_distribution
    trends['peak_hour'] = hourly_distribution.index(max(hourly_distribution))
    
    return trends
```

### 3. Müqayisəli Hesabatlar

```python
def compare_reports(current_detector, previous_reports):
    """Müxtəlif dövrlər üçün hesabatları müqayisə et"""
    comparison = {
        'current_period': {
            'duration': (datetime.now() - current_detector.start_time).total_seconds() / 60,
            'alerts': current_detector.alert_count
        },
        'previous_periods': [],
        'growth_rates': {}
    }
    
    for prev_report in previous_reports:
        comparison['previous_periods'].append(prev_report)
    
    # Artım dərəcələri
    if previous_reports:
        last_report = previous_reports[-1]
        duration_growth = (comparison['current_period']['duration'] - last_report['duration']) / last_report['duration'] * 100
        alert_growth = (comparison['current_period']['alerts'] - last_report['alerts']) / last_report['alerts'] * 100
        
        comparison['growth_rates'] = {
            'duration': duration_growth,
            'alerts': alert_growth
        }
    
    return comparison
```

---

**Növbəti:** [06. Utils Modulu - logger module](/doc/utils/06_logger_module.md)

Bu sənəd `generate_final_report` metodunun detallı işləmə prinsipini izah edir. Növbəti sənəddə logger moduluna keçəcəyik.
