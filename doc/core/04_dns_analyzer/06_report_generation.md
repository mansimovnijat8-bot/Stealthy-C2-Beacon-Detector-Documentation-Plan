# 04. DNS Analyzer Modulu - report generation

## 📋 `generate_detailed_report` Metodunun Təyinatı

`generate_detailed_report` metodu DNS təhlilinin ətraflı statistik hesabatını yaradır. Bu metod bütün aşkarlama fəaliyyətinin ümumi görünüşünü və performans göstəricilərini təqdim edir.

## 🏗️ Metod İmzası

```python
def generate_detailed_report(self) -> Dict:
```

**Parametrlər:** Heç bir parametr qəbul etmir

**Qaytarır:** `Dict` - Ətraflı hesabat məlumatlarını ehtiva edən lüğət

## 🔧 Metodun Daxili İşləməsi

### 1. Analiz Dövrünün Müəyyən Edilməsi

```python
return {
    'analysis_period': {
        'start_time': self.analysis_start,
        'end_time': datetime.now(),
        'duration_minutes': (datetime.now() - self.analysis_start).total_seconds() / 60
    },
```

**Funksiya:** Təhlilin başlama və bitmə zamanını, ümumi müddətini qeyd edir

**Çıxış Formatı:** 
- `start_time`: Analizin başlama tarixi
- `end_time`: Cari zaman
- `duration_minutes`: Analizin dəqiqə ilə müddəti

### 2. Əsas Metrikaların Hesablanması

```python
'metrics': self.metrics.__dict__,
```

**Funksiya:** DNSMetrics dataclass-ının bütün metrikalarını əks etdirir

**Əsas Metrikalar:**
- `total_queries`: Ümumi DNS sorğu sayı
- `unique_hosts`: Unikal mənbə IP ünvanları
- `unique_domains`: Unikal domain adları
- `avg_queries_per_host`: Hosta düşən orta sorğu sayı
- `query_rate_per_minute`: Dəqiqədə sorğu sayı

### 3. Top Sorğu Edən Hostların Müəyyən Edilməsi

```python
'top_querying_hosts': dict(sorted(
    self.host_query_count.items(), 
    key=lambda x: x[1], 
    reverse=True
)[:10]),
```

**Funksiya:** Ən çox sorğu edən ilk 10 hostu sıralayır

**Çıxış Formatı:** `{'192.168.1.105': 487, '192.168.1.110': 156, ...}`

### 4. Ən Çox İstifadə Edilən Sorğu Növləri

```python
'most_common_query_types': dict(sorted(
    self.query_types_count.items(),
    key=lambda x: x[1],
    reverse=True
)[:5]),
```

**Funksiya:** Ən çox istifadə edilən ilk 5 DNS sorğu növünü sıralayır

**Nümunə Çıxış:** `{'A': 1150, 'AAAA': 85, 'TXT': 15, ...}`

### 5. Şəbəkə Analizi Statistikaları

```python
'network_analysis': {
    'internal_ips_count': len(self.internal_ips),
    'external_ips_count': len(self.external_ips),
    'total_unique_ips': len(self.internal_ips) + len(self.external_ips)
}
```

**Funksiya:** Daxili və xarici IP ünvanlarının statistikasını təqdim edir

**Statistikalar:**
- `internal_ips_count`: Daxili şəbəkə IP sayı
- `external_ips_count`: Xarici şəbəkə IP sayı  
- `total_unique_ips`: Ümumi unikal IP sayı

## 📊 Hesabat Strukturu

### Tam Hesabat Nümunəsi

```python
{
    'analysis_period': {
        'start_time': datetime(2024, 1, 15, 10, 30, 0),
        'end_time': datetime(2024, 1, 15, 11, 30, 0),
        'duration_minutes': 60.0
    },
    'metrics': {
        'total_queries': 1245,
        'unique_hosts': 18,
        'unique_domains': 756,
        'avg_queries_per_host': 69.17,
        'query_rate_per_minute': 20.75
    },
    'top_querying_hosts': {
        '192.168.1.105': 487,
        '192.168.1.110': 156,
        '192.168.1.120': 98,
        ...
    },
    'most_common_query_types': {
        'A': 1150,
        'AAAA': 85,
        'TXT': 10
    },
    'network_analysis': {
        'internal_ips_count': 15,
        'external_ips_count': 3,
        'total_unique_ips': 18
    }
}
```

## 🎯 İstifadə Nümunələri

### Əsas İstifadə

```python
analyzer = DNSAnalyzer(config)
analyzer.process_dns_data(zeek_parser)

report = analyzer.generate_detailed_report()

print(f"Analiz müddəti: {report['analysis_period']['duration_minutes']:.1f} dəqiqə")
print(f"Ümumi sorğular: {report['metrics']['total_queries']}")
print(f"Unikal hostlar: {report['metrics']['unique_hosts']}")
```

### Real-time Monitorinq Üçün

```python
def monitor_analysis_progress(analyzer, interval=300):
    """Analiz irəliləyişinin monitorinqi"""
    while True:
        report = analyzer.generate_detailed_report()
        
        print(f"\n=== Real-time Hesabat ===")
        print(f"Müddət: {report['analysis_period']['duration_minutes']:.1f}d")
        print(f"Sorğu sayı: {report['metrics']['total_queries']}")
        print(f"Sorğu dərəcəsi: {report['metrics']['query_rate_per_minute']:.1f}/dəq")
        
        # Top hostları göstər
        print("\nTop 3 host:")
        for ip, count in list(report['top_querying_hosts'].items())[:3]:
            print(f"  {ip}: {count} sorğu")
        
        time.sleep(interval)
```

### HTML Hesabat Generasiyası

```python
def generate_html_report(report, output_file="report.html"):
    """Hesabatı HTML formatında çıxar"""
    html_template = """
    <html>
    <head><title>DNS Analiz Hesabatı</title></head>
    <body>
        <h1>DNS Trafik Analiz Hesabatı</h1>
        <h2>Analiz Dövrü: {start_time} - {end_time}</h2>
        
        <h3>Əsas Metrikalar</h3>
        <ul>
            <li>Ümumi Sorğular: {total_queries}</li>
            <li>Unikal Hostlar: {unique_hosts}</li>
            <li>Unikal Domainlər: {unique_domains}</li>
            <li>Sorğu Dərəcəsi: {query_rate}/dəq</li>
        </ul>
    </body>
    </html>
    """
    
    # Template-i doldur
    html_content = html_template.format(
        start_time=report['analysis_period']['start_time'],
        end_time=report['analysis_period']['end_time'],
        total_queries=report['metrics']['total_queries'],
        unique_hosts=report['metrics']['unique_hosts'],
        unique_domains=report['metrics']['unique_domains'],
        query_rate=report['metrics']['query_rate_per_minute']
    )
    
    with open(output_file, 'w') as f:
        f.write(html_content)
```

## 📈 Statistik Təhlil

### Performans Metrikaları

```python
def calculate_performance_metrics(report):
    """Hesabat əsasında performans metrikalarının hesablanması"""
    metrics = report['metrics']
    period = report['analysis_period']
    
    return {
        'queries_per_minute': metrics['total_queries'] / period['duration_minutes'],
        'queries_per_host': metrics['total_queries'] / metrics['unique_hosts'],
        'domains_per_host': metrics['unique_domains'] / metrics['unique_hosts'],
        'internal_traffic_ratio': report['network_analysis']['internal_ips_count'] / 
                                 report['network_analysis']['total_unique_ips']
    }
```

### Trend Analizi

```python
def analyze_trends(historical_reports):
    """Tarixi hesabatlara əsasən trend analizi"""
    trends = {
        'query_growth': [],
        'host_growth': [],
        'domain_growth': []
    }
    
    for report in historical_reports:
        metrics = report['metrics']
        trends['query_growth'].append(metrics['total_queries'])
        trends['host_growth'].append(metrics['unique_hosts'])
        trends['domain_growth'].append(metrics['unique_domains'])
    
    return trends
```

## 🚀 Performans Optimizasiyaları

### 1. Səmərəli Data Strukturları

```python
# Dataclass istifadəsi ilə sürətli giriş
# Sorted dict ilə sürətli çeşidləmə
# Generator expressions ilə yaddaş səmərəliliyi
```

### 2. Lazy Evaluation

```python
# Hesabat yalnız çağırılanda generasiya olunur
# Əvvəlcədən hesablama yoxdur
```

### 3. Minimal Resource İstifadəsi

```python
# Yeni data strukturları yaradılmır
# Mövcud məlumatların referansları istifadə olunur
```

## 🔧 Tənzimlənə Bilən Parametrlər

### Hesabat Konfiqurasiyası

```python
report_config = {
    'top_hosts_count': 10,      # Göstəriləcək host sayı
    'top_query_types_count': 5, # Göstəriləcək sorğu növü sayı
    'include_network_stats': True,
    'include_temporal_stats': True,
    'output_format': 'json'     # 'json', 'html', 'text'
}
```

### Dinamik Hesabat Seçimləri

```python
def generate_custom_report(analyzer, options):
    """Fərdiləşdirilmiş hesabat generasiyası"""
    base_report = analyzer.generate_detailed_report()
    custom_report = {}
    
    if options.get('include_basic_metrics', True):
        custom_report['metrics'] = base_report['metrics']
    
    if options.get('include_top_hosts', True):
        custom_report['top_hosts'] = base_report['top_querying_hosts']
    
    return custom_report
```

## 💡 Əlavə Qeydlər

### 1. Eksport Funksionallığı

```python
def export_report(report, format='json'):
    """Hesabatı müxtəlif formatlarda eksport et"""
    if format == 'json':
        return json.dumps(report, default=str, indent=2)
    elif format == 'csv':
        return convert_to_csv(report)
    elif format == 'html':
        return generate_html_report(report)
    else:
        return str(report)
```

### 2. Müqayisəli Analiz

```python
def compare_reports(current_report, previous_report):
    """İki hesabatı müqayisə et"""
    comparison = {
        'query_growth': current_report['metrics']['total_queries'] - 
                       previous_report['metrics']['total_queries'],
        'host_growth': current_report['metrics']['unique_hosts'] - 
                      previous_report['metrics']['unique_hosts'],
        'growth_rate': calculate_growth_rate(current_report, previous_report)
    }
    return comparison
```

### 3. Real-time Dashboard

```python
def create_live_dashboard(analyzer, update_interval=60):
    """Canlı monitorinq dashboardu"""
    import matplotlib.pyplot as plt
    
    while True:
        report = analyzer.generate_detailed_report()
        
        # Real-time qrafiklər
        update_dashboard_visualizations(report)
        
        time.sleep(update_interval)
```

---

**Növbəti:** [05. Detector Modulu - C2Detector Class](/doc/core/05_detector/01_C2Detector_Class.md)

Bu sənəd `generate_detailed_report` metodunun detallı işləmə prinsipini izah edir. Növbəti sənəddə əsas C2Detector sinfinin təyinatına keçəcəyik.
