# 04. DNS Analyzer Modulu - DNSAnalyzer Class

## 📋 `DNSAnalyzer` Sinfinin Təyinatı

`DNSAnalyzer` sinfi DNS məlumatlarının təhlili və C2 aşkarlama üçün əsas analiz motorudur. Bu sinif müxtəlif statistik və anomalya aşkarlama alqoritmlərini həyata keçirir.

## 🏗️ Sinif Strukturu

```python
class DNSAnalyzer:
    """
    Professional DNS analysis engine for C2 beacon detection
    with enhanced algorithms and statistical analysis
    """
```

## 🔧 Konstruktor Metodu

### `__init__(self, config: Dict = None)`

**Vəzifəsi:** DNS analizatorunun ilkin konfiqurasiyasını və data strukturlarını hazırlamaq

**Parametrlər:**
- `config` (Dict): Konfiqurasiya parametrləri (default: None)

**Daxili İşləmə:**

#### 1. Konfiqurasiyanın Təyin Edilməsi
```python
self.config = config or {}
self.thresholds = self.config.get('alert_thresholds', {})
```

**Funksiya:** Konfiqurasiya parametrlərini yükləyir

**Default Struktur:**
```json
{
  "alert_thresholds": {
    "dns_queries_per_minute": 100,
    "unusual_domain_length": 50,
    "entropy_threshold": 4.0
  }
}
```

#### 2. Həddlərin Təyin Edilməsi
```python
self.entropy_threshold = self.thresholds.get('entropy_threshold', 4.0)
self.volume_threshold = self.thresholds.get('dns_queries_per_minute', 100)
self.length_threshold = self.thresholds.get('unusual_domain_length', 50)
```

**Hədd Parametrləri:**
- `entropy_threshold`: Şübhəli domainlər üçün entropiya həddi (4.0)
- `volume_threshold`: Həddən artıq sorğu sayı (100/dəqiqə)
- `length_threshold`: Qeyri-adi uzunluqda domainlər (50 xarakter)

#### 3. Data Strukturlarının İnitializasiyası
```python
# Data structures for analysis
self.host_query_count = defaultdict(int)
self.host_unique_domains = defaultdict(set)
self.domain_lengths = []
self.query_types_count = defaultdict(int)
self.host_temporal_patterns = defaultdict(list)

# Statistics and baselines
self.avg_query_volume = 0
self.avg_domain_length = 0
self.start_time = datetime.now()
```

**Data Strukturlarının İzahı:**

| Struktur | Tip | Təsvir |
|----------|-----|---------|
| `host_query_count` | `defaultdict(int)` | Hər hostun sorğu sayı |
| `host_unique_domains` | `defaultdict(set)` | Hər hostun sorğu etdiyi unikal domainlər |
| `domain_lengths` | `List[int]` | Bütün domainlərin uzunluqları |
| `query_types_count` | `defaultdict(int)` | Sorğu növlərinin sayı |
| `host_temporal_patterns` | `defaultdict(list)` | Hər hostun sorğu zamanları |

#### 4. Statistik Dəyişənlər
```python
# Statistics and baselines
self.avg_query_volume = 0
self.avg_domain_length = 0
self.start_time = datetime.now()
```

**Statistik Dəyişənlər:**
- `avg_query_volume`: Orta sorğu sayı hosta görə
- `avg_domain_length`: Orta domain uzunluğu
- `start_time`: Analizin başlama zamanı

## 📊 Sinif Atributları

### Konfiqurasiya Parametrləri
```python
self.config: Dict  # Ümumi konfiqurasiya
self.thresholds: Dict  # Xəbərdarlıq həddləri
```

### Aşkarlama Həddləri
```python
self.entropy_threshold: float  # Entropiya həddi (4.0)
self.volume_threshold: int     # Sorğu həcmi həddi (100/dəq)
self.length_threshold: int     # Domain uzunluq həddi (50)
```

### Data Kolleksiyaları
```python
self.host_query_count: DefaultDict[str, int]
self.host_unique_domains: DefaultDict[str, Set[str]]
self.domain_lengths: List[int]
self.query_types_count: DefaultDict[str, int]
self.host_temporal_patterns: DefaultDict[str, List[datetime]]
```

### Statistik Ölçmələr
```python
self.avg_query_volume: float   # Orta sorğu sayı
self.avg_domain_length: float  # Orta domain uzunluğu
self.start_time: datetime      # Analizin başlama zamanı
```

## 🎯 İlkin Vəziyyət

Konstruktor işini bitirdikdən sonra:

```python
analyzer = DNSAnalyzer(config)

print(analyzer.entropy_threshold)  # 4.0
print(analyzer.volume_threshold)   # 100
print(analyzer.length_threshold)   # 50

print(len(analyzer.host_query_count))  # 0
print(len(analyzer.domain_lengths))    # 0
```

## ⚠️ Xəta Əlaqələndirmə

Konstruktor aşağıdakı xətaları idarə edir:

1. **Konfiqurasiya xətaları** - Default dəyərlərlə işləyir
2. **Data tipi xətaları** - Type conversion problemləri
3. **Yaddaş xətaları** - Data strukturlarının yaradılması

**Xəta handling strategiyası:** Səssizcə default dəyərlər istifadə edir

## 🚀 İstifadə Nümunələri

### Əsas İstifadə
```python
# Konfiqurasiya ilə
config = {
    "alert_thresholds": {
        "dns_queries_per_minute": 150,
        "unusual_domain_length": 60,
        "entropy_threshold": 4.2
    }
}

analyzer = DNSAnalyzer(config)

# Default konfiqurasiya ilə
analyzer = DNSAnalyzer()  # config=None
```

### Konfiqurasiya Validasiyası
```python
# Həddləri yoxlamaq
print(f"Entropiya həddi: {analyzer.entropy_threshold}")
print(f"Həcm həddi: {analyzer.volume_threshold}/dəq")
print(f"Uzunluq həddi: {analyzer.length_threshold} xarakter")

# Data strukturlarını yoxlamaq
print(f"İlkin host sayı: {len(analyzer.host_query_count)}")
print(f"İlkin domain uzunluqları: {len(analyzer.domain_lengths)}")
```

### Fərdiləşdirilmiş Konfiqurasiya
```python
# Həssas aşkarlama üçün
sensitive_config = {
    "alert_thresholds": {
        "dns_queries_per_minute": 50,      # Daha aşağı hədd
        "unusual_domain_length": 40,       # Daha qısa domainlər
        "entropy_threshold": 3.8          # Daha aşağı entropiya
    }
}

sensitive_analyzer = DNSAnalyzer(sensitive_config)
```

## 🔧 Tənzimlənə Bilən Parametrlər

### Aşkarlama Həddləri
```python
# Həcm əsaslı aşkarlama
analyzer.volume_threshold = 200  # 200 sorğu/dəq

# Domain uzunluğu
analyzer.length_threshold = 70   # 70 xarakterdən uzun domainlər

# Entropiya həddi  
analyzer.entropy_threshold = 4.5 # Daha yüksək entropiya
```

### Real-time Tənzimləmə
```python
# İş zamanı parametrlərin dəyişdirilməsi
def adjust_thresholds_based_on_load(analyzer, current_load):
    """Yükə görə həddləri dinamik tənzimləmə"""
    if current_load > 1000:  # Yüksək yük
        analyzer.volume_threshold *= 1.5
        analyzer.entropy_threshold += 0.2
    else:  Normal yük
        analyzer.volume_threshold = 100
        analyzer.entropy_threshold = 4.0
```

## 💡 Dizayn Prinsipləri

### 1. Bağlanma Prinsipi
```python
# Konfiqurasiya konstruktorda təyin edilir
# Xarici dəyişikliklərə həssas deyil
```

### 2. Default Davranış
```python
# Konfiqurasiya olmadan da işləyir
# Ağıllı default dəyərlər
```

### 3. Genişlənə Bilənlik
```python
# Yeni analiz metodları asanlıqla əlavə edilə bilər
# Data strukturları modul əsaslıdır
```

### 4. Performans Optimizasiyası
```python
# Səmərəli data strukturları (defaultdict, set)
# O(1) əməliyyat mürəkkəbliyi
```

## 📈 İlkin Hazırlıq Metrikleri

Konstruktor işini bitirdikdən sonra sistem aşağıdaki vəziyyətdə olur:

```python
# Yaddaş istifadəsi: ~1-2MB
# CPU istifadəsi: minimal
# Hazırlıq vaxtı: < 10ms

# Data strukturları boş, lakin optimallaşdırılıb
# Həddlər təyin edilib
# Statistik dəyişənlər initialize edilib
```

---

**Növbəti:** [04. DNS Analyzer Modulu - entropy calculation](/doc/core/04_dns_analyzer/02_entropy_calculation.md)

Bu sənəd `DNSAnalyzer` sinfinin konstruktor metodunun detallı işləmə prinsipini izah edir. Növbəti sənəddə entropiya hesablama metoduna keçəcəyik.
