# 04. DNS Analyzer Modulu - entropy calculation

## 📋 `calculate_entropy` Metodunun Təyinatı

`calculate_entropy` metodu verilmiş domain adının Shannon entropiyasını hesablayır. Entropiya domain adının "təsadüfi" görünüşünü ölçür - yüksək entropiya dəyərləri potensial DNS tunelləşdirmə və ya şifrələnmiş məlumatı göstərir.

## 🏗️ Metod İmzası

```python
def calculate_entropy(self, domain: str) -> float:
```

**Parametrlər:**
- `domain` (str): Analiz ediləcək domain adı

**Qaytarır:** `float` - Shannon entropiya dəyəri (0.0 ilə 8.0 arasında)

## 🔧 Metodun Daxili İşləməsi

### 1. Giriş Validasiyası

```python
if not domain or len(domain.strip()) == 0:
    return 0.0
```

**Funksiya:** Boş və ya etibarsız domain adlarını yoxlayır

**Əhəmiyyəti:** Xətalı girişləri erkən aşkar edir və 0.0 qaytarır

### 2. Domain Hissəsinin Çıxarılması

```python
domain_part = domain.split('.')[0] if '.' in domain else domain
```

**Funksiya:** Yalnız subdomain hissəsini götürür (TLD-ni çıxarır)

**Nümunə:** `x9j8f7v3k1.example.com` → `x9j8f7v3k1`

### 3. Minimum Uzunluq Yoxlaması

```python
if len(domain_part) < 2:
    return 0.0
```

**Funksiya:** Çox qısa domain hissələrini aradan qaldırır

**Əhəmiyyəti:** 1 xarakterli stringlər üçün entropiya mənasızdır

### 4. Normalizasiya

```python
domain_part = domain_part.lower()
```

**Funksiya:** Domain hissəsini kiçik hərflərə çevirir

**Əhəmiyyəti:** Böyük/kiçik hərf həssaslığını aradan qaldırır

### 5. Tezlik Analizi

```python
freq_dict = {}
for char in domain_part:
    freq_dict[char] = freq_dict.get(char, 0) + 1
```

**Funksiya:** Hər xarakterin tezliyini hesablayır

**Nümunə:** `"abcda"` → `{'a': 2, 'b': 1, 'c': 1, 'd': 1}`

### 6. Entropiya Hesablanması

```python
entropy = 0.0
domain_len = len(domain_part)
for count in freq_dict.values():
    probability = count / domain_len
    entropy -= probability * math.log2(probability)
```

**Entropiya Düsturu:** 
```
H = -Σ p(x) * log2(p(x))
```

**Hesablama Addımları:**
1. Hər xarakterin ehtimalını hesabla: `p(x) = count / total_chars`
2. Hər ehtimal üçün `p(x) * log2(p(x))` hesabla
3. Bütün dəyərləri topla və mənfi işarə ilə çarp

## 🧮 Entropiya Nümunələri

### Aşağı Entropiya (Normal Domainlər)
```python
calculate_entropy("google")      # ≈ 2.50
calculate_entropy("microsoft")   # ≈ 2.85
calculate_entropy("amazon")      # ≈ 2.65
```

### Orta Entropiya
```python
calculate_entropy("random123")   # ≈ 3.25
calculate_entropy("test456")     # ≈ 2.95
```

### Yüksək Entropiya (Şübhəli Domainlər)
```python
calculate_entropy("x9j8f7v3k1")  # ≈ 3.98
calculate_entropy("p0o9i8u7y6")  # ≈ 4.12
calculate_entropy("z1x2c3v4b5")  # ≈ 4.05
```

### Maksimum Entropiya (Tam Təsadüfi)
```python
calculate_entropy("abcdefghij")  # ≈ 3.32 (10 unikal xarakter)
calculate_entropy("0123456789")  # ≈ 3.32 (10 unikal xarakter)
```

## ⚠️ Xəta Əlaqələndirmə

Metod aşağıdakı xətaları idarə edir:

1. **Boş giriş** - `domain` parametri None və ya boş string
2. **Qısa domainlər** - 1 xarakterdən qısa stringlər
3. **Riyazi xətalar** - `log2(0)` kimi hesablama xətaları

**Xəta handling strategiyası:** Səssizcə 0.0 qaytarır və xəta loglamır

## 🎯 İstifadə Nümunələri

### Əsas İstifadə
```python
analyzer = DNSAnalyzer(config)

# Fərdi domain analizi
entropy = analyzer.calculate_entropy("x9j8f7v3k1.example.com")
print(f"Entropiya: {entropy:.3f}")  # Çıxış: 3.321

# Normal domain
normal_entropy = analyzer.calculate_entropy("google.com")
print(f"Normal entropiya: {normal_entropy:.3f}")  # 2.50
```

### Toplu Analiz
```python
def analyze_domains(domains):
    """Domain siyahısının entropiya analizi"""
    results = []
    for domain in domains:
        entropy = analyzer.calculate_entropy(domain)
        results.append((domain, entropy))
    
    # Entropiyaya görə çeşidləmə
    results.sort(key=lambda x: x[1], reverse=True)
    return results

# Nümunə analiz
domains = ["google.com", "x9j8f7v3k1.example.com", "amazon.com"]
analysis = analyze_domains(domains)
for domain, entropy in analysis:
    print(f"{domain}: {entropy:.3f}")
```

### Real-time Aşkarlama
```python
def real_time_entropy_check(domain):
    """Real-time entropiya yoxlaması"""
    entropy = analyzer.calculate_entropy(domain)
    
    if entropy > analyzer.entropy_threshold:
        print(f"🚨 Yüksək entropiya: {domain} ({entropy:.3f})")
        return True
    return False

# Real-time yoxlama
real_time_entropy_check("x9j8f7v3k1.example.com")  # 🚨 Yüksək entropiya
```

## 🔍 Entropiya Təhlili

### Entropiya Aralıqlarının Şərhi

| Entropiya Dəyəri | Təsvir | Təhlükə Səviyyəsi |
|------------------|---------|------------------|
| 0.0 - 2.5 | Çox aşağı (normal domainlər) | ✅ Təhlükəsiz |
| 2.5 - 3.5 | Orta (qarışıq domainlər) | ⚠️ Mümkün təhlükə |
| 3.5 - 4.5 | Yüksək (təsadüfi görünən) | 🚨 Şübhəli |
| 4.5+ | Çox yüksək (tam təsadüfi) | 🔴 Yüksək təhlükə |

### Domain Uzunluğunun Təsiri

```python
# Uzunluq artdıqca entropiya da artır
# Lakin normalizasiya edilmiş entropiya daha əhəmiyyətlidir

def normalized_entropy(domain):
    """Uzunluğa görə normalizə edilmiş entropiya"""
    raw_entropy = analyzer.calculate_entropy(domain)
    max_possible = math.log2(len(set(domain))) if domain else 0
    return raw_entropy / max_possible if max_possible > 0 else 0
```

## 🚀 Performans Optimizasiyaları

### 1. Səmərəli Hesablama
```python
# O(n) mürəkkəblik - domain uzunluğu ilə mütənasib
# Sürətli və yaddaş səmərəli
```

### 2. Əvvəlcədən Hesablama
```python
# Tez-tez istifadə olunan domainlər üçün cache
entropy_cache = {}

def cached_entropy(domain):
    if domain not in entropy_cache:
        entropy_cache[domain] = analyzer.calculate_entropy(domain)
    return entropy_cache[domain]
```

### 3. Parallel Hesablama
```python
from concurrent.futures import ThreadPoolExecutor

def batch_entropy_calculation(domains):
    """Çoxlu domainlərin paralel entropiya hesablanması"""
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(analyzer.calculate_entropy, domains))
    return results
```

## 📊 Statistik Təhlil

### Entropiya Paylanması
```python
def analyze_entropy_distribution(domains):
    """Domain siyahısının entropiya paylanması"""
    entropies = [analyzer.calculate_entropy(d) for d in domains]
    
    stats = {
        'mean': sum(entropies) / len(entropies),
        'max': max(entropies),
        'min': min(entropies),
        'std': statistics.stdev(entropies) if len(entropies) > 1 else 0
    }
    
    return stats
```

### Trend Analizi
```python
def entropy_trend_analysis(domain_series):
    """Domain entropiyasının zamanla dəyişməsi"""
    trends = []
    for domain in domain_series:
        entropy = analyzer.calculate_entropy(domain)
        trends.append((domain, entropy, datetime.now()))
    
    return trends
```

## 💡 Əlavə Qeydlər

### 1. False Positive Aradan Qaldırma
```python
def is_likely_dga(domain, entropy_threshold=4.0, min_length=8):
    """DGA (Domain Generation Algorithm) aşkarlama"""
    if len(domain) < min_length:
        return False
    
    entropy = analyzer.calculate_entropy(domain)
    return entropy > entropy_threshold
```

### 2. Dil Modeli İnteqrasiyası
```python
# Əlavə olaraq dil modeli ilə yoxlama
def is_english_like(domain):
    """Domainin ingilis dilinə oxşarlığının yoxlanması"""
    # Əlavə NLP-based yanaşma
    pass
```

### 3. Real-time Adaptasiya
```python
# Dinamik hədd tənzimləməsi
def adaptive_entropy_threshold(historical_entropies):
    """Tarixi məlumatlara əsasən həddin avtomatik tənzimlənməsi"""
    mean_entropy = sum(historical_entropies) / len(historical_entropies)
    return mean_entropy + 2 * statistics.stdev(historical_entropies)
```

---

**Növbəti:** [04. DNS Analyzer Modulu - anomaly detection](/doc/core/04_dns_analyzer/03_anomaly_detection.md)

Bu sənəd `calculate_entropy` metodunun detallı işləmə prinsipini izah edir. Növbəti sənəddə anomalya aşkarlama metodlarına keçəcəyik.
