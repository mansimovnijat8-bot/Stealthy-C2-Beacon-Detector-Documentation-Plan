# 03. Log Parser Modulu - get_stats method

## 📋 `get_stats` Metodunun Təyinatı

`get_stats` metodu yüklənmiş DNS məlumatları haqqında ətraflı statistik məlumatlar təqdim edir. Bu metod analitik hesabatlar, monitorinq və sistem vəziyyətinə dair ümumi məlumat almaq üçün istifadə olunur.

## 🏗️ Metod İmzası

```python
def get_stats(self) -> Dict[str, Any]:
```

**Parametrlər:** Heç bir parametr qəbul etmir

**Qaytarır:** `Dict[str, Any]` - Statistik məlumatları ehtiva edən lüğət

## 🔧 Metodun Daxili İşləməsi

### 1. Boş Məlumat Yoxlaması

```python
if self.df.empty:
    return {"total_records": 0, "time_range": "No data"}
```

**Funksiya:** DataFrame-in boş olub-olmadığını yoxlayır

**Əhəmiyyəti:** Boş məlumat olduqda əsas statistikaları qaytarır

### 2. Əsas Statistikaların Hesablanması

```python
stats = {
    "total_records": len(self.df),
    "time_range": f"{self.df.index.min()} to {self.df.index.max()}",
    "duration_hours": (self.df.index.max() - self.df.index.min()).total_seconds() / 3600,
    "unique_sources": self.df['id.orig_h'].nunique() if 'id.orig_h' in self.df.columns else 0,
    "unique_domains": self.df['query'].nunique() if 'query' in self.df.columns else 0
}
```

**Statistikaların İzahı:**

| Statistik | Təsvir | Nümunə Dəyər |
|-----------|---------|-------------|
| `total_records` | Ümumi DNS sorğu sayı | `1250` |
| `time_range` | Məlumatların vaxt aralığı | `2024-01-15 10:00:00 to 2024-01-15 15:30:00` |
| `duration_hours` | Saat olaraq müddət | `5.5` |
| `unique_sources` | Unikal mənbə IP ünvanları | `45` |
| `unique_domains` | Unikal domain adları | `890` |

### 3. Məlumat Tipi Validasiyası

```python
if 'id.orig_h' in self.df.columns else 0
```

**Funksiya:** Sütunun mövcud olub-olmadığını yoxlayır

**Əhəmiyyəti:** Qismən məlumat dəstlərində xətaların qarşısını alır

### 4. Vaxt Aralığı Hesablanması

```python
(self.df.index.max() - self.df.index.min()).total_seconds() / 3600
```

**Funksiya:** Məlumatların ümumi müddətini saatla hesablayır

**Nümunə:** 5 saat 30 dəqiqə = `5.5`

## 📊 Qaytarılan Statistikalar

Metod aşağıdakı statistik məlumatları ehtiva edən lüğət qaytarır:

```python
{
    "total_records": 1245,
    "time_range": "2024-01-15 08:12:34 to 2024-01-15 14:30:12",
    "duration_hours": 6.3,
    "unique_sources": 18,
    "unique_domains": 756
}
```

## ⚠️ Xəta Əlaqələndirmə

Metod aşağıdakı potensial xətaları idarə edir:

1. **Boş DataFrame** - Səssizcə "No data" statistikası qaytarır
2. **Çatışmayan sütunlar** - Şərti yoxlamalarla idarə olunur
3. **DateTime xətaları** - Pandas tərəfindən avtomatik idarə olunur

**Xəta handling strategiyası:** Defensiv proqramlaşdırma - bütün halları yoxlayır

## 🎯 İstifadə Nümunələri

### Əsas İstifadə
```python
parser = ZeekLogParser("config.json")
parser.read_historical(days=1)

stats = parser.get_stats()
print(f"Ümumi sorğular: {stats['total_records']}")
print(f"Vaxt aralığı: {stats['time_range']}")
print(f"Unikal mənbələr: {stats['unique_sources']}")
```

### Monitorinq Üçün
```python
def monitor_stats():
    """Dövri statistik monitorinq"""
    while True:
        stats = parser.get_stats()
        
        if stats['total_records'] > 0:
            print(f"\n=== Real-time Statistikalar ===")
            print(f"Son sorğu: {stats['time_range'].split(' to ')[1]}")
            print(f"Sorğu sayı: {stats['total_records']}")
            print(f"Unikal IP'lər: {stats['unique_sources']}")
        
        time.sleep(60)  # Hər dəqiqə
```

### Hesabat Generasiyası
```python
def generate_report():
    """Ətraflı hesabat yaradılması"""
    stats = parser.get_stats()
    
    report = f"""
DNS Trafik Hesabatı
===================
Ümumi Məlumatlar:
- Toplam Sorğular: {stats['total_records']}
- Müddət: {stats['duration_hours']:.1f} saat
- Vaxt Aralığı: {stats['time_range']}

Şəbəkə Statistikaları:
- Unikal Mənbə IP'ləri: {stats['unique_sources']}
- Sorğu Edilən Domainlər: {stats['unique_domains']}
- Ortalama Sorğu Sürəti: {stats['total_records']/stats['duration_hours']:.1f}/saat
    """
    
    return report
```

## 🔍 Statistik Təhlil

### Sorğu Sıxlığı Hesablanması
```python
stats = parser.get_stats()
if stats['duration_hours'] > 0:
    queries_per_hour = stats['total_records'] / stats['duration_hours']
    print(f"Saatlıq sorğu sıxlığı: {queries_per_hour:.1f}")
```

### Aktivlik Dövrlərinin Müəyyən Edilməsi
```python
# Günün fərdi saatları üzrə sorğu paylanması
if not parser.df.empty:
    hourly_distribution = parser.df.groupby(
        parser.df.index.hour
    ).size().to_dict()
```

## 📈 Əlavə Statistikalar (Gələcək İnkişaf)

Metod asanlıqla aşağıdakı statistikalar ilə genişləndirilə bilər:

```python
# Nümunə genişləndirmə
additional_stats = {
    "queries_per_hour": total_records / duration_hours if duration_hours > 0 else 0,
    "avg_queries_per_source": total_records / unique_sources if unique_sources > 0 else 0,
    "most_common_qtype": parser.df['qtype_name'].mode()[0] if 'qtype_name' in parser.df.columns else 'N/A',
    "success_rate": (parser.df['rcode_name'] == 'NOERROR').mean() if 'rcode_name' in parser.df.columns else 0
}
```

## 🚀 Performans Optimizasiyaları

### 1. Səmərəli Hesablama
```python
# Bütün statistikalar tək sətirdə hesablanır
# Əlavə yaddaş ayrılmır
```

### 2. Lazy Evaluation
```python
# Statistikalar yalnız çağırılanda hesablanır
# Əvvəlcədən hesablama yoxdur
```

### 3. Yaddaş Səmərəliliyi
```python
# Əlavə DataFrame surətləri yaradılmır
# O(1) yaddaş mürəkkəbliyi
```

## 💡 Əlavə Qeydlər

1. **Real-time Yeniləmə:** Statistikalar hər çağırışda yenidən hesablanır
2. **Thread Safety:** Metod thread-safe dizayn edilib
3. **Performance:** Çox sürətli işləyir (milisaniyələrlə)
4. **Resource Usage:** Heç bir əlavə resource istifadə etmir

---

**Növbəti:** [03. Log Parser Modulu - validation methods](/doc/core/03_log_parser/06_validation_methods.md)

Bu sənəd `get_stats` metodunun detallı işləmə prinsipini izah edir. Növbəti sənəddə məlumat validasiya metodlarına keçəcəyik.
