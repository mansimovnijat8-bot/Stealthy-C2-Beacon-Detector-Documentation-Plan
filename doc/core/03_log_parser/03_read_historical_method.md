# 03. Log Parser Modulu - read_historical method

## 📋 `read_historical` Metodunun Təyinatı

`read_historical` metodu Zeek-in DNS log faylından tarixi məlumatları oxuyur, strukturlaşdırır və analiz üçün hazırlayır. Bu metod proyektin əsas məlumat yükləmə funksionallığını həyata keçirir.

## 🏗️ Metod İmzası

```python
def read_historical(self, days: Optional[int] = None) -> bool:
```

**Parametrlər:**
- `days` (Optional[int]): Neçə günlük tarixi məlumat oxunacaq. `None` olarsa bütün mövcud məlumat oxunur.

**Qaytarır:** `bool` - Əməliyyatın uğurlu olub-olmadığını göstərir

## 🔧 Metodun Daxili İşləməsi

### 1. Fayl Validasiyası

```python
if not self._validate_log_file():
    return False
```

**Funksiya:** Log faylının mövcudluğunu və oxuna bilməsini yoxlayır

**Əhəmiyyəti:** Əgər fayl mövcud deyilsə, metod dərhal `False` qaytarır

### 2. Faylın Oxunması

```python
self.df = pd.read_csv(
    self.dns_log_path, 
    comment='#', 
    sep='\t', 
    names=self.DNS_COLUMNS, 
    low_memory=False,
    na_values=['-'],
    keep_default_na=False
)
```

**Parametrlərin İzahı:**
- `comment='#'`: Zeek şərh sətirlərini (#'lə başlayan) oxuma
- `sep='\t'`: Tab ilə ayrılmış sütunlar
- `names=self.DNS_COLUMNS`: Əvvəlcədən təyin edilmiş sütun adları
- `low_memory=False`: Böyük fayllar üçün yaddaş optimizasiyası
- `na_values=['-']`: '-' işarəsini NaN kimi qiymətləndir
- `keep_default_na=False`: Pandas'ın default NaN dəyərlərini istifadə etmə

### 3. Timestamp Konversiyası

```python
if 'ts' in self.df.columns:
    self.df['ts'] = pd.to_datetime(self.df['ts'], unit='s', errors='coerce')
```

**Funksiya:** Unix timestampləri Python datetime obyektlərinə çevirir

**Parametrlər:**
- `unit='s'`: Saniyə əsaslı timestamplər
- `errors='coerce'`: Xətaları `NaT` (Not a Time) kimi qeyd et

### 4. Məlumat Keyfiyyətinin Yoxlanması

```python
valid_timestamps = self.df['ts'].notna()
if not valid_timestamps.all():
    invalid_count = (~valid_timestamps).sum()
    logger.warning(f"Found {invalid_count} records with invalid timestamps")
    self.df = self.df[valid_timestamps]
```

**Funksiya:** Etibarsız timestampləri filtrləyir və xəbərdarlıq verir

### 5. DataFrame Indexinin Təyin Edilməsi

```python
self.df.set_index('ts', inplace=True)
```

**Funksiya:** Timestamp sütununu DataFrame'in indexi kimi təyin edir

**Əhəmiyyəti:** Vaxt əsaslı sorğular və filtrləmə üçün vacibdir

### 6. Vaxt Pəncərəsi Filtrləməsi

```python
if days is not None:
    cutoff_time = datetime.now() - pd.Timedelta(days=days)
    self.df = self.df[self.df.index >= cutoff_time]
```

**Funksiya:** Müəyyən gün sayına görə məlumatları filtrləyir

### 7. Məlumat Keyfiyyətinin Yoxlanması

```python
self._validate_data_quality()
```

**Funksiya:** Məlumatın tamlığını və keyfiyyətini yoxlayır

## 📊 Məlumat Strukturu

**Oxunan məlumatın nümunə strukturu:**

| ts | id.orig_h | id.resp_h | query | qtype_name | rcode_name |
|----|-----------|-----------|-------|------------|------------|
| 2024-01-15 10:30:00 | 192.168.1.100 | 8.8.8.8 | google.com | A | NOERROR |
| 2024-01-15 10:30:01 | 192.168.1.101 | 1.1.1.1 | example.com | AAAA | NXDOMAIN |

## ⚠️ Xəta Əlaqələndirmə

Metod aşağıdakı xətaları idarə edir:

1. **Fayl oxuma xətaları** - `IOError`, `PermissionError`
2. **Data parsing xətaları** - `pd.errors.ParserError`
3. **Timestamp konversiya xətaları** - `ValueError`
4. **Yaddaş xətaları** - `MemoryError`

**Xəta handling strategiyası:** Hər bir xəta `try-catch` bloku ilə idarə olunur və `False` qaytarılır

## 🎯 İstifadə Nümunələri

### Əsas İstifadə
```python
parser = ZeekLogParser("config.json")

# Son 7 günlük məlumatı oxumaq
success = parser.read_historical(days=7)
if success:
    print(f"Uğurla oxundu: {len(parser.df)} qeyd")
else:
    print("Oxuma uğursuz oldu")

# Bütün mövcud məlumatı oxumaq
success = parser.read_historical()  # days=None
```

### Məlumat Analizi
```python
if parser.read_historical(days=1):
    # Statistikaları göstərmək
    stats = parser.get_stats()
    print(f"Ümumi sorğular: {stats['total_records']}")
    print(f"Unikal mənbələr: {stats['unique_sources']}")
    
    # İlk 5 qeydi göstərmək
    print(parser.df.head())
```

## 🚀 Performans Optimizasiyaları

### 1. Yaddaş İstifadəsi
```python
low_memory=False  # Böyük fayllar üçün optimallaşdırma
```

### 2. Sütun Seçimi
```python
# Yalnız lazımi sütunları oxumaq (gələcək inkişaf)
# usecols=['ts', 'id.orig_h', 'query', 'qtype_name']
```

### 3. Çatları Oxuma
```python
# Böyük fayllar üçün chunk-based oxuma (gələcək inkişaf)
# chunksize=10000
```

## 🔍 Məlumat Keyfiyyəti Yoxlamaları

Metod aşağıdakı keyfiyyət yoxlamalarını həyata keçirir:

1. **Vacib sütunların mövcudluğu** - `id.orig_h`, `query`, `qtype_name`
2. **Çatışmayan dəyərlərin aşkarlanması** - NaN və null dəyərlər
3. **Timestamp etibarlılığı** - Etibarsız zaman damğaları
4. **Data tipi uyğunluğu** - Gözlənilən data tipləri

## 📈 Metrik və Statistikalar

Metod işlədikdən sonra aşağıdakı statistikalar mövcud olur:

```python
# Nümunə çıxış
print(f"Ümumi oxunan qeydlər: {len(parser.df)}")
print(f"Vaxt aralığı: {parser.df.index.min()} - {parser.df.index.max()}")
print(f"Unikal IP ünvanları: {parser.df['id.orig_h'].nunique()}")
print(f"Unikal domainlər: {parser.df['query'].nunique()}")
```

## 💡 Əlavə Qeydlər

1. **Fayl Ölçüsü:** Metod GB ölçülü fayllarla işləyə bilir
2. **Yaddaş İstifadəsi:** Böyük fayllar üçün əlavə yaddaş tələb edə bilər
3. **Performans:** Oxuma sürəti fayl ölçüsündən və sistem resurslarından asılıdır
4. **Error Recovery:** Xəta halında avtomatik bərpa cəhdləri

---

**Növbəti:** [03. Log Parser Modulu - tail_new_entries method](core/03_log_parser/04_tail_new_entries_method.md)

Bu sənəd `read_historical` metodunun detallı işləmə prinsipini izah edir. Növbəti sənəddə real-time log oxuma metoduna keçəcəyik.
