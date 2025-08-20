# 03. Log Parser Modulu - tail_new_entries method

## 📋 `tail_new_entries` Metodunun Təyinatı

`tail_new_entries` metodu Zeek DNS log faylını real-time olaraq izləyir və yeni əlavə olunan girişləri emal edir. Bu metod proyektin real-time C2 aşkarlama funksionallığının əsasını təşkil edir.

## 🏗️ Metod İmzası

```python
def tail_new_entries(self, callback_func: Callable, max_lines: Optional[int] = None):
```

**Parametrlər:**
- `callback_func` (Callable): Hər yeni log girişi üçün çağırılacaq funksiya
- `max_lines` (Optional[int]): Maksimum oxunacaq sətir sayı (None = limitsiz)

**Qaytarır:** `None` (metod davamlı işləyir)

## 🔧 Metodun Daxili İşləməsi

### 1. Fayl Validasiyası

```python
if not self._validate_log_file():
    return
```

**Funksiya:** Log faylının mövcudluğunu və oxuna bilməsini yoxlayır

**Əhəmiyyəti:** Əgər fayl mövcud deyilsə, metod səssizcə dayanır

### 2. Real-time Monitorinqin Başladılması

```python
logger.info("Starting real-time DNS log monitoring...")

with open(self.dns_log_path, 'r') as f:
    # Faylın sonuna keçid
    if self.last_position == 0:
        f.seek(0, 2)  # SEEK_END (faylın sonu)
```

**Funksiya:** Faylı açır və son mövqeyə keçid edir

**Əhəmiyyəti:** Yalnız yeni girişləri oxumaq üçün

### 3. Faylın Sonundan Oxuma Dövrü

```python
for line in tailer.follow(f):
    if line.startswith('#'):
        continue
```

**Funksiya:** `tailer` kitabxanası ilə faylın sonundan oxuyur

**Əhəmiyyəti:** Şərh sətirlərini (#'lə başlayan) oxumur

### 4. Sətrin Pars Edilməsi

```python
fields = line.strip().split('\t')
if len(fields) == len(self.DNS_COLUMNS):
    entry = dict(zip(self.DNS_COLUMNS, fields))
```

**Funksiya:** Tab ilə ayrılmış sətri dictionary-ə çevirir

**Nümunə Çevrilmə:**
```
"1641043200.512\tCToESa3vtyL5\t192.168.1.100\t54321\t8.8.8.8\t53\tgoogle.com\tA"
↓
{
    'ts': '1641043200.512',
    'uid': 'CToESa3vtyL5', 
    'id.orig_h': '192.168.1.100',
    ...
}
```

### 5. Timestamp Konversiyası

```python
try:
    entry['ts'] = pd.to_datetime(float(entry['ts']), unit='s')
except (ValueError, TypeError):
    entry['ts'] = None
```

**Funksiya:** Unix timestamp-i datetime obyektinə çevirir

**Xəta idarəetmə:** Əgər konversiya mümkün deyilsə, `None` təyin edir

### 6. Callback Funksiyasının Çağırılması

```python
callback_func(entry)
self.processed_count += 1
```

**Funksiya:** Xarici funksiyanı hər yeni girişlə çağırır

**Əhəmiyyəti:** Əsas emal məntiqi xarici funksiyada həyata keçirilir

### 7. Proqresin Loglanması

```python
if self.processed_count % 1000 == 0:
    logger.info(f"Processed {self.processed_count} real-time entries")
```

**Funksiya:** Hər 1000 emal edilmiş girişdə bir log yazır

**Əhəmiyyəti:** Monitorinq və performans izləmə üçün

### 8. Maksimum Sətir Limiti

```python
if max_lines is not None:
    max_lines -= 1
    if max_lines <= 0:
        break
```

**Funksiya:** Test və debug məqsədilə sətir sayını məhdudlaşdırır

### 9. CPU Yükünün İdarə Edilməsi

```python
time.sleep(0.001)
```

**Funksiya:** Kiçik fasilə verərək CPU yükünü azaldır

**Əhəmiyyəti:** Sistem resurslarının səmərəli istifadəsi

## 🎯 Callback Funksiyasının Strukturu

**Gözlənilən callback funksiyası formatı:**

```python
def my_callback_function(dns_entry: Dict) -> None:
    """
    Parameters:
        dns_entry: Dictionary containing parsed DNS log entry
    """
    # Emal məntiqi burada
    print(f"New DNS query: {dns_entry.get('query')}")
```

**Nümunə DNS Entry:**
```python
{
    'ts': datetime(2024, 1, 15, 10, 30, 0, 512000),
    'uid': 'CToESa3vtyL5',
    'id.orig_h': '192.168.1.100',
    'id.orig_p': '54321',
    'id.resp_h': '8.8.8.8',
    'id.resp_p': '53',
    'query': 'google.com',
    'qtype_name': 'A',
    'rcode_name': 'NOERROR'
}
```

## ⚠️ Xəta Əlaqələndirmə

Metod aşağıdakı xətaları idarə edir:

1. **Fayl oxuma xətaları** - `IOError` ilə əlaqələndirilir
2. **Parsing xətaları** - Sətir formatı uyğunsuzluqları
3. **Type conversion xətaları** - Timestamp konversiya problemləri
4. **Callback xətaları** - Xarici funksiyada baş verən xətalar

**Xəta handling strategiyası:** Fərdi xətalar loglanır, lakin proses davam etdirilir

## 🚀 İstifadə Nümunələri

### Əsas İstifadə
```python
def simple_callback(entry):
    """Sadə çıxış callback'i"""
    print(f"{entry['ts']} - {entry['id.orig_h']} -> {entry['query']}")

# Real-time monitorinqi başlatmaq
parser.tail_new_entries(simple_callback)
```

### Ətraflı Callback
```python
def advanced_callback(entry):
    """Ətraflı emal callback'i"""
    if len(entry.get('query', '')) > 50:
        print(f"Uzun domain aşkar edildi: {entry['query'][:50]}...")
    
    if entry.get('qtype_name') in ['TXT', 'NULL']:
        print(f"Qeyri-adi sorğu növü: {entry['qtype_name']}")

parser.tail_new_entries(advanced_callback)
```

### Test Məqsədli
```python
# Yalnız 10 sətir oxumaq üçün
parser.tail_new_entries(simple_callback, max_lines=10)
```

## 🔄 Real-time İşləmə Xüsusiyyətləri

### 1. Davamlı Monitorinq
```python
# Metod dayanmadan işləyir
# Yeni sətirlər avtomatik olaraq aşkarlanır və emal olunur
```

### 2. Fayl Rotation Dəstəyi
```python
# tailer kitabxanası fayl rotation-u avtomatik idarə edir
# Yeni fayl yaradıldıqda avtomatik keçid edir
```

### 3. Performans Optimizasiyası
```python
# CPU yükünü azaltmaq üçün kiçik sleep intervalları
# Səmərəli yaddaş idarəetməsi
```

## 📊 Performans Metrikləri

**Gözlənilən Performans:**
- **Emal Sürəti:** Saniyədə 1000+ DNS sorğusu
- **Yaddaş İstifadəsi:** ~10MB (sabit)
- **Gecikmə:** < 100ms (yeni girişlərin emalı)

**Monitorinq Üçün:**
```python
# Əlavə performans metrikləri
start_time = time.time()
processed_count = 0

def monitoring_callback(entry):
    global processed_count
    processed_count += 1
    
    if processed_count % 1000 == 0:
        elapsed = time.time() - start_time
        rate = processed_count / elapsed
        print(f"Processing rate: {rate:.2f} queries/second")
```

## 💡 Əlavə Qeydlər

1. **Blocking Nature:** Metod blockingdir (thread istifadəsi tövsiyə olunur)
2. **Resource Management:** Fayl avtomatik bağlanır (`with` statement)
3. **Signal Handling:** Ctrl+C ilə dayandırıla bilər
4. **Platform Uyğunluğu:** Linux, macOS, Windows-da işləyir

---

**Növbəti:** [03. Log Parser Modulu - get_stats method](core/03_log_parser/05_get_stats_method.md)

Bu sənəd `tail_new_entries` metodunun detallı işləmə prinsipini izah edir. Növbəti sənəddə statistik məlumatların alınması metoduna keçəcəyik.
