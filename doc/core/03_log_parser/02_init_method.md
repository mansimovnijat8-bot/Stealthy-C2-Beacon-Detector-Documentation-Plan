# 03. Log Parser Modulu - init method

## 📋 `__init__` Metodunun Təyinatı

`__init__` metodu `ZeekLogParser` sinfinin konstruktorudur. Bu metod sinif instance-ni yaradan zaman avtomatik olaraq çağırılır və bütün ilkin konfiqurasiya əməliyyatlarını həyata keçirir.

## 🏗️ Metod İmzası

```python
def __init__(self, config_path: str = "config.json"):
```

**Parametrlər:**
- `config_path` (str): Konfiqurasiya faylının yolu. Default dəyər: "config.json"

**Qaytarır:** `None` (konstruktor olduğu üçün heç nə qaytarmır)

## 🔧 Metodun Daxili İşləməsi

### 1. Konfiqurasiyanın Yüklənməsi

```python
self.config = load_config(config_path)
```

**Funksiya:** `load_config` yardımçı funksiyası vasitəsilə JSON konfiqurasiya faylını yükləyir

**Əhəmiyyəti:** Bütün sistem parametrləri mərkəzi konfiqurasiyadan idarə olunur

### 2. Zeek Konfiqurasiyasının Alınması

```python
zeek_config = self.config.get('zeek', {})
```

**Funksiya:** Konfiqurasiyanın 'zeek' bölməsini oxuyur, əgər yoxdursa boş dictionary qaytarır

**Default Struktur:**
```json
{
  "zeek": {
    "log_dir": "/opt/zeek/logs/current",
    "log_types": ["dns"],
    "monitor_interfaces": ["eth0"]
  }
}
```

### 3. Log Qovluğunun Təyin Edilməsi

```python
self.zeek_log_dir = Path(zeek_config.get('log_dir', '/opt/zeek/logs/current'))
```

**Funksiya:** Zeek log qovluğunun yolunu `Path` obyektinə çevirir

**Default Dəyər:** `/opt/zeek/logs/current`

**Əhəmiyyəti:** Pathlib istifadəsi cross-platform uyğunluq təmin edir

### 4. DNS Log Faylının Qurulması

```python
self.dns_log_path = self.zeek_log_dir / 'dns.log'
```

**Funksiya:** Tam DNS log faylının yolunu yaradır

**Nümunə:** `/opt/zeek/logs/current/dns.log`

### 5. Monitor Interfeyslərinin Konfiqurasiyası

```python
self.monitor_interfaces = zeek_config.get('monitor_interfaces', ['eth0'])
```

**Funksiya:** Zeek-in monitor etdiyi şəbəkə interfeyslərini təyin edir

**Default Dəyər:** `['eth0']`

**Əhəmiyyəti:** Çoxlu interfeys dəstəyi (məsələn: `['eth0', 'eth1']`)

### 6. DataFrame-in İlkinləşdirilməsi

```python
self.df = pd.DataFrame()
```

**Funksiya:** Pandas DataFrame-in boş olaraq yaradılması

**Əhəmiyyəti:** Tarixi məlumatların saxlanması üçün əsas data strukturudur

### 7. Oxuma Mövqeyinin İlkinləşdirilməsi

```python
self.last_position = 0
```

**Funksiya:** Real-time oxuma üçün son mövqeyi saxlayır

**Əhəmiyyəti:** Fayl rotation zamanı düzgün oxuma üçün vacibdir

### 8. Emal Sayğacının İlkinləşdirilməsi

```python
self.processed_count = 0
```

**Funksiya:** Emal edilmiş log girişlərinin sayını saxlayır

**Əhəmiyyəti:** Performans monitorinqi və statistikalar üçün istifadə olunur

## 🎯 Konfiqurasiya Faylının Strukturu

`config.json` faylının gözlənilən strukturu:

```json
{
  "zeek": {
    "log_dir": "/opt/zeek/logs/current",
    "log_types": ["dns"],
    "monitor_interfaces": ["eth0", "eth1"]
  },
  "analysis": {
    "window_minutes": 60,
    "real_time_interval": 30
  },
  "thresholds": {
    "dns_queries_per_minute": 150,
    "unusual_domain_length": 60
  }
}
```

## ⚠️ Xəta Əlaqələndirmə

Metod aşağıdakı xətaları idarə edir:

1. **Konfiqurasiya faylının tapılmaması** - `FileNotFoundError`
2. **JSON parsing xətaları** - `JSONDecodeError`
3. **Path creation xətaları** - `OSError`

**Xəta handling strategiyası:** Əgər konfiqurasiya faylı tapılmazsa, default dəyərlər istifadə olunur

## 🔄 İlkin Vəziyyət

Metod işini bitirdikdən sonra instance aşağıdaki vəziyyətdə olur:

```python
# Nümunə instance vəziyyəti
parser = ZeekLogParser("config.json")

print(parser.zeek_log_dir)      # Path('/opt/zeek/logs/current')
print(parser.dns_log_path)      # Path('/opt/zeek/logs/current/dns.log')
print(parser.monitor_interfaces) # ['eth0']
print(parser.df.empty)          # True (boş DataFrame)
print(parser.last_position)     # 0
print(parser.processed_count)   # 0
```

## 🚀 İstifadə Nümunələri

### Əsas İstifadə
```python
# Default konfiqurasiya ilə
parser = ZeekLogParser()

# Xüsusi konfiqurasiya faylı ilə  
parser = ZeekLogParser("my_config.json")

# Fərqli konfiqurasiya ilə
parser = ZeekLogParser("production_config.json")
```

### Konfiqurasiya Validasiyası
```python
# Konfiqurasiyanı yoxlamaq
print("Log directory:", parser.zeek_log_dir)
print("DNS log path:", parser.dns_log_path)
print("Interfaces:", parser.monitor_interfaces)
```

## 💡 Əlavə Qeydlər

1. **Thread Safety:** Metod thread-safe dizayn edilib
2. **Resource Management:** Heç bir resource (fayl, socket) açmır
3. **Performance:** Çox sürətli işləyir (milisaniyələrlə)
4. **Memory Usage:** Aşağı yaddaş istifadəsi

## 🔧 Fərdiləşdirmə Seçimləri

**Log qovluğunu dəyişdirmək:**
```json
{
  "zeek": {
    "log_dir": "/var/log/zeek",
    "log_types": ["dns"]
  }
}
```

**Çoxlu interfeys konfiqurasiyası:**
```json
{
  "zeek": {
    "log_dir": "/opt/zeek/logs/current",
    "monitor_interfaces": ["eth0", "wlan0", "docker0"]
  }
}
```

---

**Növbəti:** [03. Log Parser Modulu - read_historical method](core/03_log_parser/03_read_historical_method.md)

Bu sənəd `__init__` metodunun detallı işləmə prinsipini izah edir. Növbəti sənəddə tarixi məlumatların oxunması metoduna keçəcəyik.
