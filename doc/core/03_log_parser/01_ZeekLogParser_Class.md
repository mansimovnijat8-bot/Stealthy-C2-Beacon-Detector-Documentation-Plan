# 03. Log Parser Modulu - ZeekLogParser Class

## 📋 Klassın Təyinatı

`ZeekLogParser` sinfi proyektin əsas məlumat qəbuledici komponentidir. Zeek-in yaratdığı DNS log fayllarını oxuyur, strukturlaşdırır və analiz üçün hazırlayır.

## 🏗️ Klass Strukturu

```python
class ZeekLogParser:
    """
    Professional Zeek DNS log parser with enhanced error handling and performance
    """
    
    # DNS log columns with descriptions
    DNS_COLUMNS = [
        'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 
        'proto', 'trans_id', 'query', 'qclass', 'qclass_name', 'qtype', 
        'qtype_name', 'rcode', 'rcode_name', 'AA', 'TC', 'RD', 'RA', 'Z', 
        'answers', 'TTLs', 'rejected'
    ]
    
    COLUMN_DESCRIPTIONS = {
        'ts': 'Timestamp of the DNS query',
        'id.orig_h': 'Source IP address',
        # ... digər sütun təsvirləri
    }
```

## 📊 Sütun Açıqlamaları

| Sütun Adı | Tip | Təsvir | Nümunə Dəyər |
|-----------|-----|---------|-------------|
| `ts` | float | Sorğunun zaman damğası (Unix timestamp) | `1641043200.512` |
| `uid` | string | Unikal əlaqə identifikatoru | `CToESa3vtyL5` |
| `id.orig_h` | string | Mənbə IP ünvanı | `192.168.1.100` |
| `id.orig_p` | integer | Mənbə port nömrəsi | `54321` |
| `id.resp_h` | string | Cavab verən IP ünvanı | `8.8.8.8` |
| `id.resp_p` | integer | Cavab verən port nömrəsi | `53` |
| `query` | string | DNS sorğu adı | `google.com` |
| `qtype_name` | string | Sorğu növü | `A`, `AAAA`, `TXT` |
| `rcode_name` | string | Cavab kodu | `NOERROR`, `NXDOMAIN` |

## 🔧 Konstruktor Metodu

### `__init__(self, config_path: str = "config.json")`

**Vəzifəsi**: Klassın ilkin konfiqurasiyasını və dəyişənlərini hazırlamaq

**Parametrlər**:
- `config_path`: Konfiqurasiya faylının yolu (default: "config.json")

**Daxili İşləmə**:
1. Konfiqurasiya faylını yükləyir
2. Zeek log qovluğunun yolunu təyin edir
3. DNS log faylının tam yolunu qurur
4. Monitor interfeyslərini konfiqurasiyadan oxuyur
5. Pandas DataFrame və digər dəyişənləri initialize edir

**Kod Nümunəsi**:
```python
def __init__(self, config_path: str = "config.json"):
    self.config = load_config(config_path)
    zeek_config = self.config.get('zeek', {})
    
    self.zeek_log_dir = Path(zeek_config.get('log_dir', '/opt/zeek/logs/current'))
    self.dns_log_path = self.zeek_log_dir / 'dns.log'
    self.monitor_interfaces = zeek_config.get('monitor_interfaces', ['eth0'])
    
    self.df = pd.DataFrame()  # Əsas məlumat çərçivəsi
    self.last_position = 0    # Son oxuma mövqeyi
    self.processed_count = 0  # Emal edilmiş giriş sayı
```

## 📖 Əsas Oxuma Metodları

### 1. `read_historical(self, days: Optional[int] = None) -> bool`

**Vəzifəsi**: Tarixi DNS məlumatlarını oxuyur və emal edir

**Parametrlər**:
- `days`: Neçə günlük məlumat oxunacaq (None bütün məlumat deməkdir)

**İşləmə Addımları**:
1. Log faylının validasiyası
2. Faylın tam oxunması
3. Timestamp konversiyası
4. Məlumat keyfiyyətinin yoxlanması
5. DataFrame-in index kimi təyin edilməsi

**Qaytarır**: `True` uğurlu olduqda, `False` əks halda

### 2. `tail_new_entries(self, callback_func: Callable, max_lines: Optional[int] = None)`

**Vəzifəsi**: Real-time olaraq yeni log girişlərini oxuyur və işləyir

**Parametrlər**:
- `callback_func`: Hər yeni giriş üçün çağırılacaq funksiya
- `max_lines`: Maksimum oxunacaq sətir sayı

**Real-time İşləmə**:
- Faylın sonundan oxuma
- Yeni sətirlərin aşkarlanması
- Hər sətrin pars edilməsi
- Callback funksiyasının çağırılması

## 🔍 Yardımçı Metodlar

### `_validate_log_file(self) -> bool`

Log faylının mövcudluğunu, oxuna bilməsini və düzgünlüyünü yoxlayır

### `_validate_data_quality(self)`

Məlumatın keyfiyyətini yoxlayır:
- Vacib sütunların mövcudluğu
- Çatışmayan dəyərlərin aşkarlanması
- Məlumat tamlığının yoxlanması

## 📈 Statistik Metodlar

### `get_stats(self) -> Dict[str, Any]`

Mövcud məlumat haqqında statistik məlumatlar qaytarır:

```python
{
    "total_records": 1250,
    "time_range": "2024-01-01 10:00:00 to 2024-01-01 15:30:00",
    "duration_hours": 5.5,
    "unique_sources": 45,
    "unique_domains": 890
}
```

### `get_recent_entries(self, minutes: int = 60) -> pd.DataFrame`

Son N dəqiqəlik məlumatları filtrləyib qaytarır

## 🎯 İstifadə Nümunələri

### Əsas İstifadə
```python
# Parser yaratmaq
parser = ZeekLogParser("config.json")

# Tarixi məlumatları oxumaq
success = parser.read_historical(days=1)

# Statistikaları almaq
stats = parser.get_stats()
print(f"Ümumi sorğular: {stats['total_records']}")
```

### Real-time Monitorinq
```python
def my_callback(dns_entry):
    print(f"Yeni sorğu: {dns_entry['query']}")

# Real-time monitorinqi başlatmaq
parser.tail_new_entries(my_callback)
```

## ⚠️ Xəta Əlaqələndirmə

Klas aşağıdakı xətaları idarə edir:
- Faylın tapılmaması
- Format xətaları
- Timestamp konversiya xətaları
- Məlumat tamlığı problemləri

## 🚀 Performans Optimizasiyaları

- **Böyük fayllar üçün optimizasiya**: Səmərəli yaddaş istifadəsi
- **Real-time emal**: Aşağı gecikmə ilə işləmə
- **Error handling**: Avtomatik bərpa mexanizmləri
- **Log rotation**: Böyük log fayllarının idarə edilməsi

---

**Növbəti**: [03. Log Parser Modulu - init method](/02_init_method.md)

Bu sənəd `ZeekLogParser` sinfinin ümumi strukturunu və funksionallığını izah edir. Növbəti sənəddə konstruktor metodunun detallarına keçəcəyik.
