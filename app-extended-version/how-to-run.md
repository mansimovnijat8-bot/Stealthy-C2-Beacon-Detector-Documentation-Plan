## 📥 Proyekti Clone Etdikdən Sonra:

```bash
# 1. Proyekti clone et
git clone <repository-url>
cd stealthy-c2-detector

# 2. Virtual environment yarat və aktiv et
python -m venv venv
source venv/bin/activate  # Linux/Mac
# və ya
venv\Scripts\activate     # Windows

# 3. Tələb olunan paketləri quraşdır
pip install -r requirements.txt
```

## 🚀 İŞƏ SALMA MODLARI VƏ PARAMETRLƏRİ:

### 1. **ƏSAS İŞƏ SALMA KOMANDLARI:**

#### **1.1. Normal Real-time Mode** (Əsas İş Rejimi)
```bash
python src/main.py
```
**Nə edir:** Real-time monitoringu başladır, bütün logları izləyir  
**Çıxış:** Canlı alertlar və statistikalar

#### **1.2. Test Mode** (Sınaq Rejimi)
```bash
python src/main.py --test
```
**Nə edir:** Yalnız bir dəfə analiz edir və dayanır  
**İstifadə:** Konfiqurasiyanı test etmək üçün

#### **1.3. Verbose Mode** (Detallı Çıxış)
```bash
python src/main.py --verbose
# və ya
python src/main.py -v
```
**Nə edir:** Daha ətraflı log və debug informasiyası göstərir  
**İstifadə:** Problemləri diaqnoz etmək üçün

#### **1.4. Xüsusi Konfiq Faylı ilə**
```bash
python src/main.py --config my_config.json
```
**Nə edir:** Default config.json yerine fərqli konfiq faylı istifadə edir  
**İstifadə:** Fərqli mühitlər üçün

#### **1.5. Xüsusi Protokol ilə**
```bash
python src/main.py --protocol dns
# Seçimlər: dns, http, conn, ssl, all
```
**Nə edir:** Yalnız təyin olunan protokolu monitor edir  
**İstifadə:** Performansı optimallaşdırmaq üçün

---

### 2. **KOMBİNƏ EDİLMİŞ MODLAR:**

#### **2.1. Test + Verbose**
```bash
python src/main.py --test --verbose
```
**Nə edir:** Test modunda detallı çıxışla işləyir

#### **2.2. Xüsusi Konfiq + Verbose**
```bash
python src/main.py --config production.json --verbose
```

#### **2.3. Xüsusi Protokol + Test**
```bash
python src/main.py --protocol http --test
```

---

### 3. **DASHBOARD İŞƏ SALMA:**

#### **3.1. Əsas Dashboard**
```bash
streamlit run src/viz/dashboard.py
```
**Nə edir:** Veb dashboardu başladır (http://localhost:8501)

#### **3.2. Dashboard + Server Settings**
```bash
streamlit run src/viz/dashboard.py --server.port 8502 --server.address 0.0.0.0
```
**Nə edir:** Xüsusi port və ünvanla dashboardu başladır

---

### 4. **ZEEK ƏMƏLİYYATLARI:**

#### **4.1. Zeek Statusunu Yoxlama**
```bash
sudo zeekctl status
```

#### **4.2. Zeek-i Yenidən Başlatma**
```bash
sudo zeekctl restart
```

#### **4.3. Zeek Loglarını İzləmə**
```bash
# DNS loglarını izlə
tail -f /opt/zeek/logs/dns.log

# Bütün logları izlə
tail -f /opt/zeek/logs/*.log
```

---

### 5. **QƏRARLAR VƏ İSTİFADƏ SƏNƏDLƏRİ:**

#### **5.1. Yardım Əldə Etmə**
```bash
python src/main.py --help
```
**Çıxış:** Bütün parametrlərin izahı

#### **5.2. Konfiqurasiyanı Validasiya Etmə**
```bash
python -c "from src.utils.helpers import load_config; load_config('config.json'); print('✅ Config valid')"
```

#### **5.3. Logları Təmizləmə**
```bash
# Alert loglarını təmizlə
echo "" > data/alerts/c2_alerts.json

# Sistem loglarını təmizlə
echo "" > data/logs/c2_detector.log
```

---

### 6. **MONİTORİNG VƏ İZLƏMƏ:**

#### **6.1. Real-time Log İzləmə**
```bash
# Alert loglarını izlə
tail -f data/alerts/c2_alerts.json

# Sistem loglarını izlə
tail -f data/logs/c2_detector.log
```

#### **6.2. Statistikaları Görmə**
```bash
# Alert statistikaları
python -c "
import json
alerts = []
with open('data/alerts/c2_alerts.json', 'r') as f:
    for line in f:
        alerts.append(json.loads(line))
print(f'Total alerts: {len(alerts)}')
print(f'High severity: {len([a for a in alerts if a.get(\"severity\") == \"HIGH\"])}')
"
```

---

## 🎯 **TİPİK İSTİFADƏ SƏNƏDLƏRİ:**

### **Ssenari 1: İlk Test**
```bash
# Test modunda işə sal
python src/main.py --test --verbose

# Nəticəni yoxla
cat data/alerts/c2_alerts.json | wc -l
```

### **Ssenari 2: Production İşə Salma**
```bash
# Arxa planda işə sal (Linux)
nohup python src/main.py --config production.json > logs.txt 2>&1 &

# Dashboardu başlat
streamlit run src/viz/dashboard.py --server.port 8501
```

### **Ssenari 3: Problem Diaqnozu**
```bash
# Detallı modda işə sal
python src/main.py --verbose

# Zeek loglarını izlə
tail -f /opt/zeek/logs/current/dns.log

# Sistem loglarını izlə
tail -f data/logs/c2_detector.log
```

### **Ssenari 4: Performans Testi**
```bash
# Yalnız DNS monitor et
python src/main.py --protocol dns --verbose

# Yalnız HTTP monitor et
python src/main.py --protocol http
```

---

## 📊 **ÇIXIŞ NÜMUNƏLƏRİ:**

### **Normal Mod Çıxışı:**
```
🚀 PROFESSIONAL C2 BEACON DETECTOR - REAL-TIME MONITORING
✅ Config loaded successfully
📊 Monitoring DNS, HTTP, CONN, SSL traffic...
🚨 Alert generated: HIGH_DNS_VOLUME from 192.168.1.100
```

### **Test Mod Çıxışı:**
```
🧪 RUNNING IN TEST MODE
✅ Processed 15,237 historical records
📊 Generated 45 anomaly alerts
⏹️  Test completed successfully
```

### **Verbose Mod Çıxışı:**
```
DEBUG: Loading config from config.json
DEBUG: Found 4 available log types
DEBUG: Processing DNS entry: 192.168.1.100 -> malicious-domain.com
DEBUG: Entropy calculated: 4.75
🚨 ALERT: High entropy domain detected
```
