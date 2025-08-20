# 09. Installation Guide

## 📋 Sistem Tələbləri

### Əsas Tələblər
- **Python**: 3.9 və ya daha yeni versiya
- **RAM**: 2GB minimum, 4GB tövsiyə olunan
- **Disk**: 10GB boş yer
- **OS**: Linux (Ubuntu 20.04+, CentOS 7+), macOS 10.15+, Windows 10/11

### Şəbəkə Tələbləri
- **Zeek Compatibility**: Zeek 4.0+ 
- **Network Access**: Şəbəkə trafikini monitor etmə imkanı
- **Permissions**: Root/administrator icazələri (Zeek quraşdırmaq üçün)

## 🚀 Tez Quraşdırma (Recommended)

### 1. Proyekti Clone Edin
```bash
git clone https://github.com/yourusername/stealthy-c2-detector.git
cd stealthy-c2-detector
```

### 2. Virtual Environment Yaradın
```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
# və ya
venv\Scripts\activate     # Windows
```

### 3. Asılılıqları Quraşdırın
```bash
pip install -r requirements.txt
```

### 4. Zeek Quraşdırın (Linux)
```bash
# Zeek və asılılıqların quraşdırılması
chmod +x scripts/install.sh
sudo ./scripts/install.sh

# Zeek konfiqurasiyası
sudo ./scripts/setup_zeek.sh
```

### 5. Konfiqurasiyanı Yoxlayın
```bash
# Default konfiqurasiya ilə test edin
python -m src.main --test
```

## 🔧 Manual Quraşdırma

### 1. Python Asılılıqları
```bash
pip install pandas==2.0.3 tailer==0.4.1 PyYAML==6.0.1 requests==2.31.0 python-dotenv==1.0.0
```

### 2. Zeek Manual Quraşdırma (Ubuntu/Debian)
```bash
# Sistem yeniləmələri
sudo apt update && sudo apt upgrade -y

# Asılılıqlar
sudo apt install -y cmake make gcc g++ flex bison libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev

# Zeek quraşdırma
wget https://download.zeek.org/zeek-6.0.0.tar.gz
tar -xzf zeek-6.0.0.tar.gz
cd zeek-6.0.0

./configure --prefix=/opt/zeek --build-type=release
make -j$(nproc)
sudo make install

# PATH əlavə et
echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

### 3. Konfiqurasiya Faylı
```bash
# Konfiqurasiya faylını yaradın
mkdir -p config
cat > config/config.json << 'EOF'
{
  "zeek": {
    "log_dir": "/opt/zeek/logs/current",
    "log_types": ["dns"],
    "monitor_interfaces": ["eth0"]
  },
  "analysis": {
    "window_minutes": 60,
    "real_time_interval": 30,
    "historical_days": 7
  },
  "thresholds": {
    "dns_queries_per_minute": 150,
    "unusual_domain_length": 60,
    "entropy_threshold": 4.2
  }
}
EOF
```

## 🔍 Qurulumu Yoxlama

### 1. Əsas Funksionallıq Testi
```bash
# Test modunda işə salın
python -m src.main --test

# Çıxışı yoxlayın
[INFO] ZeekLogParser initialized for DNS logs
[INFO] Read 1245 records from dns.log
[INFO] DNS Analyzer initialized
[INFO] Generated 8 anomaly alerts
```

### 2. Zeek Konfiqurasiya Testi
```bash
# Zeek statusunu yoxlayın
sudo /opt/zeek/bin/zeekctl status

# Log fayllarını yoxlayın
ls -la /opt/zeek/logs/current/
```

### 3. Network Testi
```bash
# Şəbəkə interfeyslərini yoxlayın
ip link show

# Zeek-in dinlədiyi interfeysi yoxlayın
cat /opt/zeek/etc/node.cfg
```

## ⚠️ Ümumi Qurulum Problemləri və Həlləri

### 1. Python Version Problemi
**Problem:** `Python 3.9+ required`  
**Həll:**
```bash
# Python 3.9 quraşdırın
sudo apt install python3.9 python3.9-venv

# Virtual environmenti yenidən yaradın
python3.9 -m venv venv
```

### 2. Zeek Logları Tapılmır
**Problem:** `DNS log file not found`  
**Həll:**
```bash
# Zeek log qovluğunu yoxlayın
sudo mkdir -p /opt/zeek/logs/current
sudo chmod -R 755 /opt/zeek/logs

# Konfiqurasiyanı yeniləyin
# config.json-da log_dir parametrini yoxlayın
```

### 3. Permission Xətaları
**Problem:** `Permission denied`  
**Həll:**
```bash
# Fayl icazələrini tənzimləyin
sudo chown -R $USER:$USER /opt/zeek/logs
chmod -R 755 data/
```

### 4. Dependency Xətaları
**Problem:** `ModuleNotFoundError`  
**Həll:**
```bash
# Təmiz quraşdırma
pip uninstall -r requirements.txt -y
pip install -r requirements.txt --no-cache-dir
```

## 🚀 Production Deployment

### Systemd Service Faylı
```bash
# Service faylı yaradın
sudo tee /etc/systemd/system/c2-detector.service > /dev/null << 'EOF'
[Unit]
Description=C2 Beacon Detection Service
After=network.target zeek.service

[Service]
User=root
WorkingDirectory=/opt/stealthy-c2-detector
ExecStart=/opt/stealthy-c2-detector/venv/bin/python -m src.main
Restart=always
RestartSec=5
Environment=PYTHONPATH=/opt/stealthy-c2-detector/src

[Install]
WantedBy=multi-user.target
EOF
```

### Service İdarəetmə
```bash
# Service-i işə salın
sudo systemctl daemon-reload
sudo systemctl enable c2-detector
sudo systemctl start c2-detector

# Statusu yoxlayın
sudo systemctl status c2-detector
journalctl -u c2-detector -f
```

### Log Rotation
```bash
# Logrotate konfiqurasiyası
sudo tee /etc/logrotate.d/c2-detector > /dev/null << 'EOF'
/opt/stealthy-c2-detector/data/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF
```

## 📊 Qurulum Sonrası Testlər

### 1. Funksionallıq Testi
```bash
# Tam test rejimi
python -m src.main --test --verbose

# Xüsusi konfiqurasiya ilə test
python -m src.main --config config/production.json --test
```

### 2. Performans Testi
```bash
# Yük testi
python -c "
from src.core.detector import C2Detector
detector = C2Detector('config.json')
import time
start = time.time()
detector.setup_environment()
print(f'Setup time: {time.time()-start:.2f}s')
"

# Yaddaş istifadəsi
pip install memory_profiler
python -m memory_profiler -m src.main --test
```

### 3. Şəbəkə Testi
```bash
# Şəbəkə trafikini yoxlayın
sudo tcpdump -i eth0 -c 10 port 53

# Zeek loglarını yoxlayın
tail -f /opt/zeek/logs/current/dns.log
```

---

**Növbəti:** [10. Usage Examples](/doc/10_Usage_Examples.md)

Bu sənəd sistemin tam quraşdırılması üçün addım-addım təlimatları əhatə edir. Növbəti sənəddə istifadə nümunələrinə keçəcəyik.
