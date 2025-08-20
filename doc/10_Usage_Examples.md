# 10. Usage Examples

## 📋 İstifadə Senaryoları

Bu bölmə C2 Detector sisteminin müxtəlif istifadə senaryalarını və nümunələrini əhatə edir.

## 🚀 Əsas İstifadə Nümunələri

### 1. Test Modunda İşə Salma
```bash
# Əsas test modu
python -m src.main --test

# Verbose test modu
python -m src.main --test --verbose

# Xüsusi konfiqurasiya ilə test
python -m src.main --config config/custom_config.json --test
```

### 2. Real-time Monitorinq
```bash
# Əsas real-time monitorinq
python -m src.main

# Xüsusi konfiqurasiya ilə
python -m src.main --config config/production.json

# Debug modunda
python -m src.main --verbose
```

### 3. Müəyyən Konfiqurasiya ilə
```bash
# Fərdi konfiqurasiya faylı ilə
python -m src.main --config config/development.json

# Fərqli log direktoriyası ilə
python -m src.main --config config/network2_config.json
```

## 🔧 Skript Nümunələri

### 1. Avtomatik Qurulum Skripti
```bash
#!/bin/bash
# install_detector.sh

echo "C2 Detector Qurulumu Başlayır..."
echo "=========================================="

# Proyekti clone edin
git clone https://github.com/yourusername/stealthy-c2-detector.git
cd stealthy-c2-detector

# Virtual environment yaradın
echo "Virtual environment yaradılır..."
python -m venv venv
source venv/bin/activate

# Asılılıqları quraşdırın
echo "Asılılıqlar quraşdırılır..."
pip install -r requirements.txt

# Zeek quraşdırın (Linux üçün)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Zeek quraşdırılır..."
    chmod +x scripts/install.sh
    sudo ./scripts/install.sh
    sudo ./scripts/setup_zeek.sh
fi

# Konfiqurasiya faylını yoxlayın
if [ ! -f "config/config.json" ]; then
    echo "Default konfiqurasiya faylı yaradılır..."
    cp config/config.example.json config/config.json
fi

echo "Qurulum tamamlandı!"
echo "Test modunda işə salmaq üçün: python -m src.main --test"
```

### 2. Monitorinq Skripti
```bash
#!/bin/bash
# monitor_detector.sh

# Environmenti aktivləşdir
cd /opt/stealthy-c2-detector
source venv/bin/activate

# Detectoru işə sal
python -m src.main --config config/production.json

# Əgər dayanarsa, yenidən başlat
while true; do
    echo "$(date): Detector dayandı, yenidən başladılır..."
    sleep 5
    python -m src.main --config config/production.json
done
```

### 3. Statistik Skript
```bash
#!/bin/bash
# stats_detector.sh

# Gündəlik statistikalar
cd /opt/stealthy-c2-detector
source venv/bin/activate

TODAY=$(date +%Y-%m-%d)
LOG_FILE="data/stats_${TODAY}.log"

# Statistikaları hesabla
echo "=== C2 Detector Statistikaları - $TODAY ===" > $LOG_FILE
echo "Saat: $(date +%H:%M:%S)" >> $LOG_FILE
echo "==========================================" >> $LOG_FILE

# Fayl ölçülərini yoxla
if [ -f "data/alerts/c2_alerts.json" ]; then
    ALERT_COUNT=$(wc -l < "data/alerts/c2_alerts.json")
    echo "Ümumi Xəbərdarlıq Sayı: $ALERT_COUNT" >> $LOG_FILE
fi

if [ -f "data/logs/c2_detector.log" ]; then
    LOG_SIZE=$(du -h "data/logs/c2_detector.log" | cut -f1)
    echo "Log Fayl Ölçüsü: $LOG_SIZE" >> $LOG_FILE
fi

# Son 10 xəbərdarlığı göstər
echo "" >> $LOG_FILE
echo "Son 10 Xəbərdarlıq:" >> $LOG_FILE
tail -10 "data/alerts/c2_alerts.json" >> $LOG_FILE

echo "Statistikalar $LOG_FILE faylına yazıldı"
```

## 🐍 Python API Nümunələri

### 1. Birbaşa Python İstifadəsi
```python
#!/usr/bin/env python3
# custom_detector.py

import sys
from pathlib import Path

# Proyekt qovluğuna əlavə et
sys.path.insert(0, str(Path(__file__).parent))

from src.core.detector import C2Detector
from src.core.log_parser import ZeekLogParser
from src.core.dns_analyzer import DNSAnalyzer
import time

def custom_monitoring():
    """Xüsusi monitorinq konfiqurasiyası"""
    
    # Detectoru işə sal
    detector = C2Detector("config/custom_config.json")
    
    # Mühiti qur
    if detector.setup_environment():
        print("Mühit uğurla quruldu")
        print(f"Yüklənən qeydlər: {len(detector.zeek_parser.df)}")
        
        # Özəl monitorinq dövrü
        try:
            while True:
                # Dövri analiz
                detector.periodic_analysis()
                
                # Statistikaları göstər
                print(f"Ümumi xəbərdarlıqlar: {detector.alert_count}")
                
                # 5 dəqiqə gözlə
                time.sleep(300)
                
        except KeyboardInterrupt:
            print("Monitorinq dayandırıldı")
            detector.generate_final_report()
    else:
        print("Mühit qurulumu uğursuz oldu")

if __name__ == "__main__":
    custom_monitoring()
```

### 2. Real-time Xüsusi Emal
```python
#!/usr/bin/env python3
# custom_processing.py

import json
from datetime import datetime
from src.core.detector import C2Detector

class CustomDetector(C2Detector):
    """Xüsusi emal ilə genişləndirilmiş detector"""
    
    def real_time_dns_callback(self, dns_entry):
        """Xüsusi real-time emal"""
        # Əsas emal
        super().real_time_dns_callback(dns_entry)
        
        # Əlavə xüsusi emal
        source_ip = dns_entry.get('id.orig_h', 'unknown')
        query = dns_entry.get('query', '')
        
        # Özəl aşkarlama məntiqi
        if self._is_suspicious_custom_pattern(query):
            self.raise_alert({
                'timestamp': datetime.now(),
                'alert_type': 'CUSTOM_PATTERN',
                'severity': 'MEDIUM',
                'source_ip': source_ip,
                'domain': query,
                'description': f'Xüsusi pattern aşkar edildi: {query}'
            })
    
    def _is_suspicious_custom_pattern(self, domain):
        """Xüsusi pattern aşkarlama"""
        suspicious_patterns = [
            'vpn', 'proxy', 'tor', 'anonymous',
            'free', 'hidden', 'secret', 'shield'
        ]
        
        domain_lower = domain.lower()
        return any(pattern in domain_lower for pattern in suspicious_patterns)

# İstifadə
if __name__ == "__main__":
    detector = CustomDetector("config/custom_config.json")
    detector.setup_environment()
    
    # Real-time monitorinqi başlat
    print("Xüsusi detector işə salınır...")
    detector.run_realtime_monitoring()
```

### 3. Çoxsaylı Konfiqurasiya İlə İş
```python
#!/usr/bin/env python3
# multi_config_detector.py

import json
import time
from pathlib import Path
from src.core.detector import C2Detector

def multi_config_monitoring():
    """Çoxsaylı konfiqurasiya ilə monitorinq"""
    
    config_files = [
        "config/network1_config.json",
        "config/network2_config.json", 
        "config/network3_config.json"
    ]
    
    detectors = []
    
    # Bütün detectorları işə sal
    for config_file in config_files:
        if Path(config_file).exists():
            detector = C2Detector(config_file)
            if detector.setup_environment():
                detectors.append(detector)
                print(f"{config_file} uğurla yükləndi")
            else:
                print(f"{config_file} yüklənmədi")
        else:
            print(f"{config_file} tapılmadı")
    
    # Birdən çox şəbəkəni eyni vaxtda monitor et
    try:
        while True:
            for i, detector in enumerate(detectors):
                print(f"Şəbəkə {i+1} üçün analiz...")
                detector.periodic_analysis()
                print(f"Şəbəkə {i+1} ümumi xəbərdarlıqlar: {detector.alert_count}")
            
            print("=" * 50)
            time.sleep(600)  # 10 dəqiqə gözlə
            
    except KeyboardInterrupt:
        print("Çoxşəbəkə monitorinqi dayandırıldı")
        for i, detector in enumerate(detectors):
            print(f"Şəbəkə {i+1} son hesabat:")
            detector.generate_final_report()

if __name__ == "__main__":
    multi_config_monitoring()
```

## 📊 Məhsuldarlıq Nümunələri

### 1. Gündəlik Hesabat Generasiyası
```python
#!/usr/bin/env python3
# daily_report.py

import json
from datetime import datetime, timedelta
from src.core.detector import C2Detector

def generate_daily_report():
    """Gündəlik avtomatik hesabat"""
    
    detector = C2Detector("config/production.json")
    detector.setup_environment()
    
    # 24 saatlıq məlumatları analiz et
    detector.zeek_parser.read_historical(days=1)
    detector.dns_analyzer.process_dns_data(detector.zeek_parser)
    
    # Hesabat yarat
    report = {
        'date': datetime.now().strftime('%Y-%m-%d'),
        'analysis_period': '24 hours',
        'statistics': detector.dns_analyzer.generate_detailed_report(),
        'alerts_generated': detector.alert_count
    }
    
    # Fayla yaz
    report_file = f"reports/daily_report_{datetime.now().strftime('%Y%m%d')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"Gündəlik hesabat {report_file} faylına yazıldı")
    return report

if __name__ == "__main__":
    generate_daily_report()
```

### 2. Performance Monitorinqi
```python
#!/usr/bin/env python3
# performance_monitor.py

import time
import psutil
from src.core.detector import C2Detector

def monitor_performance():
    """Sistem performansını monitor et"""
    
    detector = C2Detector("config/production.json")
    
    performance_data = []
    
    try:
        while True:
            # Sistem metrikaları
            cpu_percent = psutil.cpu_percent()
            memory_info = psutil.virtual_memory()
            disk_usage = psutil.disk_usage('/')
            
            # Detector statistikaları
            detector_stats = {
                'timestamp': time.time(),
                'cpu_percent': cpu_percent,
                'memory_percent': memory_info.percent,
                'disk_free_gb': disk_usage.free / (1024**3),
                'alerts_count': detector.alert_count,
                'data_processed': len(detector.zeek_parser.df) if detector.zeek_parser.df else 0
            }
            
            performance_data.append(detector_stats)
            
            # Hər 5 dəqiqədə bir statistikaları yaz
            if len(performance_data) % 12 == 0:  # 5 dəqiqə * 12 = 1 saat
                save_performance_data(performance_data)
                performance_data = []
            
            time.sleep(300)  # 5 dəqiqə gözlə
            
    except KeyboardInterrupt:
        save_performance_data(performance_data)
        print("Performance monitorinqi dayandırıldı")

def save_performance_data(data):
    """Performance məlumatlarını saxla"""
    if data:
        filename = f"performance_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Performance məlumatları {filename} faylına yazıldı")

if __name__ == "__main__":
    monitor_performance()
```

## 🔧 Fərdiləşdirilmə Nümunələri

### 1. Xüsusi Alert Formatı
```python
#!/usr/bin/env python3
# custom_alerts.py

from src.core.detector import C2Detector
from datetime import datetime

class CustomAlertDetector(C2Detector):
    """Xüsusi alert formatı ilə detector"""
    
    def raise_alert(self, alert):
        """Xüsusi alert formatı"""
        # Əsas alert işləmə
        super().raise_alert(alert)
        
        # Əlavə xüsusi emal
        custom_alert = {
            'timestamp': datetime.now().isoformat(),
            'detector_version': '2.0.0-custom',
            'environment': 'production',
            **alert  # Orijinal alert məlumatları
        }
        
        # Xüsusi alert faylına yaz
        self._save_custom_alert(custom_alert)
    
    def _save_custom_alert(self, alert):
        """Xüsusi alert formatında saxla"""
        custom_file = "data/alerts/custom_alerts.jsonl"
        with open(custom_file, 'a') as f:
            f.write(json.dumps(alert) + '\n')

# İstifadə
detector = CustomAlertDetector("config/production.json")
```

### 2. Xarici API İnteqrasiyası
```python
#!/usr/bin/env python3
# api_integration.py

import requests
from src.core.detector import C2Detector

class APIDetector(C2Detector):
    """Xarici API inteqrasiyası ilə detector"""
    
    def __init__(self, config_path):
        super().__init__(config_path)
        self.api_url = "https://api.security-platform.com/alerts"
        self.api_key = "your-api-key-here"
    
    def raise_alert(self, alert):
        """Alertı yerli və xarici API-ə göndər"""
        # Əsas emal
        super().raise_alert(alert)
        
        # Xarici API-ə göndər
        try:
            response = requests.post(
                self.api_url,
                json=alert,
                headers={
                    'Authorization': f'Bearer {self.api_key}',
                    'Content-Type': 'application/json'
                },
                timeout=10
            )
            
            if response.status_code == 200:
                print("Alert uğurla API-ə göndərildi")
            else:
                print(f"API xətası: {response.status_code}")
                
        except Exception as e:
            print(f"API göndərilmə xətası: {e}")

# İstifadə
detector = APIDetector("config/production.json")
```

---

**Növbəti:** [Docs-in Tamamlanması]

Bu sənəd C2 Detector sisteminin müxtəlif istifadə nümunələrini və senaryolarını əhatə edir. Bütün sənədləşdirmə artıq tamamlanmışdır.
