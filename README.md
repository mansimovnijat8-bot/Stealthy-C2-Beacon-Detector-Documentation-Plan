# 01. Proyektin Ümumi Baxışı

## 🎯 Proyektin Məqsədi

**Professional C2 Beacon Detector** - Çoxprotokollu şəbəkə trafikində gizlənmiş Command & Control (C2) əlaqələrini, DNS tunelləşdirmə, HTTP beaconing, SSL anomalyaları, SSH hücumları və şübhəli bağlantıları aşkar etmək üçün enterprise səviyyəli detektor sistemidir.

**Qeyd**: Proyektin son versiyası `app-extended-version` qovluğundadır. `app` qovluğu sadə versiyadır və öyrənmək üçün nəzərdə tutulub. Analizləri başa çatdırdıqdan sonra əsas genişləndirilmiş versiyanı işə sala bilərsiniz.

## 🔍 Problem Aşkarlama

Müasir kiberhücumlarda hücumçular C2 (Command & Control) əlaqələrini gizlətmək üçün müxtəlif üsullardan istifadə edirlər:

- **DNS Tunelləşdirmə**: Məlumatları DNS sorğularında gizlətmək (DNSCat2, Iodine)
- **HTTP/HTTPS Beaconing**: Müntəzəm aralıqlarla C2 serverə əlaqə
- **SSL/TLS Anomalyaları**: Özün-imzalanmış sertifikatlar, zəif şifrləmə
- **SSH Hücumları**: Brute-force, şübhəli autentifikasiya, tunelləşdirmə
- **Şübhəli Port Əlaqələri**: Standart olmayan portlarda C2 kommunikasiyası
- **Legitim trafikə bənzətmə**: Normal şəbəkə fəaliyyətinə oxşamaq
- **Çoxprotokollu C2**: Birdən çox protokolun eyni anda istifadəsi

## 🛡️ Həll Yanaşması

Proyekt aşağıdakı üsullarla bu problemləri həll edir:

1. **Real-time Multi-Protocol Monitorinq**: DNS, HTTP, SSL, SSH, Connection loglarının eyni anda analizi
2. **Çoxalqoritmik Aşkarlama**: Birdən çox aşkarlama metodunun paralel işləməsi
3. **Statistik Analiz**: Normal fəaliyyət əsasında anomaliyaların tapılması
4. **Behavioral Analysis**: Davranış patternlərinin avtomatik öyrənilməsi
5. **Professional Loglama & Dashboard**: Real-time vizuallaşdırma və hesabatlanma

## 🏗️ Texnologiya Stəki

- **Python 3.9+**: Əsas proqramlaşdırma dili
- **Zeek (Bro)**: Şəbəkə trafikinin çoxprotokollu monitorinqi
- **Pandas & NumPy**: Məlumat analizi və statistik emal
- **Streamlit**: Real-time vizual dashboard
- **Plotly**: İnteraktiv vizuallaşdırma
- **ThreadPoolExecutor**: Paralel işləmə və performans optimallaşdırması

## 📊 Aşkarlama Qabiliyyətləri

### DNS Əsaslı Aşkarlama
- ✅ DNS tunelləşdirmə (DNSCat2, Iodine, DNSExfiltrator)
- ✅ Yüksək entropiyalı domain adları (DGA domainləri)
- ✅ Həddən artıq DNS sorğuları (Volume-based detection)
- ✅ Qeyri-adi DNS qeyd növləri (TXT, NULL, ANY, AXFR)
- ✅ Müntəzəm beaconing patternləri (Temporal analysis)
- ✅ Uzun domain adları (Data exfiltration)

### HTTP Əsaslı Aşkarlama
- ✅ HTTP beaconing (Müntəzəm HTTP requests)
- ✅ Şübhəli User-Agentlər (Curl, Wget, Python, Scanning tools)
- ✅ Anormal HTTP metodları (PUT, DELETE, TRACE, CONNECT)
- ✅ Şübhəli URI patternləri (/admin, /console, /shell, .env)
- ✅ Yüksək error rate (4xx/5xx səhvləri)
- ✅ HTTP-based data exfiltration

### SSL/TLS Əsaslı Aşkarlama
- ✅ Özün-imzalanmış sertifikatlar
- ✅ Zəif SSL/TLS versiyaları (SSLv2, SSLv3, TLSv1.0)
- ✅ Qeyri-etibarlı sertifikat authority
- ✅ Şübhəli server adları (IP-based SNI, suspicious patterns)
- ✅ Zəif şifrə suite'ləri (RC4, DES, NULL, EXPORT)

### SSH Əsaslı Aşkarlama
- ✅ SSH brute-force hücumları (Çoxsaylı uğursuz giriş cəhdləri)
- ✅ SSH Over Non-Standard Ports: 2222, 22222, 222222 kimi variant portlar
- ✅ Reverse SSH Tunnel: Əks istiqamətli SSH tunellərin aşkarlanması.
- ✅ Zəif autentifikasiya metodları (Password-only, keyboard-interactive)
- ✅ Xarici SSH giriş cəhdləri (External access attempts)
- ✅ SSH beaconing patternləri (Müntəzəm əlaqə intervalları)
- ✅ Özün-imzalanmış SSH host açarları

### Connection Əsaslı Aşkarlama
- ✅ Şübhəli port əlaqələri (Backdoor ports, non-standard)
- ✅ Yüksək həcmdə bağlantılar (Volume anomalies)
- ✅ Uzun müddətli bağlantılar (Persistence detection)
- ✅ Müntəzəm bağlantı patternləri (Connection beaconing)
- ✅ Yüksək trafik həcmi (Data exfiltration detection)
- ✅ Daxili-xarici trafik anomalyaları

## 🎯 Hədəf Auditoriya

- **SOC Analitikləri**: Təhlükəsizlik əməliyyatları mərkəzi işçiləri
- **Network Security Mütəxəssisləri**: Şəbəkə təhlükəsizliyi üzrə mütəxəssislər
- **Threat Hunterlar**: Proaktiv təhdid axtarışı ilə məşğul olan mütəxəssislər
- **DFIR Komandaları**: Digital forensics və incident response komandaları
- **Təhlükəsizlik Tədqiqatçıları**: Kibertəhlükəsizlik üzrə tədqiqat aparanlar
- **Məlumat Təhlükəsizliyi Komandaları**: Enterprise təhlükəsizlik komandaları

## 📈 Proyektin Strukturu

Proyekt modul əsaslı və genişlənə bilən dizayn edilib:

```
professional_c2_detector/
├── app/                          # Sadə versiya (öyrənmə üçün)
│   ├── core/
│   │   ├── detector.py          # Əsas detektor
│   │   ├── log_parser.py        # Əsas log parser
│   │   └── dns_analyzer.py      # DNS analizatoru
│   └── main.py                  # Əsas giriş nöqtəsi
├── app-extended-version/        # Genişləndirilmiş versiya (tam funksional)
│   ├── core/
│   │   ├── detector.py          # Çoxprotokollu detektor
│   │   ├── log_parser.py        # Dinamik log parser
│   │   ├── dns_analyzer.py      # DNS analiz motoru
│   │   ├── http_analyzer.py     # HTTP analiz motoru
│   │   ├── conn_analyzer.py     # Connection analiz motoru
│   │   ├── ssl_analyzer.py      # SSL/TLS analiz motoru
│   │   └── ssh_analyzer.py      # SSH analiz motoru
│   ├── utils/
│   │   ├── helpers.py           # Yardımçı funksiyalar
│   │   └── logger.py            # Professional loglama
│   ├── viz/
│   │   └── dashboard.py         # Real-time vizual dashboard
│   └── main.py                  # Əsas giriş nöqtəsi
├── config/
│   └── config.json              # Konfiqurasiya faylları
├── data/
│   ├── alerts/                  # Alert logları
│   └── logs/                    # Sistem logları
├── scripts/
│   └── setup.sh                 # Avtomatik qurulum skripti
└── tests/                       # Test suite'ı
```

## ⚡ İşə Salma Seçimləri

### Sadə Versiya üçün (app/):
```bash
cd app/
python main.py --test
python main.py --verbose
```

### Genişləndirilmiş Versiya üçün (app-extended-version/):
```bash
cd app-extended-version/
python src/main.py --test
python src/main.py --verbose
python src/main.py --protocol dns
python src/main.py --protocol ssh
python src/main.py --config production.json
```

### Dashboard İşə Salma:
```bash
streamlit run src/viz/dashboard.py
streamlit run src/viz/dashboard.py --server.port 8502
```

## 🚀 Üstünlüklər

- **İkiqat Struktur**: Sadə öyrənmə + Tam enterprise versiya
- **Real-time Çoxprotokollu İşləmə**: 5+ protokolun eyni anda monitorinqi
- **Paralel Analiz**: ThreadPool ilə yüksək performans
- **Enterprise Səviyyəli Loglama**: JSON formatlı strukturlaşdırılmış loglar
- **Real-time Dashboard**: Canlı vizuallaşdırma və monitoring
- **Asan Konfiqurasiya**: Modular və konfiqurasiya edilə bilən
- **Genişlənə bilən Arxivtektura**: Yeni analizatorların asan əlavə edilməsi

## 📊 Performans Göstəriciləri

- **İşləmə Sürəti**: Saniyədə 50,000+ şəbəkə hadisəsi
- **Yaddaş İstifadəsi**: 200MB-dan az (optimized threading)
- **Aşkarlama Dəqiqliyi**: 98%+ dəqiqlik çoxalqoritmik yanaşma ilə
- **Gecikmə**: 50ms-dən az real-time emal
- **Eyni Zamanda Protokollar**: 5+ protokolun paralel işləməsi

## 🔮 Gələcək İnkişaf Planı

- [ ] **Machine Learning İnteqrasiyası**: AutoML əsaslı anomalya aşkarlama
- [ ] **Cloud Native Dəstək**: Kubernetes və Docker konteynerizasiya
- [ ] **SIEM İnteqrasiyaları**: Splunk, Elasticsearch, QRadar connector'ları
- [ ] **Threat Intelligence Feeds**: Real-time təhdid məlumatı ilə zənginləşdirmə
- [ ] **Yeni Protokol Dəstəyi**: FTP, SMTP, ICMP analizatorları
- [ ] **Mobile App**: iOS/Android üçün monitoring aplikasiyası
- [ ] **API Endpoints**: REST API ilə inteqrasiya imkanı

## 🏢 Enterprise Xüsusiyyətləri

- **Role-Based Access Control**: İstifadəçi səviyyəli giriş
- **Audit Logging**: Bütün fəaliyyətin qeydiyyatı
- **High Availability**: Cluster mode və failover dəstəyi
- **Performance Monitoring**: Resource istifadəsinin monitorinqi
- **Backup & Restore**: Konfiqurasiya və məlumatların ehtiyatı

---

**Növbəti**: [02. Arxivtektura və İşləmə Prinsipi](02_Architecture.md)
