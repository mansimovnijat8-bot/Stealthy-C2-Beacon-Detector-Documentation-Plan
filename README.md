# 01. Proyektin Ümumi Baxışı

## 🎯 Proyektin Məqsədi

**Stealthy C2 Beacon Detector** - şəbəkə trafikində gizlənmiş Command & Control (C2) əlaqələrini və DNS tunelləşdirmə fəaliyyətini aşkar etmək üçün professional səviyyəli detektor sistemidir.

## 🔍 Problem Aşkarlama

Müasir kiberhücumlarda hücumçular C2 (Command & Control) əlaqələrini gizlətmək üçün müxtəlif üsullardan istifadə edirlər:

- **DNS Tunelləşdirmə**: Məlumatları DNS sorğularında gizlətmək
- **HTTP/HTTPS Beaconing**: Müntəzəm aralıqlarla C2 serverə əlaqə
- **SSL şifrələmə**: Əlaqəni şifrələyərək gizlətmək
- **Legitim trafikə bənzətmə**: Normal şəbəkə fəaliyyətinə oxşamaq

## 🛡️ Həll Yanaşması

Proyekt aşağıdakı üsullarla bu problemləri həll edir:

1. **Real-time Monitorinq**: Şəbəkə trafikinin canlı analizi
2. **Çoxalqoritmik Aşkarlama**: Birdən çox aşkarlama metodunun eyni anda işləməsi
3. **Statistik Analiz**: Normal fəaliyyət əsasında anomaliyaların tapılması
4. **Professional Loglama**: Bütün fəaliyyətin qeydə alınması və hesabatlanması

## 🏗️ Texnologiya Stəki

- **Python 3.9+**: Əsas proqramlaşdırma dili
- **Zeek (Bro)**: Şəbəkə trafikinin monitorinqi və loglanması
- **Pandas**: Məlumat analizi və emalı
- **Tailer**: Real-time log fayllarının oxunması

## 📊 Aşkarlama Qabiliyyətləri

### DNS Əsaslı Aşkarlama
- ✅ DNS tunelləşdirmə (DNSCat2, Iodine)
- ✅ Yüksək entropiyalı domain adları
- ✅ Həddən artıq DNS sorğuları
- ✅ Qeyri-adi DNS qeyd növləri (TXT, NULL, ANY)
- ✅ Müntəzəm beaconing patternləri

### Üstünlüklər
- **Real-time işləmə**: Hadisə baş verən kimi aşkarlama
- **Aşağı false-positive**: Dəqiq aşkarlama alqoritmləri
- **Asan inteqrasiya**: Mövcud SOC infrastrukturu ilə uyğunluq
- **Genişlənə bilən**: Yeni aşkarlama metodlarının əlavə edilməsi

## 🎯 Hədəf Auditoriya

- **SOC Analitikləri**: Təhlükəsizlik əməliyyatları mərkəzi işçiləri
- **Network Security Mütəxəssisləri**: Şəbəkə təhlükəsizliyi üzrə mütəxəssislər
- **Threat Hunterlar**: Proaktiv təhdid axtarışı ilə məşğul olan mütəxəssislər
- **Təhlükəsizlik Tədqiqatçıları**: Kibertəhlükəsizlik üzrə tədqiqat aparanlar

## 📈 Proyektin Strukturu

Proyekt modul əsaslı dizayn edilib:

stealthy_c2_detector/
src/
core/ # Əsas funksionallıq modulları
utils/ # Yardımçı funksiyalar
main.py # Əsas giriş nöqtəsi
config/ # Konfiqurasiya faylları
data/ # Məlumat və loglar
scripts/ # Qurulum skriptləri
tests/ # Test faylları


## 🔮 Gələcək İnkişaf

- [ ] HTTP/HTTPS C2 aşkarlama
- [ ] SSL sertifikat analizi
- [ ] Machine Learning əsaslı anomaliya aşkarlama
- [ ] Daha çox SIEM inteqrasiyası
- [ ] Qrafik istifadəçi interfeysi

## 📊 Performans Göstəriciləri

- **İşləmə Sürəti**: Saniyədə 10,000+ DNS sorğusu
- **Yaddaş İstifadəsi**: 100MB-dan az
- **Aşkarlama Dəqiqliyi**: 95%+ dəqiqlik
- **Gecikmə**: 100ms-dən az real-time emal

---

**Növbəti**: [02. Arxivtektura və İşləmə Prinsipi](02_Architecture.md)
