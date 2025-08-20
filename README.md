# 🕵️ Stealthy C2 Beacon Detector

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zeek Integration](https://img.shields.io/badge/Zeek-Integrated-green.svg)](https://zeek.org/)

A professional-grade detection system for identifying Command & Control (C2) beaconing and DNS tunneling activities in network traffic.

## 🚀 Features

- **Real-time DNS Monitoring**: Live analysis of DNS queries for immediate threat detection
- **Advanced Anomaly Detection**: Multiple detection algorithms working in concert
- **DNS Tunneling Identification**: Detection of covert channels in DNS traffic
- **Beaconing Pattern Recognition**: Identification of regular C2 callbacks
- **Professional Logging**: Structured JSON logging with rotation and monitoring
- **Configurable Thresholds**: Customizable detection parameters for different environments
- **Comprehensive Reporting**: Detailed statistical analysis and alert summaries

## 🛡️ What We Detect

- **DNS Tunneling** (DNSCat2, Iodine, etc.)
- **C2 Beaconing Activity** (Regular callbacks to C2 servers)
- **Data Exfiltration** via DNS queries
- **Suspicious Domain Patterns** (High entropy, long domains)
- **Unusual DNS Record Types** (TXT, NULL, ANY queries)
- **Anomalous Query Volumes** (Excessive DNS requests)

## 📊 Detection Methods

| Method | Description | Effectiveness |
|--------|-------------|---------------|
| Entropy Analysis | Detects random-looking domain names | ⭐⭐⭐⭐⭐ |
| Query Volume Monitoring | Identifies excessive DNS requests | ⭐⭐⭐⭐ |
| Temporal Pattern Analysis | Finds regular beaconing intervals | ⭐⭐⭐⭐⭐ |
| Protocol Anomaly Detection | Flags unusual DNS record types | ⭐⭐⭐ |
| Domain Length Analysis | Catches long domain names | ⭐⭐⭐⭐ |

## 🏗️ Architecture

```mermaid
graph TD
    A[Network Traffic] --> B(Zeek Sensor)
    B --> C[DNS Logs]
    C --> D{Log Parser}
    D --> E[Real-time Processing]
    D --> F[Historical Analysis]
    E --> G[Anomaly Detection]
    F --> G
    G --> H[Alert Generation]
    H --> I[Cortex XSIAM]
    H --> J[Local Storage]
    H --> K[Console Alerts]
