# 🔒 Security Threat Analyzer

> A Python-based desktop application for automated security threat assessment using **STRIDE** & **DREAD** threat modeling frameworks with real-world **CVE** vulnerability lookup and PDF report generation.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
![University](https://img.shields.io/badge/Riphah-University-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

---

## 📌 Overview

Most security tools only **collect data** — this tool **analyzes it**.

The Security Threat Analyzer takes your system's service configuration, identifies threats using the **STRIDE model**, scores each threat using the **DREAD model**, matches them against real **CVE vulnerabilities** from the NIST database, and generates a **professional PDF report** — all from a clean dark-themed GUI.

---

## ⚡ Features

| Feature | Description |
|---------|-------------|
| 🛡️ STRIDE Analysis | Automatically identifies threats across 6 categories |
| 📊 DREAD Scoring | Scores each threat across 5 risk factors (1–10 scale) |
| 🔍 CVE Lookup | Real-time vulnerability data from NIST NVD API |
| 📄 PDF Reports | Professional downloadable security assessment reports |
| 🖥️ GUI Interface | Clean dark-themed desktop interface built with Tkinter |
| 📦 Offline Mode | Falls back to cached CVE data when internet is unavailable |

---

## 🧠 Workflow
```
Nmap Scan  →  Identify Running Services
                      ↓
         Input Services into Tool
         (Services + Auth + Encryption)
                      ↓
        STRIDE  →  Identify Threat Categories
                      ↓
        DREAD   →  Score Each Threat (1–10)
                      ↓
        CVE     →  Match Real-World Vulnerabilities
                      ↓
        PDF Report  →  Professional Output ✅
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- pip

### Installation
```bash
# 1. Clone the repository
git clone https://github.com/Mujtaba11Riu/Operating-System-Project.git
cd Operating-System-Project

# 2. Install dependencies
pip install requests reportlab Pillow

# 3. Run the application
python main.py
```

---

## 🗂️ Project Structure
```
security_threat_analyzer/
├── main.py                         ← Entry point
├── requirements.txt                ← Dependencies
├── gui/
│   ├── main_window.py              ← Main GUI window
│   ├── input_panel.py              ← User input forms
│   └── results_panel.py            ← Results display
├── modules/
│   ├── stride/
│   │   ├── stride_analyzer.py      ← STRIDE logic
│   │   └── threat_rules.py         ← Threat rules & conditions
│   ├── dread/
│   │   ├── dread_scorer.py         ← DREAD scoring logic
│   │   └── risk_calculator.py      ← Risk level calculator
│   ├── cve/
│   │   ├── cve_lookup.py           ← NIST NVD API integration
│   │   └── cve_parser.py           ← API response parser
│   └── report/
│       ├── report_generator.py     ← Report data collector
│       └── pdf_exporter.py         ← PDF file generator
├── data/
│   └── cve_cache.json              ← Offline CVE cache
└── outputs/
    └── reports/                    ← Generated PDF reports saved here
```

---

## 🔬 Real World Usage
```bash
# Step 1 — Scan your target with Nmap
nmap -sV target.com

# Step 2 — Note the open services
# Example output: HTTP, FTP, SSH, TELNET

# Step 3 — Input services into the tool
# Select services, set Auth & Encryption status

# Step 4 — Click Analyze Threats

# Step 5 — Download your PDF report
```

---

## 📊 Sample Report Output
```
Overall Risk: HIGH (7.5/10)

STRIDE Threats Identified:
▶ Spoofing                —  HIGH      (7.2/10)
▶ Information Disclosure  —  CRITICAL  (8.6/10)
▶ Tampering               —  HIGH      (7.0/10)
▶ Elevation of Privilege  —  HIGH      (7.2/10)

CVE Matches:
▶ CVE-1999-0082   FTP root access vulnerability       [Score: 10.0]
▶ CVE-2021-41773  Apache HTTP path traversal attack   [Score: 9.8]
```

---

## 🛠️ Built With

| Library | Purpose |
|---------|---------|
| `tkinter` | Built-in Python library — powers the entire GUI |
| `requests` | Fetches live CVE data from the NIST NVD API |
| `reportlab` | Generates professional PDF security reports |
| `Pillow` | Creates the custom shield lock application icon |

> Only 3 pip installs required — `tkinter` comes pre-installed with Python.

---

## 👨‍💻 Author

**Syed Mujtaba Zaidi**
- 🎓 BS Cyber Security — Riphah International University Islamabad
- 🌍 HackerDNA Global Rank: **#95**
- 🇵🇰 HackViser Pakistan Rank: **#20**
- 🔗 [Portfolio](https://mujtaba11riu.github.io/Portfolio1.1/)
- 💼 [LinkedIn](https://www.linkedin.com/in/syedmujtaba773/)
- 🐙 [GitHub](https://github.com/Mujtaba11Riu)

---

## 📜 License

This project is licensed under the MIT License.

---

> *"Security is not a product, but a process."* — Bruce Schneier
