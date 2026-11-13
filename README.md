<p align="center">
  <img src="static/img/gasha-logo.svg" alt="Gasha Logo" width="120" />
</p>

# Gasha — Enterprise Cybersecurity & Threat Intelligence Platform

> **Gasha** (ጋሻ) is inspired by the traditional Ethiopian shield carried by warriors for defense. The platform serves as a modern digital defensive shield — providing real-time threat intelligence, automated security audits, multi-vector scanning engines, and interactive SecOps training.

<p align="center">
  <img src="https://img.shields.io/badge/Gasha-SOC%20v2.4-7c3aed?style=for-the-badge&logo=shield&logoColor=white" alt="Gasha SOC v2.4" />
  <img src="https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Framework-Flask%20%7C%20WSGI-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask" />
  <img src="https://img.shields.io/badge/Database-MySQL%20%2F%20MariaDB-4479A1?style=for-the-badge&logo=mysql&logoColor=white" alt="MySQL" />
  <img src="https://img.shields.io/badge/Security-NIST%20%7C%20MITRE%20ATT%26CK-success?style=for-the-badge&logo=security&logoColor=white" alt="Security" />
</p>

---

## 👥 Project Team Members

| # | Full Name | Student ID (CTC) |
| :-: | :--- | :--- |
| **1** | **Bereket Bahiru Nisrane** | `CTC-1144-26` |
| **2** | **Samuel Teshome Wakjira** | `CTC-2631-26` |
| **3** | **Rihana Abdu** | `CTC-6285-26` |
| **4** | **Betselot Solomon** | `CTC-2200-26` |
| **5** | **Natnael Kifle Workeneh** | `CTC-1532-26` |
| **6** | **Fikre Hailemariam** | `CTC-1751-26` |

---

## 🎥 Project Demonstration & Overview Videos

### 👤 Project Overview by Bereket Bahiru (`CTC-1144-26`)
Walkthrough of the Gasha SOC Architecture, implementation details, and live platform operations presented by Bereket Bahiru:

* 🎬 **Video File**: [docs/videos/bereket_bahiru_overview.mp4](file:///c:/Users/Bereket/Desktop/IMS/safeguard-cybersecurity-platform/docs/videos/bereket_bahiru_overview.mp4) (Direct link: `docs/videos/bereket_bahiru_overview.mp4`)

<video src="docs/videos/bereket_bahiru_overview.mp4" controls="controls" width="100%"></video>

### 🌐 Full Platform Demonstration
* 📹 **Online Demo**: [Watch Full Demo on Google Drive](https://drive.google.com/file/d/1Ah7ZTmOpPyFluWXgHDphJGS-913Tb6dN/view?usp=sharing)

---

## 📌 Project Overview

**Gasha** is a full-featured, lightweight Security Operations Center (SOC) web application built for defensive security monitoring, heuristic threat detection, and incident response preparation.

The platform provides a centralized dashboard that unifies seven distinct heuristic security scanners, live threat intelligence feeds, MITRE ATT&CK taxonomy alignments, incident handling playbooks, and an interactive learning academy.

### 🎯 Primary Objectives
- **Proactive Threat Detection**: Analyze URLs, emails, messages, headers, and IP addresses before threats infiltrate the perimeter.
- **Incident Response Readiness**: Equip analysts with structured playbooks, MITRE ATT&CK mapping, and active CVE feeds.
- **Zero-Knowledge Security Audits**: Perform client-side and server-side entropy audits without ever persisting raw passwords or secrets.
- **Interactive Training & Knowledge**: Bridge the skills gap with interactive scenario-based quizzes, masterclass courses, and cheatsheets.

---

## ⚡ Core Modules & Features

### 1. 🔍 Heuristic Security Analysis Hub (`/engine`)
- **URL & Typosquatting Radar**: Detects brand spoofing, Levenshtein typosquatting, Cyrillic/Greek homoglyphs, and high-risk TLDs.
- **Phishing & Social Engineering NLP**: Flags urgency keywords, credential harvesting prompts, and financial pressure patterns.
- **Data Breach Checker**: Cross-references identifiers against compromise databases and catalogs exposed sensitive information.
- **Zero-Knowledge Password Auditor**: Calculates NIST entropy bits and computes realistic GPU cluster brute-force timelines without storing passwords.
- **HTTP Header Inspector**: Live audit of external web perimeters (CSP, HSTS, X-Frame-Options, X-Content-Type) with remediation grades ($A^+$ to $F$).
- **IP & ASN Intelligence**: Verifies Bogon/RFC-1918 status, geo-location, ASN routing, and VPN/proxy threat indicators.
- **Cryptographic Suite**: Hash calculation (MD5, SHA-1, SHA-256, SHA-512), automatic hash identification, and encoding transforms (Base64, Hex, URL, ROT13).

### 2. 🚨 Threat Intelligence & MITRE ATT&CK
- **Live CVE Feed**: Real-time vulnerability stream cross-referenced with CISA KEV and CVSS v3.1 severity scores.
- **MITRE ATT&CK Matrix**: Tactical alignment with real-world enterprise adversary techniques.
- **Incident Playbooks**: Standard Operating Procedures (SOPs) for Ransomware containment, Phishing response, and BEC fraud.

### 3. 🎓 SecOps Academy & Learning Center
- **Course Modules**: Embedded video lectures and structured cybersecurity learning tracks.
- **Interactive Quizzes**: Scenario-based assessments with immediate rationale explanations and score tracking.
- **Security Cheatsheets**: Downloadable quick-reference manuals for network triage, incident command, and Linux hardening.

---

## 🛠️ Technology Stack

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Backend** | Python 3.10+ | Core application logic and heuristic engines |
| **Framework** | Flask 2.3+ / WSGI | REST API endpoints, routing, and session management |
| **Database** | MySQL / MariaDB | Persistent storage for users, scans, telemetry, and quizzes |
| **Connection Pooling** | DBUtils (`PooledDB`) | Low-latency reusable database connection pool |
| **Security Layer** | PBKDF2 / SHA-256 | Secure password hashing, CSRF protection, and rate limiting |
| **Frontend** | HTML5, CSS3, ES6+ JavaScript | Modern Glassmorphism SOC HUD (zero heavy external frameworks) |

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- **Python 3.10+**
- **MySQL / MariaDB** (running locally via XAMPP, Docker, or native service on port `3306`)

### 2. Clone the Repository
```bash
git clone https://github.com/Beki1238/safeguard-cybersecurity-platform.git
cd safeguard-cybersecurity-platform
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment
Create a `.env` file in the root directory (or copy from `.env.example`):
```env
SECRET_KEY=your-secure-random-secret-key-32-chars
FLASK_ENV=development
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASSWORD=
DB_NAME=safeguard_db
```

### 5. Launch the Application
- **Windows**: Double-click `start.bat` or run:
  ```powershell
  python app.py
  ```
- **Linux / macOS**:
  ```bash
  python3 app.py
  ```

Open your browser at **[http://localhost:5000](http://localhost:5000)**.

---

## 🔑 Default Administrator Credentials

When the platform is initialized, a default SecOps administrator account is available:

| Field | Default Value |
| :--- | :--- |
| **Username** | `admin` |
| **Email** | `admin@safeguard.local` |
| **Password** | `Admin@123456` |
| **Role** | `Lead SecOps Officer` |

*(Note: In production environments, change the password upon initial login.)*

---

## 📄 License
This project is developed for educational and defensive cybersecurity operations purposes under the **MIT License**.
