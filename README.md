# 🛡️ SOC Threat Dashboard

A real-time Security Operations Center (SOC) dashboard built in Python that ingests network logs, detects five categories of cyber attacks, and visualizes threats through an interactive web interface — simulating the tools used by professional SOC analysts.

![Dashboard Preview](https://img.shields.io/badge/Status-Live-brightgreen) ![Python](https://img.shields.io/badge/Python-3.11-blue) ![Streamlit](https://img.shields.io/badge/Streamlit-1.x-red) ![Plotly](https://img.shields.io/badge/Plotly-5.x-purple)

---

## 📌 Project Overview

This project simulates a real-world SOC environment where a security analyst monitors live network traffic, detects threats, investigates suspicious IPs, and generates incident reports — all from a single dashboard.

It was built to demonstrate practical cybersecurity skills including log analysis, threat detection logic, SIEM concepts, and security data visualization.

---

## 🔍 What It Does

- Generates **5,000 realistic network log entries** spanning 7 days of traffic
- Detects **5 real attack types** using rule-based detection engines
- Displays a **live threat dashboard** with filters, charts, and an alert feed
- Produces a **written incident report** with prioritized recommendations
- Allows **IP-level investigation** — drill into any attacker to see their full activity profile

---

## 🚨 Attack Types Detected

| Attack | Detection Method | Severity |
|---|---|---|
| **Port Scan** | One IP hitting 10+ unique ports within 10 minutes | Low |
| **Brute Force** | 5+ login attempts to SSH/RDP/FTP from same IP in 5 minutes | High |
| **DDoS** | 50+ connections to same destination in 1 minute | Critical |
| **SQL Injection** | High-frequency requests to database ports (3306, 5432) | High |
| **Malware C2** | Long-duration connections to unusual ports (4444, 8080, 6666) | Critical |

---

## 📊 Dashboard Features

**KPI Cards**
- Total events in view
- Attacks detected + percentage of all traffic
- Critical alerts count
- High alerts count
- Unique attacker IPs

**Charts & Visualizations**
- Attack timeline (area chart — hourly attack volume over 7 days)
- Attack type breakdown (horizontal bar chart)
- Severity split (donut chart — Critical / High / Low)
- Top 8 attacker IPs by event count
- TCP vs UDP protocol distribution
- Most targeted ports coloured by attack type

**Live Alert Feed**
- Last 50 threats, newest first
- Shows: timestamp, source IP, target IP, port, attack type, severity, bytes, protocol

**IP Investigation Panel**
- Select any attacker IP
- See total events, attack types used, unique targets, total bytes sent
- Port targeting breakdown
- 30-minute activity timeline

**Sidebar Filters**
- Date range picker
- Attack type filter
- Severity filter (Critical / High / Low)
- Protocol filter (TCP / UDP)
- Source IP search

---

## 🛠️ Tech Stack

| Tool | Purpose |
|---|---|
| **Python 3.11** | Core language |
| **Pandas** | Log ingestion, time-window grouping, detection logic |
| **Streamlit** | Web dashboard framework |
| **Plotly** | Interactive charts and visualizations |
| **Faker** | Realistic IP address and log data generation |

---

## 📁 Project Structure

```
soc-dashboard/
│
├── generate_logs.py      # Generates 5,000 realistic network log entries
├── analyze_logs.py       # Runs 5 threat detection engines, outputs report
├── dashboard.py          # Streamlit web dashboard (main app)
│
├── network_logs.csv      # Generated log data (created by generate_logs.py)
├── flagged_attacks.csv   # Detected attack events (created by analyze_logs.py)
├── analysis_report.txt   # Written incident report with recommendations
│
└── README.md
```

---

## ⚙️ How to Run Locally

**1. Clone the repository**
```bash
git clone https://github.com/adilkhanmak07/soc-threat-dashboard.git
cd soc-threat-dashboard
```

**2. Install dependencies**
```bash
pip install pandas streamlit plotly faker
```

**3. Generate the log data**
```bash
python generate_logs.py
```

**4. Run the threat detection engine**
```bash
python analyze_logs.py
```

**5. Launch the dashboard**
```bash
streamlit run dashboard.py
```

Open your browser at `http://localhost:8501`

---

## 📄 Sample Incident Report Output

```
============================================================
  SOC THREAT ANALYSIS REPORT
  Generated: 2026-06-17 14:32:01
============================================================

[ EXECUTIVE SUMMARY ]
  Total log entries   : 5,000
  Normal traffic      : 3,500
  Attack events       : 1,500  (30.0% of all traffic)
  Busiest attack hour : 14:00

[ ATTACKS BY TYPE ]
  DDoS                  305
  Port Scan             310
  Brute Force           298
  Malware C2            296
  SQL Injection         291

[ RECOMMENDATIONS ]
  1. Block IP 203.x.x.x — top port scanner (47 unique ports in 10 min)
  2. Lock accounts targeted by brute force on port 22
  3. Enable rate limiting — server received 78 hits in 60 seconds
  4. Isolate hosts with Malware C2 connections — possible compromise
  5. Investigate 12 large data transfers — possible exfiltration
```

---

## 💡 Key Concepts Demonstrated

- **Log Analysis** — parsing and querying structured network log data
- **Time-window detection** — grouping events by sliding time windows to find patterns
- **SIEM simulation** — replicating the core detection logic of tools like Splunk and IBM QRadar
- **Threat triage** — assigning severity levels (Critical / High / Low) to prioritize analyst response
- **Incident reporting** — generating written reports with actionable recommendations
- **Data visualization** — presenting security data in a format useful for both analysts and management

---

## 🔮 Future Improvements

- [ ] Connect to a real log source (Syslog, Windows Event Logs)
- [ ] Add email/SMS alerting when Critical threats are detected
- [ ] Integrate with VirusTotal API to check attacker IPs against threat intelligence feeds
- [ ] Add GeoIP mapping to show attacker countries on a world map
- [ ] Export incident reports as PDF with one click
- [ ] Add machine learning anomaly detection (Isolation Forest)

---

## 👤 About

Built by **Muhammad Adil** — Software Engineering graduate with a focus on cybersecurity and security operations.

📧 adilkhanmak07@gmail.com
💼 [Muhammad Adil | LinkedIn](https://www.linkedin.com/in/muhammad-adil-7760593ba/)
🐙 [GitHub](https://github.com/adilkhanmak07)
