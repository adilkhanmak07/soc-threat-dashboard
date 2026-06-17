# SOC Threat Dashboard

I built this project to understand what SOC analysts actually do — not just read about it. It takes network traffic logs, runs them through custom detection engines, and shows everything in a live dashboard you can filter and explore.

The detection logic covers five real attack types. The dashboard gives you the kind of view a Tier 1 analyst would have at the start of a shift — total events, active threats, top attacker IPs, and a live feed of the last 50 alerts.

> **Stack:** Python · Pandas · Streamlit · Plotly

---

## How the detection works

Each attack type has its own detection function with real thresholds:

| Attack | Logic | Severity |
|---|---|---|
| Port Scan | One IP touches 10+ different ports in a 10-min window | Low |
| Brute Force | 5+ login attempts to SSH / RDP / FTP from same IP in 5 min | High |
| DDoS | 50+ connections flood one server in under 60 seconds | Critical |
| SQL Injection | High-frequency hits on database ports 3306 and 5432 | High |
| Malware C2 | Long-duration outbound connections to ports like 4444, 8080, 6666 | Critical |

After detection, the script writes a plain-text incident report with the top threats and what to do about each one.

---

## What's in the dashboard

**KPI row** — total events, attack count, % of traffic that's malicious, critical alerts, high alerts, unique attacker IPs

**Charts**
- Attack volume per hour across 7 days (area chart)
- Attack type breakdown
- Severity split — Critical / High / Low
- Top 8 attacker IPs ranked by event count
- TCP vs UDP ratio
- Most targeted ports, coloured by attack type

**Live alert feed** — last 50 threats sorted newest first, with source IP, target, port, type, severity and bytes

**IP investigation** — click any attacker IP and get their full profile: which attacks they ran, which ports they hit, which internal machines they targeted, and a 30-min activity timeline showing when they were most active

**Sidebar filters** — date range, attack type, severity, protocol, IP search

---

## Running it locally

```bash
git clone https://github.com/adilkhanmak07/soc-threat-dashboard.git
cd soc-threat-dashboard

pip install pandas streamlit plotly faker

python generate_logs.py    # creates network_logs.csv (5,000 rows)
python analyze_logs.py     # runs detection, creates flagged_attacks.csv + report
streamlit run dashboard.py # opens at http://localhost:8501
```

---

## Project files

```
soc-dashboard/
├── generate_logs.py      # generates realistic network traffic (normal + attacks)
├── analyze_logs.py       # detection engines + incident report writer
├── dashboard.py          # Streamlit app
├── network_logs.csv      # full traffic log
├── flagged_attacks.csv   # confirmed attack events only
├── analysis_report.txt   # written SOC report with recommendations
└── README.md
```

---

## What I got out of building this

Going in I knew Python basics. Building this taught me:

- What log fields actually matter to a SOC analyst (src IP, dst port, bytes, duration)
- Why time-window detection matters — a single connection to port 22 is fine, 50 in 5 minutes is a brute force
- How Splunk and QRadar do what they do under the hood — it's basically the same logic, just at a larger scale
- The difference between a Tier 1 alert (flag it) and a Tier 2 investigation (understand it)
- How to present threat data so a manager with no security background can read it

---

## What I'd add next

- Connect to real logs via Syslog or Windows Event Viewer instead of generated data
- VirusTotal API integration to check attacker IPs against known threat feeds
- World map showing where attacks are originating from (GeoIP)
- PDF export for the incident report
- Anomaly detection using Isolation Forest instead of fixed thresholds

---

**Muhammad Adil**
adilkhanmak07@gmail.com · [LinkedIn](https://www.linkedin.com/in/muhammad-adil-7760593ba/) · [GitHub](https://github.com/adilkhanmak07)
