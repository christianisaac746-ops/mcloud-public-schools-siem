# McLoud Public Schools — SIEM Deployment & Security Program
### Enigma Labs LLC Cybersecurity Internship · Christian Rooks · April 2026

> *Building a production SIEM for a K-12 school district on a spare PC with zero software licensing cost.*

---

## 📋 Project Overview

This repository documents the design, deployment, and ongoing operation of a Security Information and Event Management (SIEM) system for McLoud Public Schools in McLoud, Oklahoma — a real K-12 school district serving 4 campuses and 400+ students and staff.

This is not a home lab. Every log source, detection rule, alert, and finding documented here comes from live production infrastructure.

**Internship Host:** Enigma Labs LLC  
**NICE Framework Roles:** PR-CDA · PR-VAM · OV-SPP · OV-TEA · PR-CIR  
**Domain:** MCLOUD.K12.OK.US  
**Status:** Active — Phase 1 (SIEM) complete · Phase 2 (Vulnerability Management) in progress

---

## 🏫 District Overview

| Campus | Code | Grades | Network |
|--------|------|--------|---------|
| High School West | HSW | 9–12 | 10.4.0.0/24 |
| High School East | HSE | 9–12 | 10.4.2.0/24 |
| Junior High School | JHS | 6–8 | 10.4.4.0/24 |
| Intermediate Campus | INT | 5–8 | 10.5.4.0/24 |
| Early Childcare Center | ECC | Pre-K–4 | 10.5.0.0/24 |
| Elementary | ELEM | K–4 | 10.5.2.0/24 |

---

## 🛠️ SIEM Stack

| Component | Version | Role |
|-----------|---------|------|
| Graylog | 6.1.16 | SIEM platform, UI, detection engine |
| OpenSearch | 2.19.5 | Log indexing and search (4GB heap) |
| MongoDB | 6.0.27 | Configuration and metadata store |
| Ubuntu | 24.10 | Host OS |
| Winlogbeat | 8.13.0 | Windows Event Log shipper |
| Python 3 | 3.x | Google Workspace log collection |

**Server:** HomeLab1 · 10.5.1.35 · 8-core · 22GB RAM · 382GB storage  
**Total software cost: $0**

---

## 📸 Screenshots

### The Stack Coming Online

**[INSERT: Terminal1.png]**
*MongoDB `active (running)` — first service confirmed live*

**[INSERT: terminal2.png]**
*OpenSearch `active (running)` — 4GB heap allocated*

**[INSERT: graylog3.png]**
*Graylog login page — the moment it all came together*

**[INSERT: graylog4.png]**
*Graylog dashboard — fully operational, all services connected*

---

## 📥 Log Sources

Three live log sources ingesting data continuously:

### 1. Windows Event Logs
- **Protocol:** Beats (Winlogbeat 8.13)
- **Port:** 5044
- **Sources:** MPS-DC1, MPS-DC3, Jflan-Desktop1
- **Stream:** Windows Security Events — filter: `beats_type = winlogbeat`

**[INSERT: graylog5.png]**
*Windows Beats Input — live and receiving on port 5044*

**[INSERT: graylog7.png]**
*First Windows Event Logs flowing — 843 messages from a single workstation in 48 hours*

### 2. Google Workspace Audit Logs
- **Protocol:** GELF HTTP via Python script
- **Port:** 12201
- **Collection:** Admin SDK Reports API — cron every 5 minutes
- **Service Account:** graylog-workspace-reader@mcloud-siem.iam.gserviceaccount.com
- **Log types:** login, admin, drive, token

**[INSERT: graylog9.png]**
*Google Workspace audit logs — login events, Drive activity, OAuth tokens across 400+ accounts*

### 3. Cisco Network Syslog
- **Protocol:** Syslog UDP
- **Port:** 514
- **Source:** Cisco core switch

**[INSERT: graylog8.png]**
*Cisco syslog — fiber optic threshold violations caught on day one*

```
%SFF8472-3-THRESHOLD_VIOLATION: Twe1/0/2: Rx power low warning
Operating value: -14.1 dBm, Threshold value: -13.3 dBm
```

> **Finding:** Two fiber optic interfaces showing low receive power warnings — a real infrastructure finding caught by the SIEM on its first morning of operation. Flagged to IT Director same day.

---

## 🎯 Detection Rules

Seven rules running every 60 seconds against the live log stream.

**[INSERT: graylog16.png]**
*All 7 detection rules live and enabled*

| Rule | Query | Threshold | Severity |
|------|-------|-----------|----------|
| Brute Force — Windows Login | `event_code:4625` | count() ≥ 5/1min per username | HIGH |
| Account Lockout | `event_code:4740` | count() ≥ 1/5min per username | HIGH |
| After Hours Authentication | `event_code:4624` | count() ≥ 50/5min | MEDIUM |
| Privilege Escalation | `event_code:4728 OR 4732` | count() ≥ 1 | HIGH |
| GWS Login Failure | `_application:login AND failure` | count() ≥ 3/5min | HIGH |
| GWS Admin Activity | `_application:admin` | count() ≥ 1/5min | HIGH |
| GWS Token Denied | `_application:token AND deny` | count() ≥ 5/5min | MEDIUM |

### MITRE ATT&CK Mapping

| Rule | Tactic | Technique |
|------|--------|-----------|
| Brute Force | Credential Access | T1110 — Brute Force |
| Account Lockout | Credential Access | T1110.001 — Password Guessing |
| After Hours Auth | Persistence | T1078 — Valid Accounts |
| Privilege Escalation | Privilege Escalation | T1078.002 — Domain Accounts |
| GWS Login Failure | Credential Access | T1110 — Brute Force |
| GWS Admin Activity | Persistence | T1098 — Account Manipulation |
| GWS Token Denied | Credential Access | T1550.001 — Application Access Token |

---

## 🚨 Alerts

### First Alert — Brute Force Confirmed

**[INSERT: graylog17.png]**
*Brute Force — Windows Login alert firing — confirmed end-to-end with email delivered*

Email alerting configured via Gmail SMTP (`smtp.gmail.com:587`) — alerts delivered to `crooks@mcloudschools.us`.

### The 1,840 Email Lesson

**[INSERT: brute1.png]**
*1,840 alert emails — one per minute for 12 hours overnight*

The after-hours authentication rule fired every minute overnight after connecting the domain controllers. Investigation revealed machine accounts ($) renewing Kerberos tickets — a false positive. Rule tuned from threshold 1 → 50. Grace period raised to 60 minutes.

> **Lesson:** Tuning is not optional. Tuning is the product.

### False Positive Investigation

**[INSERT: Screenshot_From_2026-04-27_11-23-07.png]**
*408 after-hours authentication events — investigated and resolved as false positive*

Account names examined: `HSWLAB2025-23$`, `MPS-DC1$`, `HSE-RM14$` — all machine accounts performing normal Kerberos ticket renewal. No threat. Rule tuned. Documented.

This is the daily reality of SOC analyst work — alert fires, investigate, determine context, tune or escalate.

---

## 🔧 Key Technical Challenges & Solutions

| Challenge | Root Cause | Solution |
|-----------|-----------|----------|
| apt repos dead | Ubuntu 24.10 EOL | Redirected to `old-releases.ubuntu.com` |
| curl sandbox restriction | snap curl can't write to /tmp | Replaced with native apt curl |
| MongoDB GPG key 0 bytes | snap curl restriction | Used `/usr/bin/curl` explicitly |
| Detection rules not firing | Wrong Winlogbeat field name | `winlogbeat_event_id` → `winlogbeat_event_code` |
| 1,840 alert emails | Grace period too short | Raised from 5min → 60min |
| False positive floods | Threshold too low | Added Group By username field |

---

## 📁 Repository Structure

```
mcloud-siem/
├── README.md                          # This file
├── docs/
│   ├── Architecture_Document.docx     # Signed Month 1 deliverable
│   ├── Vulnerability_Assessment.docx  # Nessus scan findings report
│   └── Vuln_Explainer.docx           # Plain-English briefing for leadership
├── configs/
│   ├── winlogbeat.yml                 # Winlogbeat configuration
│   └── detection_rules.md            # All 7 detection rule definitions
├── scripts/
│   └── fetch_workspace_logs.py        # Google Workspace log collector
├── dashboard/
│   ├── McLoud_Sentinel.html          # Live security dashboard
│   ├── McLoud_SOC_Watch_Log.html     # Daily analyst watch log
│   └── McLoud_Remediation_Log.html   # Vulnerability remediation tracker
└── screenshots/
    ├── Terminal1.png
    ├── terminal2.png
    ├── graylog3.png
    ├── graylog4.png
    ├── graylog5.png
    ├── graylog7.png
    ├── graylog8.png
    ├── graylog9.png
    ├── graylog16.png
    ├── graylog17.png
    ├── Screenshot_From_2026-04-27_11-23-07.png
    └── brute1.png
```

---

## 📊 Phase 2 — Vulnerability Assessment (In Progress)

Nessus Essentials deployed. Initial scan of 5 priority hosts completed.

**Critical Finding:** IPMI v2.0 Password Hash Disclosure on both HP iLO interfaces  
- CVE-2013-4786 · CVSS 7.5 · EPSS 0.7319 (73% exploitation probability)
- Unauthenticated attackers can retrieve admin password hash from server management interfaces
- Immediate remediation: VLAN isolation, firmware update, password rotation

**56 total findings across 5 hosts in 16 minutes.** Full report in `/docs/`.

---

## 🗺️ Roadmap

- [x] Month 1 — SIEM deployment and architecture documentation
- [x] Month 2 — Log ingestion (Windows, Google Workspace, Cisco)
- [x] Month 3 — Detection rules, alerting, tuning
- [x] Month 4 — Vulnerability assessment (Nessus)
- [ ] Month 5 — GRC: AUP, IRP, NIST CSF gap assessment
- [ ] Month 6 — Security awareness: phishing simulation, staff training, final report

---

## 🎓 Certifications & Framework Alignment

**Certifications:** CompTIA A+ · Network+ · Security+ · ITIL 4 · Linux Essentials  
**Degree:** B.S. Cybersecurity — WGU (in progress)  
**NICE Framework:** PR-CDA · PR-VAM · OV-SPP · OV-TEA · PR-CIR

---

## 📝 Write-Up Series

This project is documented in a Substack series: *[Link to your Substack]*

Post 1: *I Built a SIEM for My School District on a Spare PC. Here's What Happened on Day One.*

---

*McLoud Public Schools · Enigma Labs LLC · McLoud, Oklahoma*  
*"Shaping Minds, Forging Futures"*
