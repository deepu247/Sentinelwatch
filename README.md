# 🛡️ SentinelWatch — Security Log Auditor

![Node.js](https://img.shields.io/badge/Node.js-18+-339933?style=flat&logo=node.js&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat)
![Render](https://img.shields.io/badge/Deployed%20on-Render-46E3B7?style=flat&logo=render&logoColor=white)
![Database](https://img.shields.io/badge/Database-Turso%20libSQL-4F9EE8?style=flat)

> Real-time SSH log monitoring, brute-force detection, IP threat intelligence, and Telegram alerts — all in one dashboard.

**Live Demo:** [https://sentinelwatchh.onrender.com](https://sentinelwatchh.onrender.com)

---

## 📸 Screenshots

> Dashboard — Attack Intelligence Overview

![Dashboard](assets/Screenshot%202026-06-24%20100202.png)

> Alerts Table
![Alerts](assets/Screenshot%202026-06-24%20100221.png)

> Live Feed
![Live Feed](assets/Screenshot%202026-06-24%20100213.png)
---

## ✨ Features

- 🔴 **Brute-force detection** — flags IPs with 5+ failed logins within 60 seconds
- 💀 **Root attack detection** — alerts on direct root login attempts
- ⚠️ **Success-after-failures** — catches logins that succeed after repeated failures
- 👻 **New user creation** — alerts when a new local user is created
- 🔑 **Privilege escalation** — detects sudo/admin group modifications
- 🌐 **IP enrichment** — AbuseIPDB + ipinfo for geo, abuse score, TOR/VPN flags
- 📲 **Telegram notifications** — instant alerts with rate limiting
- 📊 **Daily summaries** — Telegram summary every 24 hours
- 🖥️ **Live web dashboard** — real-time alerts via WebSocket
- ✅ **Whitelist / Blacklist** — manage trusted and blocked IPs from the UI

---

## 🏗️ Architecture

```
  Remote Linux Server
  /var/log/auth.log
         │
         │  SSH (Paramiko)
         ▼
  ┌─────────────────┐
  │  Python Auditor │  ← anomaly detection, IP intel, Telegram
  └────────┬────────┘
           │  HTTP (Turso API)
           ▼
  ┌─────────────────┐
  │  Turso / libSQL │  ← alerts, whitelist, blacklist
  └────────┬────────┘
           │
  ┌────────▼────────┐
  │  Node.js Server │  ← Express REST API, WebSocket
  └────────┬────────┘
           │
  ┌────────▼────────┐
  │  Web Dashboard  │  ← HTML/CSS/JS frontend
  └─────────────────┘
```

---

## 🗂️ Project Structure

```text
log-auditor/
├── auditor.py              # Main Python auditor loop
├── server.js               # Express server + WebSocket + API
├── package.json
├── requirements.txt
├── frontend/
│   └── index.html          # Dashboard UI
├── modules/
│   ├── anomaly_detector.py # Brute-force & attack detection
│   ├── dossier_builder.py  # Alert message formatter
│   ├── intel_collector.py  # AbuseIPDB + ipinfo enrichment
│   ├── notifier.py         # Telegram notifications
│   ├── parser.py           # Auth log line parser
│   ├── storage.py          # Turso HTTP API database layer
│   ├── tailer.py           # SSH log tailer (Paramiko)
│   └── whitelist.py        # Whitelist/blacklist helpers
└── test_parser.py          # Parser unit tests
```

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/log-auditor.git
cd log-auditor
```

### 2. Install dependencies

```bash
npm install
pip install -r requirements.txt
```

### 3. Configure environment variables

Create a `.env` file:

```env
TURSO_DATABASE_URL=libsql://your-database.turso.io
TURSO_AUTH_TOKEN=your_turso_auth_token

SERVER_IP=your_server_ip
SERVER_SSH_KEY=/path/to/private-key.pem

ABUSEIPDB_KEY=your_abuseipdb_key
IPINFO_TOKEN=your_ipinfo_token

TELEGRAM_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_telegram_chat_id

PORT=3000
```

### 4. Start the server

```bash
npm start
```

Open [http://localhost:3000](http://localhost:3000)

> The Node server automatically starts the Python auditor on launch.

---

## 🔍 Detection Logic

SentinelWatch reads Linux SSH authentication logs from `/var/log/auth.log`, converts important log lines into normalized events, evaluates those events for attack behavior, enriches remote IPs with threat intelligence, then stores and sends actionable alerts.

### Detection Pipeline

```text
Raw auth.log line
      ↓
modules/parser.py
      ↓
Normalized event: type, time, user, ip
      ↓
modules/anomaly_detector.py
      ↓
Alert decision + severity
      ↓
modules/intel_collector.py
      ↓
IP enrichment + severity upgrade
      ↓
modules/notifier.py + modules/storage.py
      ↓
Telegram alert + dashboard database record
```
### IP Intelligence and Severity Upgrade

For remote IP alerts, `modules/intel_collector.py` enriches the IP address with:

| Source | Fields Used |
|---|---|
| AbuseIPDB | Abuse confidence score, total reports, country, last reported time |
| ipinfo.io | City, organization/ASN, TOR flag, VPN flag |

Severity can be upgraded after enrichment:

```text
Abuse score >= 90  → CRITICAL
Abuse score >= 50  → HIGH, unless already CRITICAL
Abuse score >= 20  → MEDIUM, only when current severity is LOW
```

### Whitelist and Blacklist Handling

Before sending or saving an alert, the auditor checks IP lists from the database:

- Whitelisted IPs are skipped.
- Existing blacklisted IPs reuse stored blacklist intelligence and skip a fresh AbuseIPDB lookup.
- IPs are auto-blacklisted when either condition is met:

```python
AUTO_BLACKLIST_ABUSE_SCORE = 60
AUTO_BLACKLIST_TOTAL_REPORTS = 100
```

### Telegram Alert Routing

`modules/notifier.py` reduces Telegram noise by sending critical alerts immediately and batching lower-priority traffic.

| Alert / Severity | Telegram Delivery |
|---|---|
| `CRITICAL` severity | Immediate |
| `ROOT_ATTACK` | Immediate |
| `PRIVILEGE_ESCALATION` | Immediate |
| `SUCCESS_AFTER_FAILURES` | Immediate |
| `NEW_USER_CREATED` | Immediate |
| `BRUTE_FORCE` with `HIGH` severity | Batched per IP |
| `MEDIUM` / `LOW` severity | Batched per IP |

Batching behavior:

- Each IP gets a fixed 60-second batch window.
- A continuous 5-minute attack produces about 5 batch messages, not hundreds of individual messages.
- If the attacking IP switches usernames, the old batch is flushed and a new batch starts.
- A background thread checks expired batches every 5 seconds.
- A 3-second global send interval helps avoid Telegram rate-limit issues.

### Stored Alert Data

Alerts are saved through `modules/storage.py` into Turso/libSQL with the important investigation fields:

- timestamp
- alert type and severity
- IP address and username
- country, city, organization
- AbuseIPDB score and total reports
- attempt count
- TOR/VPN flags

These records power the web dashboard, daily summaries, top-IP statistics, and generated reports.
