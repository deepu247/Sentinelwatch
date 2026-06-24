# 🛡️ SentinelWatch — Security Log Auditor

![Node.js](https://img.shields.io/badge/Node.js-18+-339933?style=flat&logo=node.js&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat)
![Render](https://img.shields.io/badge/Deployed%20on-Render-46E3B7?style=flat&logo=render&logoColor=white)
![Database](https://img.shields.io/badge/Database-Turso%20libSQL-4F9EE8?style=flat)

> Real-time SSH log monitoring, brute-force detection, IP threat intelligence, and Telegram alerts — all in one dashboard.

**Live Demo:** [https://sentinelwatch.onrender.com](https://sentinelwatch.onrender.com)

---

## 📸 Screenshots

> Dashboard — Attack Intelligence Overview

![Dashboard](https://via.placeholder.com/900x450/090d12/4da6ff?text=SentinelWatch+Dashboard)

---

## ✨ Features

- 🔴 **Brute-force detection** — flags IPs with 5+ failed logins within 60 seconds
- 💀 **Root attack detection** — alerts on direct root login attempts
- ⚠️ **Success-after-failures** — catches logins that succeed after repeated failures
- 👻 **New user creation** — alerts when a new local user is created
- 🔑 **Privilege escalation** — detects sudo/admin group modifications
- 🌐 **IP enrichment** — AbuseIPDB + ipinfo for geo, abuse score, TOR/VPN flags
- 📲 **Telegram notifications** — instant alerts with rate limiting
- 📊 **Daily summaries** — Telegram + HTML report every 24 hours
- 🖥️ **Live web dashboard** — real-time alerts via WebSocket
- ✅ **Whitelist / Blacklist** — manage trusted and blocked IPs from the UI
- 📁 **Report browser** — view and download daily HTML reports

---

## 🏗️ Architecture

```
  Oracle/Ubuntu Server
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
├── render.yaml             # Render deployment blueprint
├── known_hosts             # SSH host key pinning
├── frontend/
│   └── index.html          # Dashboard UI
├── modules/
│   ├── anomaly_detector.py # Brute-force & attack detection
│   ├── dossier_builder.py  # Alert message formatter
│   ├── intel_collector.py  # AbuseIPDB + ipinfo enrichment
│   ├── notifier.py         # Telegram notifications
│   ├── parser.py           # Auth log line parser
│   ├── reporter.py         # Daily HTML report generator
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

ORACLE_IP=your_server_ip
ORACLE_SSH_KEY=/path/to/private-key.pem

ABUSEIPDB_KEY=your_abuseipdb_key
IPINFO_TOKEN=your_ipinfo_token

TELEGRAM_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_telegram_chat_id

PORT=3000
REPORTS_DIR=reports
KNOWN_HOSTS_PATH=known_hosts
```

### 4. Start the server

```bash
npm start
```

Open [http://localhost:3000](http://localhost:3000)

> The Node server automatically starts the Python auditor on launch.

---

## 🔍 Detection Logic

The parser matches common Linux auth log patterns:

| Pattern | Event Type |
|---|---|
| `Failed password for ... from IP` | `failed_login` |
| `Invalid user ... from IP` | `invalid_user` |
| `Accepted password for ... from IP` | `successful_login` |
| `Accepted publickey for ... from IP` | `successful_login_key` |
| `Failed password for root from IP` | `root_attack` |
| `maximum authentication attempts exceeded` | `max_auth_exceeded` |
| `pam_unix ... authentication failure` | `pam_auth_failure` |
| `new user: name=...` | `new_user_created` |
| `usermod ... sudo/admin/wheel` | `privilege_escalation` |

The anomaly detector uses **in-memory tracking** per IP:

```python
BRUTE_FORCE_THRESHOLD = 5   # attempts
BRUTE_FORCE_WINDOW    = 60  # seconds
MAX_TRACKED_IPS       = 5000
```

Severity is upgraded based on AbuseIPDB score:

| Abuse Score | Resulting Severity |
|---|---|
| ≥ 90% | CRITICAL |
| ≥ 50% | HIGH |
| ≥ 20% | MEDIUM |

---

## 📡 API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/status` | Auditor running status |
| GET | `/api/stats` | 24h alert counts |
| GET | `/api/alerts` | Alert list (paginated, sortable) |
| GET | `/api/top-ips` | Top attacking IPs last 24h |
| POST | `/api/auditor/start` | Start Python auditor |
| POST | `/api/auditor/stop` | Stop Python auditor |
| GET | `/api/whitelist` | List whitelisted IPs |
| POST | `/api/whitelist` | Add IP to whitelist |
| DELETE | `/api/whitelist/:ip` | Remove from whitelist |
| GET | `/api/blacklist` | List blacklisted IPs |
| POST | `/api/blacklist` | Add IP to blacklist |
| DELETE | `/api/blacklist/:ip` | Remove from blacklist |
| GET | `/api/reports` | List generated reports |
| GET | `/api/reports/:filename` | View a report |

---

## 🌐 WebSocket Events

The server broadcasts real-time events to the dashboard:

```json
{ "type": "new_alert",       "data": { ... } }
{ "type": "auditor_status",  "running": true }
{ "type": "log",             "data": "log line" }
{ "type": "log_err",         "data": "error line" }
{ "type": "whitelist_update" }
{ "type": "blacklist_update" }
```

---

## ☁️ Deploy on Render

### 1. Push to GitHub

```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/log-auditor.git
git push -u origin main
```

### 2. Create a Web Service on Render

1. Go to [dashboard.render.com](https://dashboard.render.com)
2. Click **New → Web Service**
3. Connect your GitHub repo
4. Use these settings:

```text
Runtime:        Node
Build Command:  npm install && pip install -r requirements.txt
Start Command:  node server.js
Instance Type:  Free
```

### 3. Add environment variables

In Render: **Service → Environment → Add Environment Variable**

Add all values from your `.env` file.

### 4. Add SSH private key as a Secret File

1. Go to **Environment → Secret Files**
2. Filename: `oracle_key.pem`
3. Paste your private key content
4. Set env var:

```env
ORACLE_SSH_KEY=/etc/secrets/oracle_key.pem
```

### 5. Deploy

Click **Manual Deploy → Deploy latest commit**

Your app will be live at:

```text
https://your-app-name.onrender.com
```

---

## ⏰ Keep-Alive Cron (Free Tier)

Render free services sleep after 15 minutes of inactivity. Keep your app awake using a cron job on your Oracle server.

### Install cron (Ubuntu)

```bash
sudo apt update && sudo apt install cron curl -y
sudo systemctl enable cron && sudo systemctl start cron
```

### Install cron (Oracle Linux)

```bash
sudo yum install cronie curl -y
sudo systemctl enable crond && sudo systemctl start crond
```

### Add cron job

```bash
crontab -e
```

Add:

```bash
*/10 * * * * curl -s https://sentinelwatch.onrender.com/api/status > /dev/null && curl -s -X POST https://sentinelwatch.onrender.com/api/auditor/start > /dev/null
```

---

## 🧪 Testing

```bash
python test_parser.py
```

Expected output:

```text
Running parser tests...

[DETECTED] {'type': 'invalid_user', ...}
[DETECTED] {'type': 'failed_login', ...}
[IGNORED]  (not relevant)

All tests done!
```

---

## 🔒 Security Notes

- Never commit `.env`, private keys, or tokens to GitHub
- If any secret was accidentally exposed, **rotate it immediately**
- Add authentication before making the dashboard publicly accessible
- `/api/auditor/start` is currently unprotected — add a token check before production
- Render free tier is suitable for testing but not for reliable 24/7 monitoring

---

## 📦 Dependencies

### Node.js

| Package | Purpose |
|---|---|
| `express` | HTTP server |
| `ws` | WebSocket |
| `@libsql/client` | Turso database |
| `cors` | CORS middleware |
| `dotenv` | Environment variables |

### Python

| Package | Purpose |
|---|---|
| `paramiko` | SSH connection to remote server |
| `requests` | HTTP calls to AbuseIPDB, ipinfo, Telegram |

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  Made with ❤️ for security monitoring
</p>
