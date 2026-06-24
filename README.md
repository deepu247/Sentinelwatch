# Log Auditor

A full-stack security log auditing dashboard for monitoring SSH authentication activity, detecting suspicious login patterns, enriching alerts with IP intelligence, and sending real-time notifications.

The project combines:

- A **Python auditor worker** that tails server authentication logs, parses security events, detects anomalies, enriches alerts, stores them, and sends Telegram notifications.
- A **Node.js / Express web server** that exposes API endpoints, serves the dashboard UI, manages whitelist/blacklist entries, and streams live updates over WebSockets.
- A **static frontend dashboard** for viewing alerts, stats, live logs, IP lists, and generated reports.
- A **Turso / libSQL database** for storing alerts and allow/deny lists.

---

## Features

- SSH authentication log monitoring from an remote Linux server
- Detection for:
  - Brute-force login attempts
  - Root login attacks
  - Successful login after repeated failures
  - New local user creation
  - Privilege escalation events
- IP enrichment using AbuseIPDB and ipinfo
- Severity upgrades based on IP reputation
- Telegram alert notifications
- Rate limiting for non-critical notifications
- Daily Telegram summaries
- HTML daily report generation
- Web dashboard with:
  - Alert statistics
  - Recent alerts
  - Top attacking IPs
  - Live auditor logs
  - Whitelist and blacklist management
  - Report listing and viewing
- WebSocket updates for new alerts and status changes
- Render deployment configuration included

---

## Project Structure

```text
log-auditor/
├── auditor.py                  # Main Python auditor loop
├── server.js                   # Express API, dashboard server, WebSocket server
├── frontend/
│   └── index.html              # Static dashboard UI
├── modules/
│   ├── anomaly_detector.py     # Detection logic and brute-force tracking
│   ├── dossier_builder.py      # Human-readable alert report builder
│   ├── intel_collector.py      # AbuseIPDB/ipinfo enrichment
│   ├── notifier.py             # Telegram notifications and summaries
│   ├── parser.py               # Auth log parser
│   ├── reporter.py             # Daily HTML report generator
│   ├── storage.py              # Turso HTTP-backed database layer
│   ├── tailer.py               # SSH log tailing via Paramiko
│   └── whitelist.py            # Whitelist/blacklist helpers
├── test_parser.py              # Basic parser test script
├── package.json                # Node dependencies and scripts
├── requirements.txt            # Python dependencies
├── render.yaml                 # Render deployment blueprint
├── known_hosts                 # SSH host key pinning file
└── .env                        # Local environment variables; do not commit
```

---

## Requirements

### Runtime

- Node.js 18+
- Python 3.10+
- A Turso/libSQL database
- SSH access to the server whose `/var/log/auth.log` should be monitored
- Optional but recommended API accounts:
  - AbuseIPDB
  - ipinfo
  - Telegram bot

### Node packages

Installed from `package.json`:

- `express`
- `cors`
- `dotenv`
- `ws`
- `@libsql/client`

### Python packages

Installed from `requirements.txt`:

- `paramiko`
- `requests`

---

## Environment Variables

Create a `.env` file in the project root.

```env
TURSO_DATABASE_URL=libsql://your-database.turso.io
TURSO_AUTH_TOKEN=your_turso_auth_token

SERVER_IP=your.server.ip.address
SERVER_SSH_KEY=/absolute/path/to/your/private-key.pem

ABUSEIPDB_KEY=your_abuseipdb_key
IPINFO_TOKEN=your_ipinfo_token

TELEGRAM_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_telegram_chat_id

PORT=3000
REPORTS_DIR=reports
KNOWN_HOSTS_PATH=known_hosts
```

> **Security note:** Never commit `.env`, SSH private keys, database tokens, or API keys. If secrets were ever shared or committed accidentally, rotate them immediately.

---

## Local Setup

### 1. Install Node dependencies

```bash
npm install
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

If your system uses `python3` and `pip3`:

```bash
pip3 install -r requirements.txt
```

### 3. Configure environment variables

Create `.env` using the variables listed above.

Make sure `SERVER_SSH_KEY` points to a valid private key file and that the key file has safe permissions:

```bash
chmod 600 /path/to/private-key.pem
```

### 4. Start the web server

```bash
npm start
```

The dashboard will run at:

```text
http://localhost:3000
```

On startup, `server.js` also starts the Python auditor process automatically.

---

## Running the Auditor Directly

To run only the Python auditor:

```bash
python auditor.py
```

or:

```bash
python3 auditor.py
```

The auditor will:

1. Connect to the configured remote Linux server over SSH.
2. Tail `/var/log/auth.log`.
3. Parse each log line.
4. Detect suspicious patterns.
5. Skip whitelisted IPs.
6. Enrich alerts with AbuseIPDB/ipinfo.
7. Send Telegram notifications.
8. Store alerts in Turso.
9. Generate daily summaries and reports.

---

## Dashboard

The frontend is served from `frontend/index.html`.

Main dashboard areas include:

- Overview stats
- Alert table
- Top attacking IPs
- Live auditor feed
- Module status cards
- Whitelist management
- Blacklist management
- Report browser

The dashboard uses REST API calls and WebSocket messages from the Node server.

---

## API Endpoints

### Status

```http
GET /api/status
```

Returns whether the Python auditor process is running.

### Alerts

```http
GET /api/alerts?limit=50&offset=0&severity=all&sort=id&order=desc
```

Returns stored alerts.

Supported sortable columns:

- `timestamp`
- `ip`
- `user`
- `alert_type`
- `country`
- `abuse_score`
- `severity`

### Stats

```http
GET /api/stats
```

Returns alert counts for the last 24 hours.

### Top IPs

```http
GET /api/top-ips?limit=5
```

Returns the most active attacking IPs from the last 24 hours.

### Auditor Controls

```http
POST /api/auditor/start
POST /api/auditor/stop
```

Starts or stops the Python auditor process.

### Whitelist

```http
GET /api/whitelist
POST /api/whitelist
DELETE /api/whitelist/:ip
```

Example body:

```json
{
  "ip": "203.0.113.10",
  "note": "Trusted admin IP"
}
```

If the IP already exists in the blacklist, use `force: true` to move it:

```json
{
  "ip": "203.0.113.10",
  "note": "Trusted admin IP",
  "force": true
}
```

### Blacklist

```http
GET /api/blacklist
POST /api/blacklist
DELETE /api/blacklist/:ip
```

Example body:

```json
{
  "ip": "198.51.100.20",
  "note": "Known attacker"
}
```

If the IP already exists in the whitelist, use `force: true` to move it.

### Reports

```http
GET /api/reports
GET /api/reports/:filename
```

Lists generated HTML reports and serves individual report files.

---

## WebSocket Events

The server broadcasts JSON messages to connected dashboard clients.

Examples:

```json
{
  "type": "new_alert",
  "data": {
    "id": 1,
    "timestamp": "2026-06-23 10:00:00",
    "alert_type": "BRUTE_FORCE",
    "severity": "HIGH",
    "ip": "203.0.113.10"
  }
}
```

Other event types include:

- `log`
- `log_err`
- `auditor_status`
- `whitelist_update`
- `blacklist_update`

---

## Detection Logic

The parser recognizes common Linux authentication log patterns, including:

- Failed password attempts
- Invalid users
- Accepted password logins
- Accepted public key logins
- Root login attempts
- Maximum authentication attempts exceeded
- PAM authentication failures
- New user creation
- Privilege escalation through sudo/admin/wheel group changes

The anomaly detector tracks failed attempts by IP in memory.

Default brute-force settings:

```python
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 60
MAX_TRACKED_IPS = 5000
```

An IP that reaches 5 failed attempts within 60 seconds triggers a `BRUTE_FORCE` alert.

---

## Reports

Daily reports are generated as HTML files in the configured `REPORTS_DIR`, defaulting to:

```text
reports/
```

Report files follow this naming pattern:

```text
report_YYYY-MM-DD_HHMM.html
```

Reports include:

- Total alerts
- Critical/high/medium/low counts
- Unique IP count
- Severity breakdown chart
- Top attacking IPs
- Full alert table for the last 24 hours

---

## Deployment on Render

A `render.yaml` blueprint is included with two services:

1. `log-auditor-server` — Node web service
2. `log-auditor-python` — Python worker

Before deploying, configure all required environment variables in Render.

### Web service

```yaml
runtime: node
buildCommand: npm install
startCommand: node server.js
```

### Worker service

```yaml
runtime: python
buildCommand: pip install -r requirements.txt
startCommand: python auditor.py
```

> The Node web service already starts the auditor process automatically. If you also run the separate Python worker, you may end up with two auditor processes unless this behavior is adjusted.

---

## Testing

Run the parser test script:

```bash
python test_parser.py
```

Expected behavior:

- Detect invalid users
- Detect failed login attempts
- Ignore unrelated sudo command lines that do not match alert conditions

---

## Security Recommendations

- Rotate any credentials that were shared, committed, or included in an archive.
- Keep `.env` out of version control.
- Keep SSH private keys outside the repository.
- Use least-privilege Turso tokens where possible.
- Restrict dashboard access before exposing it publicly.
- Add authentication to the Express app before production use.
- Use HTTPS in production.
- Review the SSH command in `modules/tailer.py` before granting sudo access.
- Consider storing failed-attempt counters in a shared datastore if running multiple auditor instances.
- Avoid running both the Node-managed auditor and a separate worker unless duplicate processing is intended.

---

## Common Issues

### `SERVER_IP` or `SERVER_SSH_KEY` is missing

`modules/tailer.py` reads these variables directly from the environment. Ensure they are set in `.env` or the deployment environment.

### SSH connection fails

Check:

- Server IP
- SSH username
- Private key path
- Private key permissions
- Security group/firewall rules
- Whether the target server allows SSH from the deployment host

### Telegram alerts are not sent

Check:

- `TELEGRAM_TOKEN`
- `TELEGRAM_CHAT_ID`
- Bot permissions
- Rate limiting behavior

### No AbuseIPDB data appears

Check:

- `ABUSEIPDB_KEY`
- API quota
- Network access from the runtime environment

### Reports do not appear

Check:

- `REPORTS_DIR`
- File write permissions
- Whether enough alerts exist in the last 24 hours

---

## License

No license file is currently included. Add a license before distributing or open-sourcing this project.
