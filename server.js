require('dotenv').config();
const express             = require('express');
const http                = require('http');
const WebSocket           = require('ws');
const { createClient }    = require('@libsql/client');
const cors                = require('cors');
const path                = require('path');
const fs                  = require('fs');
const { spawn }           = require('child_process');

const PORT        = process.env.PORT        || 3000;
const REPORTS_DIR = process.env.REPORTS_DIR || 'reports';

const db = createClient({
  url:       process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

async function initDB() {
  await db.batch([
    `CREATE TABLE IF NOT EXISTS alerts (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp     TEXT    NOT NULL DEFAULT (datetime('now')),
      alert_type    TEXT    NOT NULL,
      severity      TEXT    NOT NULL,
      ip            TEXT    NOT NULL,
      user          TEXT,
      country       TEXT,
      city          TEXT,
      org           TEXT,
      abuse_score   INTEGER DEFAULT 0,
      total_reports INTEGER DEFAULT 0,
      attempts      INTEGER DEFAULT 1,
      is_tor        INTEGER DEFAULT 0,
      is_vpn        INTEGER DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS whitelist (
      ip        TEXT PRIMARY KEY,
      note      TEXT DEFAULT '',
      added_at  TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS blacklist (
      ip        TEXT PRIMARY KEY,
      note      TEXT DEFAULT '',
      added_at  TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
  ], 'write');
}

const app    = express();
const server = http.createServer(app);
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'frontend')));

const wss = new WebSocket.Server({ server });

function broadcast(data) {
  const msg = JSON.stringify(data);
  wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(msg); });
}

let lastSeenId = 0;

async function startPolling() {
  const result = await db.execute({ sql: 'SELECT MAX(id) as m FROM alerts', args: [] });
  const row    = result.rows[0];
  lastSeenId   = (row && row.m) ? Number(row.m) : 0;

  setInterval(async () => {
    try {
      const r = await db.execute({
        sql:  'SELECT * FROM alerts WHERE id > ? ORDER BY id ASC',
        args: [lastSeenId],
      });
      if (r.rows.length > 0) {
        lastSeenId = Number(r.rows[r.rows.length - 1].id);
        r.rows.forEach(row => broadcast({ type: 'new_alert', data: row }));
      }
    } catch (e) {
      console.error('[poll]', e.message);
    }
  }, 3000);
}

let auditorProcess = null;

function startAuditor() {
  if (auditorProcess) return { ok: false, msg: 'Already running' };
  const env = { ...process.env, PYTHONIOENCODING: 'utf-8' };
  auditorProcess = spawn('python', ['auditor.py'], { env, cwd: __dirname });

  auditorProcess.stdout.on('data', data => {
    const line = data.toString().trim();
    console.log('[python]', line);
    broadcast({ type: 'log', data: line });
  });
  auditorProcess.stderr.on('data', data => {
    const line = data.toString().trim();
    console.error('[python-err]', line);
    broadcast({ type: 'log_err', data: line });
  });
  auditorProcess.on('close', code => {
    console.log(`[python] exited (${code}). Restarting in 5s...`);
    broadcast({ type: 'auditor_status', running: false });
    auditorProcess = null;
    setTimeout(startAuditor, 5000);
  });

  console.log('[server] Python auditor started.');
  broadcast({ type: 'auditor_status', running: true });
  return { ok: true, msg: 'Auditor started' };
}

function stopAuditor() {
  if (!auditorProcess) return { ok: false, msg: 'Not running' };
  auditorProcess.removeAllListeners('close');
  auditorProcess.kill();
  auditorProcess = null;
  broadcast({ type: 'auditor_status', running: false });
  return { ok: true, msg: 'Auditor stopped' };
}

app.get('/api/stats', async (req, res) => {
  try {
    const r = await db.execute({
      sql: `SELECT COUNT(*) as total,
        SUM(severity='CRITICAL') as critical, SUM(severity='HIGH') as high,
        SUM(severity='MEDIUM') as medium,     SUM(severity='LOW')  as low,
        COUNT(DISTINCT ip) as unique_ips
        FROM alerts WHERE timestamp > datetime('now', '-1 day')`,
      args: [],
    });
    const row = r.rows[0];
    res.json({ total: Number(row.total)||0, critical: Number(row.critical)||0,
               high: Number(row.high)||0,  medium: Number(row.medium)||0,
               low: Number(row.low)||0,    unique_ips: Number(row.unique_ips)||0 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/alerts', async (req, res) => {
  try {
    const limit    = Math.min(parseInt(req.query.limit)  || 50, 200);
    const offset   = parseInt(req.query.offset) || 0;
    const severity = req.query.severity;
    const order    = req.query.order === 'asc' ? 'ASC' : 'DESC';
    const SORTABLE = ['timestamp','ip','user','alert_type','country','abuse_score','severity'];
    const sortCol  = SORTABLE.includes(req.query.sort) ? req.query.sort : 'id';

    const conditions = [];
    const args       = [];
    if (severity && severity !== 'all') { conditions.push('severity = ?'); args.push(severity); }

    let sql = 'SELECT * FROM alerts';
    if (conditions.length) sql += ' WHERE ' + conditions.join(' AND ');
    sql += ` ORDER BY ${sortCol} ${order} LIMIT ? OFFSET ?`;
    args.push(limit, offset);

    const r = await db.execute({ sql, args });
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/top-ips', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 5;
    const r = await db.execute({
      sql:  `SELECT ip, country, MAX(abuse_score) as abuse_score, COUNT(*) as hits
             FROM alerts WHERE timestamp > datetime('now', '-1 day')
             GROUP BY ip ORDER BY hits DESC LIMIT ?`,
      args: [limit],
    });
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/status', (req, res) => {
  res.json({ running: auditorProcess !== null, pid: auditorProcess?.pid || null });
});

app.post('/api/auditor/start', (req, res) => res.json(startAuditor()));
app.post('/api/auditor/stop',  (req, res) => res.json(stopAuditor()));

function isValidIP(ip) {
  const v4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (v4.test(ip)) return ip.split('.').every(n => parseInt(n, 10) <= 255);
  return /^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i.test(ip);
}

app.get('/api/whitelist', async (req, res) => {
  try {
    const r = await db.execute({ sql: 'SELECT ip, note, added_at FROM whitelist ORDER BY added_at DESC', args: [] });
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/whitelist', async (req, res) => {
  try {
    const { ip: rawIp, note = '', force = false } = req.body;
    const ip = (rawIp || '').trim();
    if (!ip)            return res.status(400).json({ error: 'ip is required' });
    if (!isValidIP(ip)) return res.status(400).json({ error: 'Invalid IP address format' });

    if ((await db.execute({ sql: 'SELECT 1 FROM whitelist WHERE ip = ?', args: [ip] })).rows.length)
      return res.json({ ok: true, already: true, ip });

    if ((await db.execute({ sql: 'SELECT 1 FROM blacklist WHERE ip = ?', args: [ip] })).rows.length) {
      if (!force) return res.status(409).json({ conflict: 'blacklist', ip });
      await db.execute({ sql: 'DELETE FROM blacklist WHERE ip = ?', args: [ip] });
      broadcast({ type: 'blacklist_update' });
    }

    await db.execute({ sql: 'INSERT INTO whitelist (ip, note) VALUES (?, ?)', args: [ip, note] });
    broadcast({ type: 'whitelist_update' });
    res.json({ ok: true, ip });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/whitelist/:ip', async (req, res) => {
  try {
    await db.execute({ sql: 'DELETE FROM whitelist WHERE ip = ?', args: [req.params.ip] });
    broadcast({ type: 'whitelist_update' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/blacklist', async (req, res) => {
  try {
    const r = await db.execute({ sql: 'SELECT ip, note, added_at FROM blacklist ORDER BY added_at DESC', args: [] });
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/blacklist', async (req, res) => {
  try {
    const { ip: rawIp, note = '', force = false } = req.body;
    const ip = (rawIp || '').trim();
    if (!ip)            return res.status(400).json({ error: 'ip is required' });
    if (!isValidIP(ip)) return res.status(400).json({ error: 'Invalid IP address format' });

    if ((await db.execute({ sql: 'SELECT 1 FROM blacklist WHERE ip = ?', args: [ip] })).rows.length)
      return res.json({ ok: true, already: true, ip });

    if ((await db.execute({ sql: 'SELECT 1 FROM whitelist WHERE ip = ?', args: [ip] })).rows.length) {
      if (!force) return res.status(409).json({ conflict: 'whitelist', ip });
      await db.execute({ sql: 'DELETE FROM whitelist WHERE ip = ?', args: [ip] });
      broadcast({ type: 'whitelist_update' });
    }

    await db.execute({ sql: 'INSERT INTO blacklist (ip, note) VALUES (?, ?)', args: [ip, note] });
    broadcast({ type: 'blacklist_update' });
    res.json({ ok: true, ip });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/blacklist/:ip', async (req, res) => {
  try {
    await db.execute({ sql: 'DELETE FROM blacklist WHERE ip = ?', args: [req.params.ip] });
    broadcast({ type: 'blacklist_update' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/reports', (req, res) => {
  if (!fs.existsSync(REPORTS_DIR)) return res.json([]);
  const files = fs.readdirSync(REPORTS_DIR)
    .filter(f => f.startsWith('report_') && f.endsWith('.html'))
    .sort().reverse()
    .map(f => ({
      filename: f,
      date:     f.replace('report_', '').replace('.html', '').replace('_', ' ').slice(0, 16),
      size:     fs.statSync(path.join(REPORTS_DIR, f)).size,
    }));
  res.json(files);
});


app.post('/api/reports/instant', (req, res) => {
  const child = spawn('python3', ['instant_report.py'], {
    cwd: __dirname,
    env: { ...process.env, PYTHONIOENCODING: 'utf-8' },
  });
  let out = '', err = '';
  child.stdout.on('data', d => { out += d.toString(); });
  child.stderr.on('data', d => { err += d.toString(); });
  child.on('close', code => {
    if (code !== 0) {
      console.error('[instant-report] Error:', err.trim());
      return res.status(500).json({ error: err.trim() || 'Report generation failed' });
    }
    const filename = out.trim().split('\n').pop();
    console.log('[instant-report] Generated:', filename);
    broadcast({ type: 'new_report', filename });
    res.json({ ok: true, filename });
  });
});
app.get('/api/reports/:filename', (req, res) => {
  const filename = path.basename(req.params.filename);
  const filepath = path.join(REPORTS_DIR, filename);
  if (!fs.existsSync(filepath)) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.resolve(filepath));
});

initDB()
  .then(startPolling)
  .then(() => {
    server.listen(PORT, () => {
      console.log(`[server] Running at http://localhost:${PORT}`);
      startAuditor();
    });
  })
  .catch(err => {
    console.error('[server] Startup failed:', err);
    process.exit(1);
  });
