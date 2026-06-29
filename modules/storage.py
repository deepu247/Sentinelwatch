import os
import requests as _requests

TURSO_URL   = os.environ.get("TURSO_DATABASE_URL", "")
TURSO_TOKEN = os.environ.get("TURSO_AUTH_TOKEN", "")


def _http_url() -> str:
    """Convert libsql:// URL to https:// for the Turso HTTP API."""
    return TURSO_URL.replace("libsql://", "https://")


def _turso_type(value):
    """Map a Python value to a Turso HTTP API argument descriptor."""
    if value is None:
        return {"type": "null"}
    if isinstance(value, bool):
        return {"type": "integer", "value": str(int(value))}
    if isinstance(value, int):
        return {"type": "integer", "value": str(value)}
    if isinstance(value, float):
        return {"type": "float", "value": str(value)}
    return {"type": "text", "value": str(value)}


class _ResultSet:
    """Thin wrapper around the Turso HTTP API result that mimics fetchone/fetchall."""

    def __init__(self, result: dict):
        cols = [c["name"] for c in result.get("cols", [])]
        raw_rows = result.get("rows", [])
        self._rows = []
        for raw_row in raw_rows:
            row = tuple(
                cell.get("value") if cell.get("type") != "null" else None
                for cell in raw_row
            )
            self._rows.append(row)

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows


class _Connection:
    """Synchronous connection-like object backed by the Turso HTTP pipeline API."""

    def __init__(self, url: str, token: str):
        self._endpoint = f"{url}/v2/pipeline"
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def execute(self, sql: str, args=()) -> _ResultSet:
        body = {
            "requests": [
                {
                    "type": "execute",
                    "stmt": {
                        "sql": sql,
                        "args": [_turso_type(a) for a in args],
                    },
                },
                {"type": "close"},
            ]
        }
        resp = _requests.post(self._endpoint, headers=self._headers, json=body, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        result = data["results"][0]["response"]["result"]
        return _ResultSet(result)

    def commit(self):
        pass  # Turso auto-commits every statement via the HTTP API


def init_db() -> _Connection:
    conn = _Connection(_http_url(), TURSO_TOKEN)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
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
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS whitelist (
            ip        TEXT PRIMARY KEY,
            note      TEXT DEFAULT '',
            added_at  TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            ip        TEXT PRIMARY KEY,
            note      TEXT DEFAULT '',
            added_at  TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    return conn


def save_alert(conn: _Connection, alert: dict, intel: dict) -> None:
    conn.execute(
        "INSERT INTO alerts (alert_type, severity, ip, user, country, city, "
        "org, abuse_score, total_reports, attempts, is_tor, is_vpn) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            alert.get("alert",    "UNKNOWN"),
            alert.get("severity", "LOW"),
            intel.get("ip",       alert.get("ip", "unknown")),
            alert.get("user",     "unknown"),
            intel.get("country",  "Unknown"),
            intel.get("city",     "Unknown"),
            intel.get("org",      "Unknown"),
            intel.get("abuse_score",   0),
            intel.get("total_reports", 0),
            alert.get("count",    1),
            int(intel.get("is_tor", False)),
            int(intel.get("is_vpn", False)),
        ),
    )


def get_daily_stats(conn: _Connection) -> dict:
    row = conn.execute("""
        SELECT COUNT(*), SUM(severity='CRITICAL'), SUM(severity='HIGH'),
               SUM(severity='MEDIUM'), SUM(severity='LOW'),
               COUNT(DISTINCT ip)
        FROM alerts WHERE timestamp > datetime('now', '-1 day')
    """).fetchone()
    return {
        "total":      row[0] or 0,
        "critical":   row[1] or 0,
        "high":       row[2] or 0,
        "medium":     row[3] or 0,
        "low":        row[4] or 0,
        "unique_ips": row[5] or 0,
    }


def get_top_ips(conn: _Connection, limit: int = 5) -> list:
    return conn.execute("""
        SELECT ip, COUNT(*) as hits FROM alerts
        WHERE timestamp > datetime('now', '-1 day')
        GROUP BY ip ORDER BY hits DESC LIMIT ?
    """, (limit,)).fetchall()


def get_recent_alerts(conn: _Connection, limit: int = 10) -> list:
    cursor = conn.execute("""
        SELECT timestamp, alert_type, severity, ip, user, country, abuse_score
        FROM alerts ORDER BY id DESC LIMIT ?
    """, (limit,))
    return [
        {"timestamp": r[0], "alert_type": r[1], "severity": r[2],
         "ip": r[3], "user": r[4], "country": r[5], "abuse_score": r[6]}
        for r in cursor.fetchall()
    ]
