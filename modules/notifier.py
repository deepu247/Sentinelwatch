"""
notifier.py  —  Telegram alert sender with batching
Fixes applied:
  1. Added send_startup_message() — was missing, auditor.py called it on boot
  2. Added send_daily_summary()   — was missing, auditor.py called it daily
  3. Flush thread auto-starts at module import
  4. CRITICAL/HIGH alerts send immediately (no batching)
  5. send_alert() accepts merged alert+intel dict
"""

import os
import time
import threading
import requests
import zipfile
from datetime import datetime
from typing import Dict

# ── ENV ────────────────────────────────────────────────────────────────
TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

# ── CONFIG ─────────────────────────────────────────────────────────────
BATCH_TIMEOUT       = 60    # seconds before a batch force-flushes
GLOBAL_MIN_INTERVAL = 3     # min seconds between any two Telegram sends
FLUSH_INTERVAL      = 5     # how often flush thread checks batches

# Alert types that ALWAYS send immediately (no batching)
IMMEDIATE_ALERT_TYPES = {
    "ROOT_ATTACK",
    "PRIVILEGE_ESCALATION",
    "SUCCESS_AFTER_FAILURES",
    "NEW_USER_CREATED",
}

# ── STATE ──────────────────────────────────────────────────────────────
BATCH_LOCK        = threading.Lock()
_BATCH: Dict[str, dict] = {}   # key = ip
_last_sent_global = 0.0


# ── CORE SEND ──────────────────────────────────────────────────────────
def _send_raw(text: str) -> bool:
    """Send a plain text message to Telegram. Returns True on success."""
    global _last_sent_global

    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[notifier] TELEGRAM_TOKEN or TELEGRAM_CHAT_ID not set — skipping send")
        return False

    # Rate-limit
    elapsed = time.time() - _last_sent_global
    if elapsed < GLOBAL_MIN_INTERVAL:
        time.sleep(GLOBAL_MIN_INTERVAL - elapsed)

    url = "https://api.telegram.org/bot" + TELEGRAM_TOKEN + "/sendMessage"
    try:
        resp = requests.post(
            url,
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"},
            timeout=15,
        )
        result = resp.json()
        if result.get("ok"):
            _last_sent_global = time.time()
            print(f"[notifier] Telegram sent OK: {text[:60]}")
            return True
        print(f"[notifier] Telegram error: {result.get('description')}")
        return False
    except Exception as e:
        print(f"[notifier] Telegram exception: {e}")
        return False


# ── SEVERITY EMOJI ─────────────────────────────────────────────────────
SEV_EMOJI = {
    "CRITICAL": "\U0001f6a8",
    "HIGH":     "\U0001f534",
    "MEDIUM":   "\U0001f7e1",
    "LOW":      "\U0001f7e2",
}


def _build_message(buf: dict) -> str:
    """Build a Telegram message from a batch buffer."""
    alert_type  = buf.get("alert_type",  "UNKNOWN")
    severity    = buf.get("severity",    "MEDIUM")
    ip          = buf.get("ip",          "?.?.?.?")
    user        = buf.get("user",        "\u2014")
    country     = buf.get("country",     "Unknown")
    org         = buf.get("org",         "Unknown")
    abuse       = buf.get("abuse_score", 0)
    is_tor      = buf.get("is_tor",      False)
    is_vpn      = buf.get("is_vpn",      False)
    blacklisted = buf.get("is_blacklisted", False)
    count       = buf.get("count",       1)
    ts          = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    emoji = SEV_EMOJI.get(severity, "\u26a0\ufe0f")
    flags = []
    if is_tor:      flags.append("\U0001f3f4 TOR")
    if is_vpn:      flags.append("\U0001f510 VPN")
    if blacklisted: flags.append("\u26d4 BLACKLISTED")
    flag_str = "  ".join(flags) if flags else "None"

    lines = [
        f"{emoji} <b>SentinelWatch Alert</b>",
        f"\u251c Type     : <code>{alert_type}</code>",
        f"\u251c Severity : <b>{severity}</b>",
        f"\u251c IP       : <code>{ip}</code>",
        f"\u251c User     : <code>{user}</code>",
        f"\u251c Country  : {country}",
        f"\u251c Org      : {org}",
        f"\u251c Abuse    : {abuse}%",
        f"\u251c Flags    : {flag_str}",
        f"\u2514 Attempts : <b>{count}</b>  \u23f0 {ts}",
    ]
    return "\n".join(lines)


# ── STARTUP & DAILY SUMMARY ─────────────────────────────────────────────
def send_startup_message() -> None:
    """Send a startup notification to Telegram. Called once when auditor launches."""
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = (
        f"\U0001f6e1\ufe0f <b>SentinelWatch Started</b>\n"
        f"\u251c Status  : <b>Online</b>\n"
        f"\u2514 Time    : {ts}"
    )
    _send_raw(msg)


def send_daily_summary(
    total: int = 0,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    unique_ips: int = 0,
    top_ips: list = None,
) -> None:
    """Send a daily summary to Telegram. Called once per day at DAILY_SUMMARY_HOUR."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    top_ips = top_ips or []

    top_section = ""
    if top_ips:
        lines = []
        for row in top_ips[:5]:
            # row may be a tuple (ip, hits) or (ip, country, abuse_score, hits)
            if isinstance(row, (list, tuple)):
                ip_val   = row[0]
                hits_val = row[-1]
            else:
                ip_val   = str(row)
                hits_val = "?"
            lines.append(f"  \u2022 <code>{ip_val}</code> — {hits_val} hits")
        top_section = "\n\U0001f30d Top IPs:\n" + "\n".join(lines)

    msg = (
        f"\U0001f4ca <b>SentinelWatch Daily Summary</b>\n"
        f"\u251c \U0001f4c5 Period    : Last 24 hours ({ts})\n"
        f"\u251c \U0001f6a8 Critical  : <b>{critical}</b>\n"
        f"\u251c \U0001f534 High      : {high}\n"
        f"\u251c \U0001f7e1 Medium    : {medium}\n"
        f"\u251c \U0001f7e2 Low       : {low}\n"
        f"\u251c \U0001f4e6 Total     : {total}\n"
        f"\u2514 \U0001f310 Unique IPs: {unique_ips}"
        f"{top_section}"
    )
    _send_raw(msg)


# ── BATCH LOGIC ────────────────────────────────────────────────────────
def _flush_ip(ip: str) -> None:
    """Flush one IP's batch and send the message."""
    with BATCH_LOCK:
        buf = _BATCH.pop(ip, None)
    if buf:
        msg = _build_message(buf)
        _send_raw(msg)


def _flush_all_expired() -> None:
    """Flush all batches whose timeout has expired."""
    now = time.time()
    with BATCH_LOCK:
        expired = [ip for ip, buf in _BATCH.items()
                   if now - buf["first_seen"] >= BATCH_TIMEOUT]
    for ip in expired:
        print(f"[notifier] Batch timeout flush for {ip}")
        _flush_ip(ip)


def send_alert(alert: dict) -> None:
    """
    Main entry point called by auditor.py.
    Accepts merged alert+intel dict with keys:
      alert (or alert_type), severity, ip, user, count,
      country, org, abuse_score, is_tor, is_vpn, is_blacklisted
    """
    alert_type = alert.get("alert", alert.get("alert_type", "UNKNOWN"))
    severity   = alert.get("severity", "MEDIUM")
    ip         = alert.get("ip", "")
    user       = alert.get("user", "")
    count      = alert.get("count", alert.get("attempts", 1))

    # ── IMMEDIATE: CRITICAL, HIGH, or special types ──
    if severity in ("CRITICAL", "HIGH") or alert_type in IMMEDIATE_ALERT_TYPES:
        buf = {
            "alert_type":     alert_type,
            "severity":       severity,
            "ip":             ip,
            "user":           user,
            "country":        alert.get("country",      "Unknown"),
            "org":            alert.get("org",          "Unknown"),
            "abuse_score":    alert.get("abuse_score",  0),
            "is_tor":         alert.get("is_tor",       False),
            "is_vpn":         alert.get("is_vpn",       False),
            "is_blacklisted": alert.get("is_blacklisted", False),
            "count":          count,
            "first_seen":     time.time(),
        }
        msg = _build_message(buf)
        _send_raw(msg)
        with BATCH_LOCK:
            _BATCH.pop(ip, None)
        return

    # ── BATCH: MEDIUM / LOW ──
    with BATCH_LOCK:
        if ip in _BATCH:
            existing  = _BATCH[ip]
            prev_user = existing.get("user", "")

            if user and user != prev_user:
                old_buf = _BATCH.pop(ip)
                threading.Thread(
                    target=lambda b: _send_raw(_build_message(b)),
                    args=(old_buf,), daemon=True
                ).start()
                _BATCH[ip] = {
                    "alert_type":     alert_type,
                    "severity":       severity,
                    "ip":             ip,
                    "user":           user,
                    "country":        alert.get("country",      "Unknown"),
                    "org":            alert.get("org",          "Unknown"),
                    "abuse_score":    alert.get("abuse_score",  0),
                    "is_tor":         alert.get("is_tor",       False),
                    "is_vpn":         alert.get("is_vpn",       False),
                    "is_blacklisted": alert.get("is_blacklisted", False),
                    "count":          count,
                    "first_seen":     time.time(),
                }
            else:
                existing["count"] += 1
                existing["severity"] = severity
        else:
            _BATCH[ip] = {
                "alert_type":     alert_type,
                "severity":       severity,
                "ip":             ip,
                "user":           user,
                "country":        alert.get("country",      "Unknown"),
                "org":            alert.get("org",          "Unknown"),
                "abuse_score":    alert.get("abuse_score",  0),
                "is_tor":         alert.get("is_tor",       False),
                "is_vpn":         alert.get("is_vpn",       False),
                "is_blacklisted": alert.get("is_blacklisted", False),
                "count":          count,
                "first_seen":     time.time(),
            }


# ── REPORT SENDER ──────────────────────────────────────────────────────
def send_report_to_telegram(filepath: str, stats: dict) -> bool:
    """Send a summary + zipped HTML report to Telegram."""
    total    = stats.get("total",     0)
    critical = stats.get("critical",  0)
    high     = stats.get("high",      0)
    medium   = stats.get("medium",    0)
    low      = stats.get("low",       0)
    unique   = stats.get("unique_ips", 0)
    ts       = datetime.now().strftime("%Y-%m-%d %H:%M")

    summary = (
        f"\U0001f4cb <b>Instant Security Report</b>\n"
        f"\u251c \U0001f4c5 Generated   : {ts}\n"
        f"\u251c \U0001f4ca Period      : Last 24 hours\n"
        f"\u251c \U0001f6a8 Critical    : {critical}\n"
        f"\u251c \U0001f534 High        : {high}\n"
        f"\u251c \U0001f7e1 Medium      : {medium}\n"
        f"\u251c \U0001f7e2 Low         : {low}\n"
        f"\u251c \U0001f4e6 Total       : {total}\n"
        f"\u251c \U0001f310 Unique IPs  : {unique}\n"
        f"\u2514 \U0001f4ce Full report attached below."
    )
    _send_raw(summary)

    zip_path = None
    try:
        base_name = os.path.basename(filepath)
        zip_name  = base_name.replace(".html", ".zip")
        zip_path  = os.path.join(os.path.dirname(filepath), zip_name)

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(filepath, base_name)

        with open(zip_path, "rb") as f:
            resp = requests.post(
                "https://api.telegram.org/bot" + TELEGRAM_TOKEN + "/sendDocument",
                data={"chat_id":  TELEGRAM_CHAT_ID,
                      "caption":  "\U0001f4c4 Full Security Report (extract & open HTML)"},
                files={"document": (zip_name, f, "application/zip")},
                timeout=30,
            )
        result = resp.json()
        if result.get("ok"):
            print("[notifier] Report zip sent to Telegram.")
            return True
        print(f"[notifier] ERROR sending zip: {result.get('description')}")
    except Exception as e:
        print(f"[notifier] ERROR sending zip: {e}")
    finally:
        if zip_path and os.path.exists(zip_path):
            try:
                os.remove(zip_path)
            except Exception:
                pass
    return False


# ── AUTO-START FLUSH THREAD ────────────────────────────────────────────
def _flush_loop():
    while True:
        time.sleep(FLUSH_INTERVAL)
        try:
            _flush_all_expired()
        except Exception as e:
            print(f"[notifier] Flush loop error: {e}")


_flush_thread = threading.Thread(target=_flush_loop, daemon=True, name="notifier-flush")
_flush_thread.start()
print("[notifier] \u2705 Flush thread started.")
