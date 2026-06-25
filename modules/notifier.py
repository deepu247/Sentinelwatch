import requests
import os
import time
from datetime import datetime

TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

GLOBAL_MIN_INTERVAL = 3    # minimum seconds between any two Telegram messages
BATCH_TIMEOUT       = 120  # seconds — max wait before a batch is force-flushed

_last_sent_global: float = 0.0

# Buffer: one entry per attacking IP
# {
#   "username"   : str,
#   "count"      : int,      # accumulated attempt count
#   "severity"   : str,      # worst severity seen in this batch
#   "alert_type" : str,      # type of the latest/worst alert
#   "intel"      : dict,     # latest intel dict
#   "first_seen" : float,    # epoch of first event in this batch
#   "last_seen"  : float,    # epoch of most recent event
# }
_buffers: dict[str, dict] = {}


# ── Severity helpers ─────────────────────────────────────────────────────────

_SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

def _higher_severity(a: str, b: str) -> str:
    return a if _SEV_RANK.get(a, 0) >= _SEV_RANK.get(b, 0) else b


# ── Buffer helpers ────────────────────────────────────────────────────────────

def _new_buffer(username: str, severity: str, alert_type: str,
                intel: dict, attempts: int, ts: float) -> dict:
    return {
        "username":   username,
        "count":      attempts,
        "severity":   severity,
        "alert_type": alert_type,
        "intel":      intel,
        "first_seen": ts,
        "last_seen":  ts,
    }


def _build_batch_message(ip: str, buf: dict, reason: str) -> str:
    intel      = buf["intel"]
    severity   = buf["severity"]
    username   = buf["username"]
    count      = buf["count"]
    alert_type = buf["alert_type"]
    first_ts   = datetime.fromtimestamp(buf["first_seen"]).strftime("%H:%M:%S")
    last_ts    = datetime.fromtimestamp(buf["last_seen"]).strftime("%H:%M:%S")
    duration   = int(buf["last_seen"] - buf["first_seen"])
    dur_str    = f"{duration // 60}m {duration % 60}s" if duration >= 60 else f"{duration}s"

    sev_emoji = {"CRITICAL": "\U0001f6a8", "HIGH": "\U0001f534",
                 "MEDIUM": "\U0001f7e1", "LOW": "\U0001f7e2"}.get(severity, "\u26aa")

    abuse_score   = intel.get("abuse_score",   0) or 0
    total_reports = intel.get("total_reports", 0) or 0
    country       = intel.get("country") or "\u2014"
    city          = intel.get("city")    or ""
    org           = intel.get("org")     or "\u2014"
    is_tor        = intel.get("is_tor",  False)
    is_vpn        = intel.get("is_vpn",  False)

    location = f"{country}" + (f" | {city}" if city else "")
    flags = " ".join(filter(None, [
        "\U0001f534 TOR" if is_tor else "",
        "\U0001f535 VPN" if is_vpn else "",
    ])) or "\u2014"

    flush_reason = {
        "username_changed": "\U0001f504 New username detected",
        "timeout":          "\u23f0 Batch timeout (2 min)",
        "critical":         "\U0001f6a8 Critical alert",
    }.get(reason, reason)

    alert_type_display = alert_type.replace("_", " ").title()

    return (
        f"{sev_emoji} <b>{severity} \u2014 {alert_type_display} Batch</b>\n"
        f"{'=' * 38}\n"
        f"\U0001f310 <b>IP Address</b>   : <code>{ip}</code>\n"
        f"\U0001f3f3\ufe0f <b>Location</b>    : {location}\n"
        f"\U0001f3e2 <b>Org / ISP</b>    : {org}\n"
        f"\u2620\ufe0f <b>Abuse Score</b>  : {abuse_score}% ({total_reports} reports)\n"
        f"\U0001f6a9 <b>Flags</b>        : {flags}\n"
        f"\n"
        f"\U0001f464 <b>Target User</b>  : <code>{username}</code>\n"
        f"\U0001f501 <b>Attempts</b>     : {count}\n"
        f"\u23f1\ufe0f <b>Duration</b>     : {dur_str}\n"
        f"\u23f0 <b>First Seen</b>   : {first_ts}\n"
        f"\u23f0 <b>Last Seen</b>    : {last_ts}\n"
        f"\U0001f4e4 <b>Reason</b>       : {flush_reason}"
    )


def _flush_ip(ip: str, reason: str) -> None:
    buf = _buffers.pop(ip, None)
    if buf is None:
        return
    msg = _build_batch_message(ip, buf, reason)
    _send_raw(msg)
    print(f"[notifier] Flushed batch for {ip} | user={buf['username']} | "
          f"attempts={buf['count']} | reason={reason}")


def _flush_timed_out(now: float) -> None:
    """Flush any IP buffers that have exceeded BATCH_TIMEOUT."""
    timed_out_ips = [
        ip for ip, buf in _buffers.items()
        if (now - buf["first_seen"]) >= BATCH_TIMEOUT
    ]
    for ip in timed_out_ips:
        _flush_ip(ip, reason="timeout")


# ── Core send ─────────────────────────────────────────────────────────────────

def _send_raw(message: str) -> bool:
    global _last_sent_global

    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[notifier] WARNING: Telegram credentials not set.")
        return False

    # Global spam guard
    now = time.time()
    if now - _last_sent_global < GLOBAL_MIN_INTERVAL:
        time.sleep(GLOBAL_MIN_INTERVAL - (now - _last_sent_global))

    try:
        response = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"},
            timeout=10,
        )
        result = response.json()
        if result.get("ok"):
            _last_sent_global = time.time()
            print("[notifier] OK Message sent to Telegram.")
            return True
        print(f"[notifier] ERROR Telegram: {result.get('description')}")
        return False
    except Exception as e:
        print(f"[notifier] ERROR Exception: {e}")
        return False


# ── Public API ────────────────────────────────────────────────────────────────

def queue_alert(alert: dict, intel: dict) -> None:
    """
    Main entry point for attack alerts.
    Buffers events per (IP + username) and flushes when:
      - username changes          -> flush old batch, start new
      - batch timeout (2 min)     -> force-flush
      - severity is CRITICAL      -> flush immediately
    """
    ip         = alert["ip"]
    username   = alert.get("user") or "unknown"
    severity   = alert["severity"]
    alert_type = alert.get("alert_type", "unknown")
    attempts   = alert.get("attempts", 1)
    now        = time.time()

    # Check and flush any other IPs that have timed out
    _flush_timed_out(now)

    if ip in _buffers:
        buf = _buffers[ip]
        username_changed = buf["username"] != username
        timed_out        = (now - buf["first_seen"]) >= BATCH_TIMEOUT

        if username_changed or timed_out:
            # Flush the old batch, then start a fresh one
            reason = "username_changed" if username_changed else "timeout"
            _flush_ip(ip, reason=reason)
            _buffers[ip] = _new_buffer(username, severity, alert_type, intel, attempts, now)
        else:
            # Same username — accumulate into existing batch
            buf["count"]    += attempts
            buf["last_seen"] = now
            buf["severity"]  = _higher_severity(severity, buf["severity"])
            buf["intel"]     = intel   # keep intel fresh (latest lookup)
            buf["alert_type"] = alert_type if _SEV_RANK.get(severity, 0) >= _SEV_RANK.get(buf["severity"], 0) else buf["alert_type"]
    else:
        _buffers[ip] = _new_buffer(username, severity, alert_type, intel, attempts, now)

    # CRITICAL: flush immediately regardless
    if severity == "CRITICAL":
        _flush_ip(ip, reason="critical")


def send_telegram(message: str, ip: str = "_global", severity: str = "LOW", attempts: int = 1) -> bool:
    """Direct send — used for startup/daily-summary messages only."""
    return _send_raw(message)


def send_startup_message() -> None:
    try:
        _send_raw(
            "\U0001f6e1\ufe0f <b>Security Lab Auditor Started</b>\n"
            "Monitoring server for attacks...\n"
            "All modules active [OK]"
        )
    except Exception as e:
        print(f"[notifier] WARNING: Startup message failed: {e}")


def send_daily_summary(total: int, critical: int, top_ips: list) -> None:
    top_list = "\n".join(
        [f"  \u2022 {ip} \u2014 {count} attempts" for ip, count in top_ips[:5]]
    ) or "  None"
    _send_raw(
        f"\U0001f4ca <b>Daily Security Summary</b>\n\n"
        f"\U0001f525 Total Alerts    : {total}\n"
        f"\U0001f6a8 Critical Alerts : {critical}\n\n"
        f"\U0001f30d Top Attackers:\n{top_list}"
    )
