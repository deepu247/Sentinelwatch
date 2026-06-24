import requests
import os
import time

TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

RATE_LIMIT_SECONDS   = 60 
GLOBAL_MIN_INTERVAL  = 3 

_last_sent_per_ip: dict[str, float] = {}
_last_sent_global: float = 0.0

def _is_rate_limited(ip: str, severity: str) -> bool:
    now = time.time()

    if now - _last_sent_global < GLOBAL_MIN_INTERVAL:
        return True

    if severity == "CRITICAL":
        return False

    last = _last_sent_per_ip.get(ip, 0.0)
    return (now - last) < RATE_LIMIT_SECONDS

def send_telegram(message: str, ip: str = "_global", severity: str = "LOW") -> bool:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[notifier] WARNING: Telegram credentials not set.")
        return False

    if _is_rate_limited(ip, severity):
        print(f"[notifier] Rate-limited — skipping alert for {ip} ({severity})")
        return False

    try:
        response = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"},
            timeout=10,
        )
        result = response.json()
        if result.get("ok"):
            now = time.time()
            _last_sent_per_ip[ip] = now
            globals()["_last_sent_global"] = now
            print("[notifier] OK Alert sent to Telegram.")
            return True
        print(f"[notifier] ERROR Telegram error: {result.get('description')}")
        return False
    except Exception as e:
        print(f"[notifier] ERROR Exception: {e}")
        return False

def send_startup_message() -> None:
    try:
        send_telegram(
            "[SHIELD] <b>Security Lab Auditor Started</b>\n"
            "Monitoring server for attacks...\n"
            "All modules active [OK]",
            ip="_startup",
            severity="LOW",
        )
    except Exception as e:
        print(f"[notifier] WARNING: Startup message failed (Telegram may be blocked): {e}")

def send_daily_summary(total: int, critical: int, top_ips: list) -> None:
    top_list = "\n".join(
        [f"  • {ip} — {count} attempts" for ip, count in top_ips[:5]]
    ) or "  None"
    send_telegram(
        f"📊 <b>Daily Security Summary</b>\n\n"
        f"🔥 Total Alerts    : {total}\n"
        f"🚨 Critical Alerts : {critical}\n\n"
        f"🌍 Top Attackers:\n{top_list}",
        ip="_daily_summary",
        severity="LOW",
    )
