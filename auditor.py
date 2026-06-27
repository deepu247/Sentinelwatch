import time
from datetime import datetime, timedelta

from modules.tailer import stream_server_logs
from modules.parser import parse_line
from modules.anomaly_detector import detect
from modules.intel_collector import collect_intel, upgrade_severity
from modules.notifier import queue_alert, send_startup_message, send_daily_summary
from modules.storage import init_db, save_alert, get_daily_stats, get_top_ips
from modules.whitelist import is_whitelisted, is_blacklisted, add_to_blacklist, get_blacklist_intel
from modules.reporter import generate_report

DAILY_SUMMARY_HOUR = 8

# Auto-blacklist thresholds
AUTO_BLACKLIST_ABUSE_SCORE   = 60   # auto-blacklist if AbuseIPDB score >= this %
AUTO_BLACKLIST_TOTAL_REPORTS = 100  # auto-blacklist if total reports >= this


def _next_daily_time() -> datetime:
    now    = datetime.now()
    target = now.replace(hour=DAILY_SUMMARY_HOUR, minute=0, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return target


def main():
    conn = init_db()
    send_startup_message()

    next_daily = _next_daily_time()

    for raw_line in stream_server_logs():
        if datetime.now() >= next_daily:
            try:
                stats   = get_daily_stats(conn)
                top_ips = get_top_ips(conn)
                send_daily_summary(
                    total=stats["total"],
                    critical=stats["critical"],
                    top_ips=top_ips,
                )
                report_path = generate_report(conn)
                print(f"[auditor] Daily report generated: {report_path}")
            except Exception as e:
                print(f"[auditor] Daily task error: {e}")
            next_daily = _next_daily_time()

        event = parse_line(raw_line)
        if not event:
            continue

        alert = detect(event)
        if not alert:
            continue

        ip = alert["ip"]

        if is_whitelisted(conn, ip):
            print(f"[auditor] Skipping whitelisted IP: {ip}")
            continue

        # --- Blacklist check: skip AbuseIPDB API call if already blacklisted ---
        if is_blacklisted(conn, ip):
            print(f"[auditor] Known blacklisted IP: {ip} — skipping intel API call, using stored intel")
            # Restore REAL intel from the blacklist note (country, city, org, abuse, flags)
            # so Telegram still shows full information without any new API call.
            # Do NOT override severity — keep original so batching works correctly.
            intel = get_blacklist_intel(conn, ip)
        else:
            intel = collect_intel(ip)
            alert["severity"] = upgrade_severity(alert, intel)

            # --- Auto-blacklist triage: store REAL intel data in the note ---
            abuse_score   = intel.get("abuse_score",   0) or 0
            total_reports = intel.get("total_reports", 0) or 0
            if abuse_score >= AUTO_BLACKLIST_ABUSE_SCORE or total_reports >= AUTO_BLACKLIST_TOTAL_REPORTS:
                country  = intel.get("country") or "Unknown"
                city     = intel.get("city")    or ""
                org      = intel.get("org")     or "Unknown"
                is_tor   = intel.get("is_tor",  False)
                is_vpn   = intel.get("is_vpn",  False)
                last_seen = intel.get("last_seen") or "N/A"
                location = f"{country}" + (f", {city}" if city else "")
                flags    = ", ".join(filter(None, [
                    "TOR" if is_tor else "",
                    "VPN" if is_vpn else "",
                ])) or "none"
                note = (
                    f"Auto-blacklisted | "
                    f"abuse={abuse_score}% | reports={total_reports} | "
                    f"location={location} | org={org} | "
                    f"flags={flags} | last_seen={last_seen}"
                )
                add_to_blacklist(conn, ip, note)
                print(f"[auditor] Auto-blacklisted {ip}: {note}")

        # --- Queue alert for batched Telegram notification ---
        queue_alert(alert, intel)
        save_alert(conn, alert, intel)


if __name__ == "__main__":
    main()
