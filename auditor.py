import time
from datetime import datetime, timedelta

from modules.tailer import stream_server_logs
from modules.parser import parse_line
from modules.anomaly_detector import detect
from modules.intel_collector import collect_intel, upgrade_severity
from modules.dossier_builder import build_dossier
from modules.notifier import send_telegram, send_startup_message, send_daily_summary
from modules.storage import init_db, save_alert, get_daily_stats, get_top_ips
from modules.whitelist import is_whitelisted
from modules.reporter import generate_report

DAILY_SUMMARY_HOUR = 8 

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

        if is_whitelisted(conn, alert["ip"]):
            print(f"[auditor] Skipping whitelisted IP: {alert['ip']}")
            continue

        intel = collect_intel(alert["ip"])
        alert["severity"] = upgrade_severity(alert, intel)

        report = build_dossier(alert, intel)
        send_telegram(report, ip=alert["ip"], severity=alert["severity"])
        save_alert(conn, alert, intel)

if __name__ == "__main__":
    main()
