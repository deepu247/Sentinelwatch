#!/usr/bin/env python3
"""
instant_report.py — called by server.js when the user clicks ⚡ Instant Report.
Generates the HTML report, sends stats summary + file to Telegram, prints filename.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.storage  import init_db
from modules.reporter import generate_report
from modules.notifier import send_report_to_telegram


def main():
    conn     = init_db()
    filepath = generate_report(conn)

    # Query stats for the Telegram summary
    row = conn.execute(
        "SELECT "
        "  COUNT(*), "
        "  SUM(severity='CRITICAL'), "
        "  SUM(severity='HIGH'), "
        "  SUM(severity='MEDIUM'), "
        "  SUM(severity='LOW'), "
        "  COUNT(DISTINCT ip) "
        "FROM alerts "
        "WHERE timestamp > datetime('now', '-1 day')"
    ).fetchone()

    stats = {
        "total":      int(row[0] or 0),
        "critical":   int(row[1] or 0),
        "high":       int(row[2] or 0),
        "medium":     int(row[3] or 0),
        "low":        int(row[4] or 0),
        "unique_ips": int(row[5] or 0),
    }

    send_report_to_telegram(filepath, stats)

    # Print just the filename so server.js can read it
    print(os.path.basename(filepath))


if __name__ == "__main__":
    main()
