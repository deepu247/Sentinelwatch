import os
from datetime import datetime

REPORTS_DIR = os.environ.get("REPORTS_DIR", "reports")


def _ensure_reports_dir() -> str:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    return REPORTS_DIR


def _severity_color(s: str) -> str:
    return {"CRITICAL": "#ff4757", "HIGH": "#ffa502",
            "MEDIUM": "#4da6ff", "LOW": "#2ed573"}.get(s, "#c9d8e8")


CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: #090d12;
  color: #c9d8e8;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  padding: 32px 24px;
  max-width: 1100px;
  margin: 0 auto;
  line-height: 1.5;
}
h1 { font-size: 22px; font-weight: 700; color: #fff; margin-bottom: 6px; }
.meta { font-size: 12px; color: #5a7a99; margin-bottom: 28px; font-family: monospace; }
.grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 28px; }
.card { background: #141b24; border: 1px solid #1e2d3d; border-radius: 10px; padding: 18px 20px; }
.card-val { font-size: 36px; font-weight: 700; line-height: 1; margin-bottom: 6px; }
.card-label { font-size: 11px; color: #5a7a99; text-transform: uppercase; letter-spacing: .5px; }
.section { background: #141b24; border: 1px solid #1e2d3d; border-radius: 10px; padding: 20px 24px; margin-bottom: 20px; }
h2 { font-size: 14px; font-weight: 600; color: #fff; margin-bottom: 16px; }
.bar-row { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }
.bar-label { width: 80px; font-size: 12px; font-weight: 600; text-align: right; }
.bar-track { flex: 1; height: 10px; background: #1e2d3d; border-radius: 5px; }
.bar-fill { height: 100%; border-radius: 5px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { padding: 8px 12px; text-align: left; font-size: 11px; text-transform: uppercase;
     letter-spacing: .5px; color: #5a7a99; font-weight: 500; border-bottom: 1px solid #1e2d3d; }
td { padding: 10px 12px; border-bottom: 1px solid #1a2535; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(77,166,255,.04); }
.footer { margin-top: 32px; font-size: 11px; color: #2e4460; text-align: center;
          padding-top: 16px; border-top: 1px solid #1e2d3d; }
"""


def generate_report(conn) -> str:
    now      = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%B %d, %Y \u2014 %H:%M")

    row = conn.execute("""
        SELECT
            COUNT(*)                 AS total,
            SUM(severity='CRITICAL') AS critical,
            SUM(severity='HIGH')     AS high,
            SUM(severity='MEDIUM')   AS medium,
            SUM(severity='LOW')      AS low,
            COUNT(DISTINCT ip)       AS unique_ips
        FROM alerts
        WHERE timestamp > datetime('now', '-1 day')
    """).fetchone()
    total, critical, high, medium, low, unique_ips = [int(v or 0) for v in row]

    top_ips = conn.execute("""
        SELECT ip, country, org, MAX(abuse_score) AS abuse,
               SUM(is_tor) AS tor_hits, COUNT(*) AS hits
        FROM alerts
        WHERE timestamp > datetime('now', '-1 day')
        GROUP BY ip ORDER BY hits DESC LIMIT 10
    """).fetchall()

    alerts = conn.execute("""
        SELECT timestamp, alert_type, severity, ip, user,
               country, abuse_score, is_tor, is_vpn
        FROM alerts
        WHERE timestamp > datetime('now', '-1 day')
        ORDER BY id DESC
    """).fetchall()

    bar_max = max(critical, high, medium, low, 1)
    bars = (
        f'<div class="bar-row"><div class="bar-label" style="color:#ff4757">CRITICAL</div>'
        f'<div class="bar-track"><div class="bar-fill" style="width:{round(critical/bar_max*100)}%;background:#ff4757"></div></div>'
        f'<div style="font-size:12px;color:#ff4757;min-width:30px">{critical}</div></div>'
        f'<div class="bar-row"><div class="bar-label" style="color:#ffa502">HIGH</div>'
        f'<div class="bar-track"><div class="bar-fill" style="width:{round(high/bar_max*100)}%;background:#ffa502"></div></div>'
        f'<div style="font-size:12px;color:#ffa502;min-width:30px">{high}</div></div>'
        f'<div class="bar-row"><div class="bar-label" style="color:#4da6ff">MEDIUM</div>'
        f'<div class="bar-track"><div class="bar-fill" style="width:{round(medium/bar_max*100)}%;background:#4da6ff"></div></div>'
        f'<div style="font-size:12px;color:#4da6ff;min-width:30px">{medium}</div></div>'
        f'<div class="bar-row"><div class="bar-label" style="color:#2ed573">LOW</div>'
        f'<div class="bar-track"><div class="bar-fill" style="width:{round(low/bar_max*100)}%;background:#2ed573"></div></div>'
        f'<div style="font-size:12px;color:#2ed573;min-width:30px">{low}</div></div>'
    )

    top_rows = ""
    for r in top_ips:
        ip, country, org, abuse, tor_hits, hits = r
        flags = " \U0001f3f4" if tor_hits else ""
        top_rows += (
            f"<tr>"
            f"<td style='font-family:monospace;color:#4da6ff'>{ip}</td>"
            f"<td>{country or '\u2014'}</td>"
            f"<td style='max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>{org or '\u2014'}</td>"
            f"<td style='color:#ffa502'>{abuse}%</td>"
            f"<td style='color:#ff4757;font-weight:700'>{hits}{flags}</td>"
            f"</tr>"
        )
    if not top_rows:
        top_rows = "<tr><td colspan='5' style='text-align:center;padding:24px;color:#2e4460'>No attacks in last 24h</td></tr>"

    alert_rows = ""
    for a in alerts:
        ts, atype, sev, ip, user, country, abuse, is_tor, is_vpn = a
        color = _severity_color(sev)
        flags = ("TOR " if is_tor else "") + ("VPN" if is_vpn else "")
        alert_rows += (
            f"<tr>"
            f"<td style='color:#5a7a99;font-size:11px;white-space:nowrap;font-family:monospace'>{ts}</td>"
            f"<td style='font-family:monospace;color:#4da6ff'>{ip}</td>"
            f"<td>{user or '\u2014'}</td>"
            f"<td style='font-size:12px'>{atype}</td>"
            f"<td style='font-size:12px'>{country or '\u2014'}</td>"
            f"<td style='color:#ffa502'>{abuse}%</td>"
            f"<td><span style='font-size:10px;font-weight:700;padding:2px 9px;border-radius:20px;"
            f"background:rgba(0,0,0,.4);color:{color};border:1px solid {color}55'>{sev}</span></td>"
            f"<td style='font-size:11px;color:#5a7a99'>{flags.strip()}</td>"
            f"</tr>"
        )
    if not alert_rows:
        alert_rows = "<tr><td colspan='8' style='text-align:center;padding:24px;color:#2e4460'>No alerts</td></tr>"

    html = (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
        "  <meta charset=\"UTF-8\">\n"
        f"  <title>Security Report \u2014 {date_str}</title>\n"
        f"  <style>{CSS}</style>\n"
        "</head>\n<body>\n"
        f"  <h1>\U0001f6e1\ufe0f Security Lab \u2014 Daily Attack Report</h1>\n"
        f"  <div class=\"meta\">Generated: {time_str} &nbsp;|&nbsp; Period: last 24 hours</div>\n"
        "  <div class=\"grid\">\n"
        f"    <div class=\"card\"><div class=\"card-val\" style=\"color:#fff\">{total}</div><div class=\"card-label\">Total Alerts</div></div>\n"
        f"    <div class=\"card\"><div class=\"card-val\" style=\"color:#ff4757\">{critical}</div><div class=\"card-label\">Critical</div></div>\n"
        f"    <div class=\"card\"><div class=\"card-val\" style=\"color:#ffa502\">{high}</div><div class=\"card-label\">High</div></div>\n"
        f"    <div class=\"card\"><div class=\"card-val\" style=\"color:#4da6ff\">{unique_ips}</div><div class=\"card-label\">Unique IPs</div></div>\n"
        "  </div>\n"
        "  <div class=\"section\">\n"
        "    <h2>\U0001f4ca Severity Breakdown</h2>\n"
        f"    {bars}\n"
        "  </div>\n"
        "  <div class=\"section\">\n"
        "    <h2>\U0001f30d Top Attacking IPs</h2>\n"
        "    <table><thead><tr><th>IP Address</th><th>Country</th><th>Org / ISP</th><th>Abuse Score</th><th>Hits</th></tr></thead>\n"
        f"    <tbody>{top_rows}</tbody></table>\n"
        "  </div>\n"
        f"  <div class=\"section\">\n"
        f"    <h2>\U0001f6a8 All Alerts ({len(alerts)})</h2>\n"
        "    <div style=\"overflow-x:auto\">\n"
        "    <table><thead><tr><th>Time</th><th>IP</th><th>User</th><th>Type</th><th>Country</th><th>Abuse</th><th>Severity</th><th>Flags</th></tr></thead>\n"
        f"    <tbody>{alert_rows}</tbody></table>\n"
        "    </div>\n  </div>\n"
        f"  <div class=\"footer\">Security Lab Auditor &nbsp;|&nbsp; Auto-generated report for {date_str}</div>\n"
        "</body>\n</html>\n"
    )

    reports_dir = _ensure_reports_dir()
    filename    = f"report_{date_str}_{now.strftime('%H%M')}.html"
    filepath    = os.path.join(reports_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[reporter] Report saved: {filepath}")
    return filepath


def list_reports() -> list:
    if not os.path.isdir(REPORTS_DIR):
        return []
    files = [f for f in os.listdir(REPORTS_DIR)
             if f.startswith("report_") and f.endswith(".html")]
    return sorted(files, reverse=True)
