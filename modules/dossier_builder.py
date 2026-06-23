def build_dossier(alert, intel):
    severity_icons = {
        "CRITICAL": "🚨 CRITICAL",
        "HIGH":     "🔴 HIGH",
        "MEDIUM":   "🟡 MEDIUM",
        "LOW":      "🟢 LOW"
    }
    alert_labels = {
        "BRUTE_FORCE":            "💪 Brute Force Attack",
        "ROOT_ATTACK":            "💀 Root Login Attempt",
        "SUCCESS_AFTER_FAILURES": "⚠️ Successful Login After Failures",
        "NEW_USER_CREATED":       "👻 New User Account Created",
        "PRIVILEGE_ESCALATION":   "🔑 Privilege Escalation Detected"
    }

    ip        = intel.get("ip",            alert.get("ip", "?"))
    country   = intel.get("country",       "Unknown")
    city      = intel.get("city",          "Unknown")
    org       = intel.get("org",           "Unknown")
    score     = intel.get("abuse_score",   0)
    reports   = intel.get("total_reports", 0)
    is_tor    = intel.get("is_tor",        False)
    is_vpn    = intel.get("is_vpn",        False)
    last_seen = intel.get("last_reported", "Never")
    severity  = alert.get("severity",      "LOW")

    flags = []
    if is_tor:    flags.append("🏴 TOR Exit Node")
    if is_vpn:    flags.append("🔴 VPN")
    if score >= 90: flags.append("☠️ Known Attacker (90%+)")
    flags_str = "  " + " | ".join(flags) if flags else "  None"

    return f"""
{'='*40}
{severity_icons.get(severity, severity)} ALERT
{alert_labels.get(alert.get('alert', '?'), alert.get('alert', '?'))}
{'='*40}
🌐 IP Address   : {ip}
🏁 Country      : {country} | {city}
🏢 Org / ISP    : {org}
☠️  Abuse Score  : {score}% ({reports} reports)
🕰️  Last Seen    : {last_seen}
🚮  Flags        :{flags_str}

👤 Target User  : {alert.get('user', '?')}
🔁 Attempts     : {alert.get('count', 1)}
⏰ Time         : {alert.get('time', 'N/A')}
{'='*40}
""".strip()

def build_short_summary(alert, intel):
    return (
        f"[{alert.get('severity', '?')}] "
        f"{alert.get('alert', '?')} — "
        f"{intel.get('ip', alert.get('ip', '?'))} "
        f"({intel.get('country', '?')}) "
        f"score={intel.get('abuse_score', 0)}%"
    )
