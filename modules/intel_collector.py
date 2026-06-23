import requests
import os

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")
IPINFO_TOKEN  = os.environ.get("IPINFO_TOKEN", "")

def collect_intel(ip):
    intel = {
        "ip":            ip,
        "abuse_score":   0,
        "total_reports": 0,
        "country":       "Unknown",
        "city":          "Unknown",
        "org":           "Unknown",
        "is_tor":        False,
        "is_vpn":        False,
        "last_reported": "Never"
    }

    if ABUSEIPDB_KEY:
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 30},
                timeout=5
            )
            data = r.json().get("data", {})
            intel["abuse_score"]   = data.get("abuseConfidenceScore", 0)
            intel["total_reports"] = data.get("totalReports", 0)
            intel["country"]       = data.get("countryCode", "Unknown")
            intel["last_reported"] = data.get("lastReportedAt", "Never") or "Never"
        except Exception as e:
            print(f"[intel] AbuseIPDB error: {e}")

    try:
        token = f"?token={IPINFO_TOKEN}" if IPINFO_TOKEN else ""
        r = requests.get(f"https://ipinfo.io/{ip}/json{token}", timeout=5)
        info = r.json()
        intel["city"]   = info.get("city",    intel["country"])
        intel["org"]    = info.get("org",     "Unknown")
        privacy = info.get("privacy", {})
        intel["is_tor"] = privacy.get("tor", False)
        intel["is_vpn"] = privacy.get("vpn", False)
        if intel["country"] == "Unknown":
            intel["country"] = info.get("country", "Unknown")
    except Exception as e:
        print(f"[intel] ipinfo error: {e}")

    return intel

def upgrade_severity(alert, intel):
    score   = intel.get("abuse_score", 0)
    current = alert.get("severity", "LOW")
    if score >= 90:                            return "CRITICAL"
    if score >= 50 and current != "CRITICAL":  return "HIGH"
    if score >= 20 and current == "LOW":       return "MEDIUM"
    return current
