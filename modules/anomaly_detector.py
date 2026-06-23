from collections import defaultdict
from datetime import datetime

failed_attempts: dict[str, list[float]] = defaultdict(list)

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW    = 60 
MAX_TRACKED_IPS       = 5000 

def _now() -> float:
    return datetime.now().timestamp()

def _record_failure(ip: str) -> int:
    now = _now()
    failed_attempts[ip].append(now)
    failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t < BRUTE_FORCE_WINDOW]

    if len(failed_attempts) > MAX_TRACKED_IPS:
        oldest_ip = min(failed_attempts, key=lambda k: max(failed_attempts[k], default=0))
        del failed_attempts[oldest_ip]

    return len(failed_attempts[ip])

def detect(event):
    if not event:
        return None

    ip    = event.get("ip", "unknown")
    user  = event.get("user", "unknown")
    time  = event.get("time", "")
    etype = event.get("type", "")

    if etype in (
        "failed_login", "invalid_user", "auth_flood",
        "max_auth_exceeded", "pam_auth_failure",
        "root_attack",
    ):
        count = _record_failure(ip)

        if etype == "root_attack":
            severity = "CRITICAL" if count >= BRUTE_FORCE_THRESHOLD else "HIGH"
            return {
                "alert": "ROOT_ATTACK",
                "ip": ip, "user": "root", "time": time,
                "count": count, "severity": severity,
            }

        if count >= BRUTE_FORCE_THRESHOLD:
            return {
                "alert": "BRUTE_FORCE",
                "ip": ip, "user": user, "time": time,
                "count": count, "severity": "HIGH",
            }

    elif etype in ("successful_login", "successful_login_key"):
        prior = len(failed_attempts.get(ip, []))
        if prior >= 3:
            return {
                "alert": "SUCCESS_AFTER_FAILURES",
                "ip": ip, "user": user, "time": time,
                "count": prior, "severity": "CRITICAL",
            }

    elif etype == "new_user_created":
        return {
            "alert": "NEW_USER_CREATED",
            "ip": "local", "user": user, "time": time,
            "count": 1, "severity": "CRITICAL",
        }

    elif etype == "privilege_escalation":
        return {
            "alert": "PRIVILEGE_ESCALATION",
            "ip": "local", "user": user, "time": time,
            "count": 1, "severity": "CRITICAL",
        }

    return None
