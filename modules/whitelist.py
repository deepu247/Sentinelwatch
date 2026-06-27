def init_lists(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS whitelist (
            ip        TEXT PRIMARY KEY,
            note      TEXT DEFAULT '',
            added_at  TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            ip        TEXT PRIMARY KEY,
            note      TEXT DEFAULT '',
            added_at  TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.commit()


def add_to_whitelist(conn, ip: str, note: str = "") -> None:
    conn.execute(
        "INSERT OR REPLACE INTO whitelist (ip, note) VALUES (?, ?)",
        (ip, note)
    )
    conn.commit()


def remove_from_whitelist(conn, ip: str) -> None:
    conn.execute("DELETE FROM whitelist WHERE ip = ?", (ip,))
    conn.commit()


def is_whitelisted(conn, ip: str) -> bool:
    row = conn.execute("SELECT 1 FROM whitelist WHERE ip = ?", (ip,)).fetchone()
    return row is not None


def get_whitelist(conn) -> list:
    rows = conn.execute(
        "SELECT ip, note, added_at FROM whitelist ORDER BY added_at DESC"
    ).fetchall()
    return [{"ip": r[0], "note": r[1], "added_at": r[2]} for r in rows]


def add_to_blacklist(conn, ip: str, note: str = "") -> None:
    conn.execute(
        "INSERT OR REPLACE INTO blacklist (ip, note) VALUES (?, ?)",
        (ip, note)
    )
    conn.commit()


def remove_from_blacklist(conn, ip: str) -> None:
    conn.execute("DELETE FROM blacklist WHERE ip = ?", (ip,))
    conn.commit()


def is_blacklisted(conn, ip: str) -> bool:
    row = conn.execute("SELECT 1 FROM blacklist WHERE ip = ?", (ip,)).fetchone()
    return row is not None


def get_blacklist_intel(conn, ip: str) -> dict:
    """
    Parse the stored blacklist note to reconstruct the original intel dict.
    Note format: "Auto-blacklisted | abuse=76% | reports=42 | location=CN, Beijing | org=China Telecom | flags=VPN | last_seen=..."
    """
    import re
    row = conn.execute("SELECT note FROM blacklist WHERE ip = ?", (ip,)).fetchone()
    intel = {
        "abuse_score":    100,
        "total_reports":  999,
        "country":        "Unknown",
        "city":           "",
        "org":            "Unknown",
        "is_tor":         False,
        "is_vpn":         False,
        "is_blacklisted": True,
    }
    if not row or not row[0]:
        return intel
    note = row[0]
    m = re.search(r'abuse=(\d+)%', note)
    if m:
        intel["abuse_score"] = int(m.group(1))
    m = re.search(r'reports=(\d+)', note)
    if m:
        intel["total_reports"] = int(m.group(1))
    m = re.search(r'location=([^|]+)', note)
    if m:
        loc = m.group(1).strip()
        parts = loc.split(',', 1)
        intel["country"] = parts[0].strip() or "Unknown"
        intel["city"]    = parts[1].strip() if len(parts) > 1 else ""
    m = re.search(r'org=([^|]+)', note)
    if m:
        intel["org"] = m.group(1).strip() or "Unknown"
    flags_lower = note.lower()
    intel["is_tor"] = "tor" in flags_lower
    intel["is_vpn"] = "vpn" in flags_lower
    return intel


def get_blacklist(conn) -> list:
    rows = conn.execute(
        "SELECT ip, note, added_at FROM blacklist ORDER BY added_at DESC"
    ).fetchall()
    return [{"ip": r[0], "note": r[1], "added_at": r[2]} for r in rows]
