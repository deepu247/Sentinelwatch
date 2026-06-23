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


def get_blacklist(conn) -> list:
    rows = conn.execute(
        "SELECT ip, note, added_at FROM blacklist ORDER BY added_at DESC"
    ).fetchall()
    return [{"ip": r[0], "note": r[1], "added_at": r[2]} for r in rows]
