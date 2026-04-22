from datetime import datetime
from app.db import get_db
from app.services.notifications import send_alert_email
from app.services.runtime_settings import is_setting_enabled


def prune_old_alerts(retention_days: int = 30):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM alerts WHERE datetime(ts) < datetime('now', ?)",
        (f"-{int(retention_days)} days",)
    )
    conn.commit()
    deleted = cur.rowcount
    conn.close()
    return deleted


def create_alert(level: str, category: str, title: str, message: str,
                 device_mac: str = "", related_type: str = "", related_id: str = "",
                 send_email: bool = False):
    prune_old_alerts(30)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO alerts(ts, level, category, title, message, device_mac, related_type, related_id, read)
        VALUES(?,?,?,?,?,?,?,?,0)
    """, (
        datetime.utcnow().isoformat(),
        level,
        category,
        title,
        message,
        device_mac,
        related_type,
        str(related_id),
    ))
    conn.commit()
    conn.close()

    if send_email and is_setting_enabled("email_notifications_enabled", True):
        send_alert_email(title=title, message=message, level=level)


def list_alerts(limit: int = 50, unread_only: bool = False):
    prune_old_alerts(30)

    conn = get_db()
    cur = conn.cursor()

    if unread_only:
        cur.execute("SELECT * FROM alerts WHERE read=0 ORDER BY id DESC LIMIT ?", (limit,))
    else:
        cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))

    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def mark_alert_read(alert_id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE alerts SET read=1 WHERE id=?", (alert_id,))
    conn.commit()
    changed = cur.rowcount
    conn.close()
    return changed
