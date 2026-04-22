"""
app/services/audit.py

Audit logging helper for admin actions.
Keeps logging consistent and centralized.
Also applies retention cleanup so audit_log does not grow forever.
"""

import json
from datetime import datetime
from flask import request
from app.db import get_db


def prune_old_audit_log(retention_days: int = 30):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM audit_log WHERE datetime(ts) < datetime('now', ?)",
        (f"-{int(retention_days)} days",)
    )
    conn.commit()
    deleted = cur.rowcount
    conn.close()
    return deleted


def list_audit_logs(limit: int = 50):
    prune_old_audit_log(30)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def log_action(action: str, target_type: str, target_id: str = "", payload: dict | None = None):
    """
    Insert an audit entry into SQLite.

    action: short action name (e.g. "group.activate")
    target_type: e.g. "group", "device", "domain", "schedule"
    target_id: e.g. group_id or device MAC
    payload: extra JSON data
    """
    prune_old_audit_log(30)

    actor_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    ts = datetime.utcnow().isoformat()

    payload_str = ""
    if payload is not None:
        try:
            payload_str = json.dumps(payload, ensure_ascii=False)
        except Exception:
            payload_str = str(payload)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO audit_log(ts, actor_ip, actor, action, target_type, target_id, payload)
        VALUES(?,?,?,?,?,?,?)
    """, (ts, actor_ip, "admin", action, target_type, str(target_id), payload_str))
    conn.commit()
    conn.close()
