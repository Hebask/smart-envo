from datetime import datetime, timezone

from app.db import get_db


def _utc_iso():
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z")
    if ts.endswith("+0000"):
        ts = ts[:-5] + "+00:00"
    return ts


def insert_activity_log(
    device_ip: str = "",
    device_mac: str = "",
    domain: str = "",
    query_name: str = "",
    app_name: str = "",
    category: str = "Other",
    action: str = "",
    details: str = "",
    group_id=None,
    ts: str | None = None,
):
    """
    Backward-compatible helper for the CURRENT activity_logs schema.

    Old callers may still pass query_name/action/details.
    We keep accepting them so old code does not crash, but only store
    the fields that exist in the live table:

        activity_logs(
            id, device_ip, device_mac, domain, app_name,
            category, group_id, ts
        )
    """
    conn = get_db()
    cur = conn.cursor()

    final_domain = (domain or query_name or "").strip().lower()
    final_ts = ts or _utc_iso()
    final_app_name = (app_name or "").strip()
    final_category = (category or "Other").strip() or "Other"

    cur.execute("""
        INSERT INTO activity_logs
        (device_ip, device_mac, domain, app_name, category, group_id, ts)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        (device_ip or "").strip(),
        (device_mac or "").strip().lower(),
        final_domain,
        final_app_name,
        final_category,
        group_id,
        final_ts,
    ))

    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return row_id


def list_activity_logs(
    limit: int = 100,
    category: str = "",
    device_ip: str = "",
    device_mac: str = "",
    group_id=None,
    domain: str = "",
):
    conn = get_db()
    cur = conn.cursor()

    limit = max(1, min(int(limit), 1000))

    sql = "SELECT * FROM activity_logs WHERE 1=1"
    params = []

    if category:
        sql += " AND category=?"
        params.append(category)

    if device_ip:
        sql += " AND device_ip=?"
        params.append(device_ip)

    if device_mac:
        sql += " AND lower(device_mac)=?"
        params.append(device_mac.lower())

    if group_id is not None and str(group_id).strip() != "":
        sql += " AND group_id=?"
        params.append(int(group_id))

    if domain:
        sql += " AND lower(domain)=?"
        params.append(domain.lower())

    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def activity_summary(limit: int = 200):
    conn = get_db()
    cur = conn.cursor()

    limit = max(1, min(int(limit), 2000))

    cur.execute("""
        SELECT category, COUNT(*) AS count
        FROM (
            SELECT * FROM activity_logs
            ORDER BY id DESC
            LIMIT ?
        )
        GROUP BY category
        ORDER BY count DESC, category ASC
    """, (limit,))
    by_category = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT device_ip, device_mac, COUNT(*) AS count
        FROM (
            SELECT * FROM activity_logs
            ORDER BY id DESC
            LIMIT ?
        )
        GROUP BY device_ip, device_mac
        ORDER BY count DESC, device_ip ASC, device_mac ASC
    """, (limit,))
    by_device = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT group_id, COUNT(*) AS count
        FROM (
            SELECT * FROM activity_logs
            ORDER BY id DESC
            LIMIT ?
        )
        GROUP BY group_id
        ORDER BY count DESC
    """, (limit,))
    by_group = [dict(r) for r in cur.fetchall()]

    conn.close()
    return {
        "by_category": by_category,
        "by_device": by_device,
        "by_group": by_group,
    }
