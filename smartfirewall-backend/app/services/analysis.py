"""
app/services/analysis.py

Higher-level activity analysis built on top of:
- usage snapshots
- alerts
- audit logs
- winner-group/device policy state

This is the layer that helps the frontend show:
- monitor page data
- user activity analysis
- top active devices
- anomalies / suspicious activity summaries

Design notes:
- stays local-only (aligned with project privacy goals)
- does not modify firewall rules
- focuses on analysis-ready, frontend-friendly responses
"""

from datetime import datetime

from app.db import get_db
from app.services.policy import latest_active_group_per_device
from app.services.alerts import prune_old_alerts
from app.services.audit import prune_old_audit_log
from app.services.usage import usage_summary, usage_by_devices, usage_for_device


def _window_start_sql(hours: int) -> str:
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT datetime('now', '-{int(hours)} hours') AS cutoff")
    cutoff = cur.fetchone()["cutoff"]
    conn.close()
    return cutoff


def _parse_iso(ts: str):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return datetime.min



def _short_text(value: str, max_len: int = 140) -> str:
    s = str(value or "").replace("\n", " ").replace("\r", " ").strip()
    s = " ".join(s.split())
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def _safe_load_json(value: str):
    import json
    try:
        return json.loads(value or "")
    except Exception:
        return None


def _humanize_audit_action(action: str) -> str:
    mapping = {
        "device.update": "Device updated",
        "settings.update": "Settings updated",
        "group.create": "Group created",
        "group.update": "Group updated",
        "group.delete": "Group deleted",
        "group.activate": "Group activated",
        "group.deactivate": "Group deactivated",
        "group.add_member": "Device added to group",
        "group.remove_member": "Device removed from group",
        "service.create": "Service created",
        "service.update": "Service updated",
        "service.delete": "Service deleted",
        "service.add_domain": "Service domain added",
        "service.remove_domain": "Service domain removed",
        "domain.add": "Blocked domain added",
        "domain.delete": "Blocked domain deleted",
        "domain.enable": "Blocked domain enabled",
        "domain.disable": "Blocked domain disabled",
        "schedule.create": "Schedule created",
        "schedule.update": "Schedule updated",
        "schedule.delete": "Schedule deleted",
        "schedule.enable": "Schedule enabled",
        "schedule.disable": "Schedule disabled",
        "backup.create_sqlite": "SQLite backup created",
        "backup.create_json": "JSON export created",
    }
    if action in mapping:
        return mapping[action]
    return action.replace(".", " ").replace("_", " ").strip().title()


def _humanize_audit_message(action: str, target_type: str, target_id: str, payload_text: str) -> str:
    payload = _safe_load_json(payload_text) or {}

    if action == "device.update":
        return f"{target_type.title()} {target_id} was updated."
    if action == "settings.update":
        return "System settings were updated."
    if action == "group.activate":
        applied = payload.get("applied_to")
        return f"Group {target_id} was activated" + (f" and applied to {applied} device(s)." if applied is not None else ".")
    if action == "group.deactivate":
        return f"Group {target_id} was deactivated."
    if action == "group.add_member":
        mac = payload.get("mac", "")
        return f"Device {mac or target_id} was added to group {target_id}."
    if action == "group.remove_member":
        mac = payload.get("mac", "")
        return f"Device {mac or target_id} was removed from a group."
    if action == "service.create":
        name = payload.get("name", "")
        return f"Service '{name}' was created." if name else "A service was created."
    if action == "service.update":
        name = payload.get("name", "")
        return f"Service '{name}' was updated." if name else "A service was updated."
    if action == "service.add_domain":
        domain = payload.get("domain", "")
        return f"Domain '{domain}' was added to a service." if domain else "A service domain was added."
    if action == "service.remove_domain":
        domain = payload.get("domain", "")
        return f"Domain '{domain}' was removed from a service." if domain else "A service domain was removed."
    if action == "domain.add":
        domain = payload.get("domain", "")
        return f"Domain '{domain}' was added to the blocked list." if domain else "A blocked domain was added."
    if action == "domain.delete":
        return f"Blocked domain {target_id} was deleted."
    if action == "schedule.create":
        start = payload.get("start_time", "")
        end = payload.get("end_time", "")
        return f"Schedule created from {start} to {end}." if start or end else "A schedule was created."
    if action == "schedule.update":
        return f"Schedule {target_id} was updated."
    if action == "schedule.delete":
        return f"Schedule {target_id} was deleted."
    if action == "schedule.enable":
        return f"Schedule {target_id} was enabled."
    if action == "schedule.disable":
        return f"Schedule {target_id} was disabled."
    if action == "backup.create_sqlite":
        return "A SQLite backup was created."
    if action == "backup.create_json":
        return "A JSON export was created."

    if payload:
        return _short_text(str(payload), 140)

    return f"{_humanize_audit_action(action)}."

def build_monitor_feed(limit: int = 100):
    """
    Combine alerts + audit logs into one unified monitor feed sorted by time DESC.
    Keep it readable and avoid noisy low-value events.
    """
    prune_old_alerts(30)
    prune_old_audit_log(30)

    conn = get_db()
    cur = conn.cursor()

    # Fetch extra rows so we can filter noise and still return enough items
    fetch_n = max(limit * 3, 60)

    cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (fetch_n,))
    alerts = [dict(r) for r in cur.fetchall()]

    cur.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (fetch_n,))
    audits = [dict(r) for r in cur.fetchall()]

    conn.close()

    items = []

    for a in alerts:
        category = str(a.get("category", "") or "").lower()
        related_type = str(a.get("related_type", "") or "").lower()
        title = str(a.get("title", "") or "").lower()
        message = str(a.get("message", "") or "").lower()

        is_backup_noise = (
            category == "backup"
            or related_type == "backup"
            or "backup created" in title
            or "export created" in title
            or "backup file" in message
            or "export file" in message
        )
        if is_backup_noise:
            continue

        items.append({
            "ts": a.get("ts", ""),
            "kind": "alert",
            "severity": a.get("level", "info"),
            "title": _short_text(a.get("title", ""), 70),
            "message": _short_text(a.get("message", ""), 120),
            "device_mac": a.get("device_mac", ""),
            "source": a.get("category", ""),
            "related_type": a.get("related_type", ""),
            "related_id": a.get("related_id", ""),
            "read": int(a.get("read", 0)),
        })

    noisy_actions = {
        "backup.create_sqlite",
        "backup.create_json",
        "debug.tables",
    }

    for a in audits:
        action = a.get("action", "")
        if action in noisy_actions:
            continue

        items.append({
            "ts": a.get("ts", ""),
            "kind": "audit",
            "severity": "info",
            "title": _humanize_audit_action(action),
            "message": _short_text(
                _humanize_audit_message(
                    action=action,
                    target_type=a.get("target_type", ""),
                    target_id=a.get("target_id", ""),
                    payload_text=a.get("payload", ""),
                ),
                120,
            ),
            "device_mac": "",
            "source": a.get("target_type", ""),
            "related_type": a.get("target_type", ""),
            "related_id": a.get("target_id", ""),
            "actor": a.get("actor", ""),
            "actor_ip": a.get("actor_ip", ""),
        })

    items.sort(key=lambda x: _parse_iso(x.get("ts", "")), reverse=True)
    return items[:limit]


def analysis_overview(hours: int = 24):
    """
    High-level activity summary for dashboard/monitor pages.
    """
    usage = usage_summary(hours=hours)
    top_devices = usage_by_devices(hours=hours)[:5]
    winners = latest_active_group_per_device()

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM devices")
    devices = [dict(r) for r in cur.fetchall()]

    cur.execute("SELECT COUNT(*) AS c FROM alerts")
    total_alerts = int(cur.fetchone()["c"])

    cur.execute("SELECT COUNT(*) AS c FROM alerts WHERE read=0")
    unread_alerts = int(cur.fetchone()["c"])

    cur.execute("SELECT COUNT(*) AS c FROM alerts WHERE level='warning'")
    warning_alerts = int(cur.fetchone()["c"])

    cur.execute("SELECT COUNT(*) AS c FROM alerts WHERE level='critical'")
    critical_alerts = int(cur.fetchone()["c"])

    cur.execute("SELECT COUNT(*) AS c FROM audit_log")
    total_audit_events = int(cur.fetchone()["c"])

    cur.execute("SELECT COUNT(*) AS c FROM groups")
    total_groups = int(cur.fetchone()["c"])

    cur.execute("SELECT COUNT(*) AS c FROM active_groups WHERE active=1")
    active_groups = int(cur.fetchone()["c"])

    conn.close()

    pending_devices = sum(1 for d in devices if int(d["approved"]) == 0)
    manual_blocked_devices = sum(1 for d in devices if int(d["internet_blocked"]) == 1)

    winner_blocked_devices = 0
    for d in devices:
        mac = d["mac"].lower()
        if mac in winners and int(winners[mac]["internet_blocked"]) == 1:
            winner_blocked_devices += 1

    return {
        "hours": hours,
        "usage": usage,
        "counts": {
            "total_devices": len(devices),
            "pending_devices": pending_devices,
            "manual_blocked_devices": manual_blocked_devices,
            "winner_blocked_devices": winner_blocked_devices,
            "total_alerts": total_alerts,
            "unread_alerts": unread_alerts,
            "warning_alerts": warning_alerts,
            "critical_alerts": critical_alerts,
            "total_audit_events": total_audit_events,
            "total_groups": total_groups,
            "active_groups": active_groups,
        },
        "top_devices": top_devices,
    }


def device_activity_analysis(mac: str, hours: int = 24, limit: int = 60):
    """
    Per-device activity analysis:
    - device metadata
    - winner group
    - usage totals
    - usage trend points (interval deltas)
    - recent alerts
    - recent audit logs
    """
    mac = mac.lower().strip()

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM devices WHERE mac=?", (mac,))
    device = cur.fetchone()
    device = dict(device) if device else None

    cur.execute("""
        SELECT g.id, g.name,
               g.internet_blocked, g.dns_filtered,
               COALESCE(ag.active, 0) AS active,
               ag.activated_at
        FROM group_members gm
        JOIN groups g ON g.id = gm.group_id
        LEFT JOIN active_groups ag ON ag.group_id = g.id
        WHERE gm.device_mac=?
        ORDER BY COALESCE(ag.activated_at, '') DESC, g.name ASC
    """, (mac,))
    groups = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT * FROM alerts
        WHERE device_mac=?
        ORDER BY id DESC
        LIMIT 20
    """, (mac,))
    recent_alerts = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT * FROM audit_log
        WHERE target_id=? OR payload LIKE ?
        ORDER BY id DESC
        LIMIT 20
    """, (mac, f"%{mac}%"))
    recent_audit = [dict(r) for r in cur.fetchall()]

    conn.close()

    winners = latest_active_group_per_device()
    winner = winners.get(mac)

    if winner:
        winner = dict(winner)
        for g in groups:
            if int(g.get("id", 0)) == int(winner.get("group_id", 0)):
                winner["group_name"] = g.get("name", "")
                break

    usage = usage_for_device(mac=mac, limit=limit, hours=hours)
    snapshots = usage.get("points", [])

    trend_points = []
    prev = None
    for s in snapshots:
        if prev is None:
            delta_tx = int(s.get("tx_bytes", 0) or 0)
            delta_rx = int(s.get("rx_bytes", 0) or 0)
            delta_total = int(s.get("total_bytes", 0) or 0)
        else:
            delta_tx = max(0, int(s.get("tx_bytes", 0) or 0) - int(prev.get("tx_bytes", 0) or 0))
            delta_rx = max(0, int(s.get("rx_bytes", 0) or 0) - int(prev.get("rx_bytes", 0) or 0))
            delta_total = max(0, int(s.get("total_bytes", 0) or 0) - int(prev.get("total_bytes", 0) or 0))

        trend_points.append({
            "ts": s.get("ts", ""),
            "interval_tx_bytes": delta_tx,
            "interval_rx_bytes": delta_rx,
            "interval_total_bytes": delta_total,
        })
        prev = s

    estimated_active_intervals = len(snapshots)
    estimated_minutes_online = estimated_active_intervals

    if not device:
        current_status = "unknown"
    elif int(device.get("approved", 0)) == 0:
        current_status = "pending"
    elif winner and int(winner.get("internet_blocked", 0)) == 1:
        current_status = "blocked"
    elif int(device.get("internet_blocked", 0)) == 1:
        current_status = "blocked"
    else:
        current_status = "active"

    return {
        "mac": mac,
        "device": device,
        "groups": groups,
        "winner_group": winner,
        "usage_summary": usage.get("summary", {}),
        "usage_snapshots": snapshots,
        "trend_points": trend_points,
        "recent_alerts": recent_alerts,
        "recent_audit": recent_audit,
        "activity_summary": {
            "alerts_count": len(recent_alerts),
            "audit_count": len(recent_audit),
            "estimated_minutes_online": estimated_minutes_online,
            "current_status": current_status,
        }
    }


def detect_anomalies(hours: int = 24, spike_threshold_bytes: int = 50 * 1024 * 1024):
    """
    Basic anomaly detection using current local data.
    Examples:
    - pending devices still present
    - high per-minute traffic spikes
    - warning/critical alerts
    """
    cutoff = _window_start_sql(hours)
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM devices")
    devices = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT * FROM alerts
        WHERE ts >= ? AND level IN ('warning','critical')
        ORDER BY id DESC
        LIMIT 50
    """, (cutoff,))
    recent_alerts = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT * FROM usage_snapshots
        WHERE ts >= ?
        ORDER BY mac ASC, ts ASC
    """, (cutoff,))
    snaps = [dict(r) for r in cur.fetchall()]
    conn.close()

    anomalies = []

    for d in devices:
        if int(d["approved"]) == 0:
            anomalies.append({
                "type": "pending_device",
                "severity": "warning",
                "title": "Pending device still on network",
                "message": f"Device {d.get('name') or d['mac']} is still pending approval.",
                "device_mac": d["mac"],
            })

    for a in recent_alerts:
        anomalies.append({
            "type": "alert",
            "severity": a["level"],
            "title": a["title"],
            "message": a["message"],
            "device_mac": a.get("device_mac", ""),
        })

    by_mac = {}
    for s in snaps:
        by_mac.setdefault(s["mac"].lower(), []).append(s)

    for mac, rows in by_mac.items():
        prev = None
        for r in rows:
            total = int(r["tx_bytes"]) + int(r["rx_bytes"])
            if prev is not None:
                prev_total = int(prev["tx_bytes"]) + int(prev["rx_bytes"])
                delta = total - prev_total if total >= prev_total else total
                if delta >= spike_threshold_bytes:
                    anomalies.append({
                        "type": "traffic_spike",
                        "severity": "warning",
                        "title": "High traffic spike detected",
                        "message": f"Device {mac} generated {delta} bytes in a short interval.",
                        "device_mac": mac,
                        "bytes": delta,
                        "ts": r["ts"],
                    })
            prev = r

    anomalies.sort(key=lambda x: (0 if x.get("severity") == "critical" else 1))
    return anomalies[:100]


def group_content_analytics(group_id: int, days: int = 7):
    """
    Content analytics for a specific group.
    Returns category breakdown, daily visit counts,
    top visited sites, and safety summary.
    """
    conn = get_db()
    cur = conn.cursor()

    cutoff = f"datetime('now', '-{int(days)} days')"

    cur.execute(f"""
        SELECT category,
               COUNT(*) AS count,
               COUNT(*) * 100.0 / MAX(1, (
                   SELECT COUNT(*) FROM activity_logs
                   WHERE group_id=? AND ts >= {cutoff}
               )) AS pct
        FROM activity_logs
        WHERE group_id=? AND ts >= {cutoff}
        GROUP BY category
        ORDER BY count DESC
    """, (group_id, group_id))
    categories = [
        {"category": r["category"], "count": r["count"], "percentage": round(r["pct"], 1)}
        for r in cur.fetchall()
    ]

    cur.execute(f"""
        SELECT DATE(ts) AS day, COUNT(*) AS visits
        FROM activity_logs
        WHERE group_id=? AND ts >= {cutoff}
        GROUP BY DATE(ts)
        ORDER BY day ASC
    """, (group_id,))
    daily = [{"day": r["day"], "visits": r["visits"]} for r in cur.fetchall()]

    cur.execute(f"""
        SELECT domain, app_name, category, COUNT(*) AS visits
        FROM activity_logs
        WHERE group_id=? AND ts >= {cutoff}
        GROUP BY domain
        ORDER BY visits DESC
        LIMIT 5
    """, (group_id,))
    top_sites = [
        {"domain": r["domain"], "app_name": r["app_name"],
         "category": r["category"], "visits": r["visits"]}
        for r in cur.fetchall()
    ]

    cur.execute(
        f"SELECT COUNT(*) AS c FROM activity_logs WHERE group_id=? AND ts >= {cutoff}",
        (group_id,)
    )
    total_visits = int(cur.fetchone()["c"])

    cur.execute(
        f"SELECT COUNT(DISTINCT domain) AS c FROM activity_logs WHERE group_id=? AND ts >= {cutoff}",
        (group_id,)
    )
    unique_domains = int(cur.fetchone()["c"])

    cur.execute(f"""
        SELECT COUNT(*) * 100.0 / MAX(1, (
            SELECT COUNT(*) FROM activity_logs WHERE group_id=? AND ts >= {cutoff}
        )) AS pct
        FROM activity_logs
        WHERE group_id=? AND category='Education' AND ts >= {cutoff}
    """, (group_id, group_id))
    edu_pct = round(cur.fetchone()["pct"] or 0, 1)

    cur.execute("SELECT name FROM groups WHERE id=?", (group_id,))
    grow = cur.fetchone()
    group_name = grow["name"] if grow else f"Group {group_id}"

    conn.close()

    daily_avg = round(total_visits / max(1, days), 1)

    return {
        "group_id": group_id,
        "group_name": group_name,
        "categories": categories,
        "daily": daily,
        "top_sites": top_sites,
        "summary": {
            "total_visits": total_visits,
            "unique_domains": unique_domains,
            "daily_avg": daily_avg,
            "educational_pct": edu_pct,
        }
    }
