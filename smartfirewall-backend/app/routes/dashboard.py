from flask import Blueprint, jsonify

from app.auth import require_admin
from app.db import get_db
from app.services.policy import latest_active_group_per_device
from app.services.runtime_settings import is_setting_enabled

bp = Blueprint("dashboard", __name__)


@bp.route("/api/dashboard/summary", methods=["GET"])
@require_admin
def dashboard_summary():
    """
    Return frontend-friendly dashboard summary data.

    Includes:
    - summary counts
    - recent alerts
    - recent audit entries

    Notes:
      pending -> blocked
      manual block -> blocked
      winner group block -> blocked
    """
    conn = get_db()
    cur = conn.cursor()

    # -------------------------
    # Devices
    # -------------------------
    cur.execute("SELECT * FROM devices")
    devices = [dict(r) for r in cur.fetchall()]

    total_devices = len(devices)
    pending_devices = sum(1 for d in devices if int(d["approved"]) == 0)
    manual_blocked_devices = sum(1 for d in devices if int(d["internet_blocked"]) == 1)
    dns_filtered_devices = sum(1 for d in devices if int(d["dns_filtered"]) == 1)

    # -------------------------
    # Groups
    # -------------------------
    cur.execute("SELECT COUNT(*) AS c FROM groups")
    total_groups = int(cur.fetchone()["c"])

    cur.execute("SELECT COUNT(*) AS c FROM active_groups WHERE active=1")
    active_groups = int(cur.fetchone()["c"])

    # -------------------------
    # Schedules
    # -------------------------
    cur.execute("SELECT COUNT(*) AS c FROM schedules")
    total_schedules = int(cur.fetchone()["c"])

    cur.execute("SELECT COUNT(*) AS c FROM schedules WHERE enabled=1")
    active_schedules = int(cur.fetchone()["c"])

    # -------------------------
    # Domains
    # -------------------------
    cur.execute("SELECT COUNT(*) AS c FROM blocked_domains")
    total_domains = int(cur.fetchone()["c"])

    cur.execute("SELECT COUNT(*) AS c FROM blocked_domains WHERE enabled=1")
    active_domains = int(cur.fetchone()["c"])

    # -------------------------
    # Alerts
    # -------------------------
    cur.execute("SELECT COUNT(*) AS c FROM alerts")
    total_alerts = int(cur.fetchone()["c"])

    cur.execute("SELECT COUNT(*) AS c FROM alerts WHERE read=0")
    unread_alerts = int(cur.fetchone()["c"])

    cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 5")
    recent_alerts = [dict(r) for r in cur.fetchall()]

    # -------------------------
    # Audit logs
    # -------------------------
    cur.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 5")
    recent_audit = [dict(r) for r in cur.fetchall()]

    conn.close()

    # -------------------------
    # Effective blocked devices
    # -------------------------
    firewall_enabled = is_setting_enabled("firewall_enabled", True)

    if not firewall_enabled:
        manual_blocked_devices = 0
        dns_filtered_devices = 0
        effective_blocked_devices = 0
    else:
        winners = latest_active_group_per_device()
        effective_blocked_devices = 0

        for d in devices:
            mac = d["mac"].lower()

            if int(d["approved"]) == 0:
                effective_blocked_devices += 1
            elif int(d["internet_blocked"]) == 1:
                effective_blocked_devices += 1
            elif mac in winners and int(winners[mac]["internet_blocked"]) == 1:
                effective_blocked_devices += 1

    return jsonify({
        "ok": True,
        "summary": {
            "total_devices": total_devices,
            "pending_devices": pending_devices,
            "manual_blocked_devices": manual_blocked_devices,
            "effective_blocked_devices": effective_blocked_devices,
            "dns_filtered_devices": dns_filtered_devices,
            "total_groups": total_groups,
            "active_groups": active_groups,
            "total_schedules": total_schedules,
            "active_schedules": active_schedules,
            "total_domains": total_domains,
            "active_domains": active_domains,
            "total_alerts": total_alerts,
            "unread_alerts": unread_alerts
        },
        "recent_alerts": recent_alerts,
        "recent_audit": recent_audit
    })
