from flask import Blueprint, jsonify, request
import sqlite3

from app.auth import require_admin
from app.db import get_db
from app.services.ai_user_reports import managed_user_ai_report
from app.services.policy import (
    latest_active_group_per_device,
    now_local_hhmm,
    today_key,
    time_in_window,
)

bp = Blueprint("managed_users", __name__)


def _user_with_devices(conn, user_id: int):
    cur = conn.cursor()

    cur.execute("""
        SELECT id, name, email, notes, created_at
        FROM managed_users
        WHERE id=?
    """, (user_id,))
    row = cur.fetchone()
    if not row:
        return None

    user = dict(row)

    cur.execute("""
        SELECT d.mac, d.name, d.last_ip, d.last_seen, d.approved,
               d.internet_blocked, d.dns_filtered
        FROM managed_user_devices mud
        JOIN devices d ON d.mac = mud.device_mac
        WHERE mud.managed_user_id=?
        ORDER BY d.name ASC, d.mac ASC
    """, (user_id,))
    user["devices"] = [dict(r) for r in cur.fetchall()]
    return user


@bp.route("/api/managed-users", methods=["GET"])
@require_admin
def list_managed_users():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT mu.id, mu.name, mu.email, mu.notes, mu.created_at,
               COUNT(mud.device_mac) AS devices_count
        FROM managed_users mu
        LEFT JOIN managed_user_devices mud
          ON mud.managed_user_id = mu.id
        GROUP BY mu.id
        ORDER BY mu.name ASC, mu.id ASC
    """)
    items = [dict(r) for r in cur.fetchall()]

    for item in items:
        user_id = item["id"]

        cur.execute("""
            SELECT MAX(al.ts) AS latest_activity_ts
            FROM activity_logs al
            JOIN managed_user_devices mud
              ON mud.device_mac = al.device_mac
            WHERE mud.managed_user_id=?
        """, (user_id,))
        row = cur.fetchone()
        item["latest_activity_ts"] = row["latest_activity_ts"] if row else None

        cur.execute("""
            SELECT al.category, COUNT(*) AS c
            FROM activity_logs al
            JOIN managed_user_devices mud
              ON mud.device_mac = al.device_mac
            WHERE mud.managed_user_id=?
            GROUP BY al.category
            ORDER BY c DESC, al.category ASC
            LIMIT 1
        """, (user_id,))
        top = cur.fetchone()
        item["top_category"] = top["category"] if top else None

    conn.close()
    return jsonify({"ok": True, "items": items})

@bp.route("/api/managed-users", methods=["POST"])
@require_admin
def create_managed_user():
    data = request.get_json(force=True, silent=True) or {}

    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip() or None
    notes = (data.get("notes") or "").strip() or None

    if not name:
        return jsonify({"ok": False, "error": "name is required"}), 400

    conn = get_db()
    cur = conn.cursor()

    if email:
        cur.execute("SELECT id FROM managed_users WHERE lower(email)=lower(?)", (email,))
        if cur.fetchone():
            conn.close()
            return jsonify({"ok": False, "error": "email already exists"}), 409

    cur.execute("""
        INSERT INTO managed_users(name, email, notes)
        VALUES (?, ?, ?)
    """, (name, email, notes))
    conn.commit()
    user_id = cur.lastrowid

    user = _user_with_devices(conn, user_id)
    conn.close()
    return jsonify({"ok": True, "item": user}), 201


@bp.route("/api/managed-users/<int:user_id>", methods=["GET"])
@require_admin
def get_managed_user(user_id):
    conn = get_db()
    user = _user_with_devices(conn, user_id)
    conn.close()

    if not user:
        return jsonify({"ok": False, "error": "not found"}), 404

    return jsonify({"ok": True, "item": user})


@bp.route("/api/managed-users/<int:user_id>", methods=["PUT"])
@require_admin
def update_managed_user(user_id):
    data = request.get_json(force=True, silent=True) or {}

    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip() or None
    notes = (data.get("notes") or "").strip() or None

    if not name:
        return jsonify({"ok": False, "error": "name is required"}), 400

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM managed_users WHERE id=?", (user_id,))
    if not cur.fetchone():
        conn.close()
        return jsonify({"ok": False, "error": "not found"}), 404

    if email:
        cur.execute(
            "SELECT id FROM managed_users WHERE lower(email)=lower(?) AND id<>?",
            (email, user_id)
        )
        if cur.fetchone():
            conn.close()
            return jsonify({"ok": False, "error": "email already exists"}), 409

    cur.execute("""
        UPDATE managed_users
        SET name=?, email=?, notes=?
        WHERE id=?
    """, (name, email, notes, user_id))
    conn.commit()

    user = _user_with_devices(conn, user_id)
    conn.close()
    return jsonify({"ok": True, "item": user})


@bp.route("/api/managed-users/<int:user_id>", methods=["DELETE"])
@require_admin
def delete_managed_user(user_id):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM managed_users WHERE id=?", (user_id,))
    if not cur.fetchone():
        conn.close()
        return jsonify({"ok": False, "error": "not found"}), 404

    cur.execute("DELETE FROM managed_user_devices WHERE managed_user_id=?", (user_id,))
    cur.execute("DELETE FROM managed_users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()

    return jsonify({"ok": True})


@bp.route("/api/managed-users/<int:user_id>/devices", methods=["GET"])
@require_admin
def list_managed_user_devices(user_id):
    conn = get_db()
    user = _user_with_devices(conn, user_id)
    conn.close()

    if not user:
        return jsonify({"ok": False, "error": "not found"}), 404

    return jsonify({"ok": True, "items": user["devices"]})


@bp.route("/api/managed-users/<int:user_id>/devices", methods=["POST"])
@require_admin
def add_device_to_managed_user(user_id):
    data = request.get_json(force=True, silent=True) or {}
    device_mac = (data.get("device_mac") or "").strip().lower()

    if not device_mac:
        return jsonify({"ok": False, "error": "device_mac is required"}), 400

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM managed_users WHERE id=?", (user_id,))
    if not cur.fetchone():
        conn.close()
        return jsonify({"ok": False, "error": "user not found"}), 404

    cur.execute("SELECT mac FROM devices WHERE lower(mac)=?", (device_mac,))
    if not cur.fetchone():
        conn.close()
        return jsonify({"ok": False, "error": "device not found"}), 404

    cur.execute("""
        SELECT managed_user_id, device_mac
        FROM managed_user_devices
        WHERE lower(device_mac)=?
        LIMIT 1
    """, (device_mac,))
    existing = cur.fetchone()

    if existing and int(existing["managed_user_id"]) != int(user_id):
        conn.close()
        return jsonify({
            "ok": False,
            "error": "device already linked to another managed user",
            "managed_user_id": existing["managed_user_id"]
        }), 409

    try:
        cur.execute("""
            INSERT INTO managed_user_devices(managed_user_id, device_mac)
            VALUES (?, ?)
        """, (user_id, device_mac))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({
            "ok": False,
            "error": "device already linked to another managed user"
        }), 409

    user = _user_with_devices(conn, user_id)
    conn.close()
    return jsonify({"ok": True, "item": user})

@bp.route("/api/managed-users/<int:user_id>/devices/<path:device_mac>", methods=["DELETE"])
@require_admin
def remove_device_from_managed_user(user_id, device_mac):
    device_mac = device_mac.strip().lower()

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        DELETE FROM managed_user_devices
        WHERE managed_user_id=? AND device_mac=?
    """, (user_id, device_mac))
    conn.commit()

    user = _user_with_devices(conn, user_id)
    conn.close()

    if not user:
        return jsonify({"ok": False, "error": "user not found"}), 404

    return jsonify({"ok": True, "item": user})


@bp.route("/api/managed-users/<int:user_id>/analytics/content", methods=["GET"])
@require_admin
def managed_user_content_analytics(user_id):
    try:
        days = int(request.args.get("days", "7"))
    except ValueError:
        days = 7

    days = max(1, min(days, 90))

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, name, email, notes, created_at
        FROM managed_users
        WHERE id=?
    """, (user_id,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return jsonify({"ok": False, "error": "not found"}), 404

    user = dict(user_row)

    cur.execute("""
        SELECT device_mac
        FROM managed_user_devices
        WHERE managed_user_id=?
        ORDER BY device_mac ASC
    """, (user_id,))
    device_rows = [r["device_mac"] for r in cur.fetchall()]

    if not device_rows:
        conn.close()
        return jsonify({
            "ok": True,
            "user": user,
            "devices": [],
            "categories": [],
            "daily": [],
            "top_sites": [],
            "summary": {
                "devices_count": 0,
                "total_visits": 0,
                "unique_domains": 0,
                "daily_avg": 0.0,
                "educational_pct": 0,
            }
        })

    placeholders = ",".join(["?"] * len(device_rows))
    cutoff_expr = f"datetime('now', '-{days} days')"

    # categories
    cur.execute(f"""
        SELECT category, COUNT(*) AS count
        FROM activity_logs
        WHERE device_mac IN ({placeholders})
          AND ts >= {cutoff_expr}
        GROUP BY category
        ORDER BY count DESC, category ASC
    """, device_rows)
    category_rows = [dict(r) for r in cur.fetchall()]
    total_visits = sum(int(r["count"]) for r in category_rows)

    categories = []
    for r in category_rows:
        count = int(r["count"])
        pct = round((count * 100.0 / total_visits), 1) if total_visits else 0
        categories.append({
            "category": r["category"],
            "count": count,
            "percentage": pct,
        })

    # daily
    cur.execute(f"""
        SELECT DATE(ts) AS day, COUNT(*) AS visits
        FROM activity_logs
        WHERE device_mac IN ({placeholders})
          AND ts >= {cutoff_expr}
        GROUP BY DATE(ts)
        ORDER BY day ASC
    """, device_rows)
    daily = [{"day": r["day"], "visits": r["visits"]} for r in cur.fetchall()]

    # top sites
    cur.execute(f"""
        SELECT domain, app_name, category, COUNT(*) AS visits
        FROM activity_logs
        WHERE device_mac IN ({placeholders})
          AND ts >= {cutoff_expr}
        GROUP BY domain, app_name, category
        ORDER BY visits DESC, domain ASC
        LIMIT 10
    """, device_rows)
    top_sites = [
        {
            "domain": r["domain"],
            "app_name": r["app_name"],
            "category": r["category"],
            "visits": r["visits"],
        }
        for r in cur.fetchall()
    ]

    # unique domains
    cur.execute(f"""
        SELECT COUNT(DISTINCT domain) AS c
        FROM activity_logs
        WHERE device_mac IN ({placeholders})
          AND ts >= {cutoff_expr}
    """, device_rows)
    unique_domains = int(cur.fetchone()["c"])

    # educational pct
    cur.execute(f"""
        SELECT COUNT(*) AS c
        FROM activity_logs
        WHERE device_mac IN ({placeholders})
          AND ts >= {cutoff_expr}
          AND category='Education'
    """, device_rows)
    education_count = int(cur.fetchone()["c"])
    educational_pct = round((education_count * 100.0 / total_visits), 1) if total_visits else 0

    conn.close()

    return jsonify({
        "ok": True,
        "user": user,
        "devices": device_rows,
        "categories": categories,
        "daily": daily,
        "top_sites": top_sites,
        "summary": {
            "devices_count": len(device_rows),
            "total_visits": total_visits,
            "unique_domains": unique_domains,
            "daily_avg": round(total_visits / max(1, days), 1),
            "educational_pct": educational_pct,
        }
    })


@bp.route("/api/managed-users/<int:target_user_id>/devices/reassign", methods=["POST"])
@require_admin
def reassign_device_to_managed_user(target_user_id):
    data = request.get_json(force=True, silent=True) or {}
    device_mac = (data.get("device_mac") or "").strip().lower()

    if not device_mac:
        return jsonify({"ok": False, "error": "device_mac is required"}), 400

    conn = get_db()
    cur = conn.cursor()

    # target user must exist
    cur.execute("SELECT id FROM managed_users WHERE id=?", (target_user_id,))
    if not cur.fetchone():
        conn.close()
        return jsonify({"ok": False, "error": "target user not found"}), 404

    # device must exist
    cur.execute("SELECT mac FROM devices WHERE lower(mac)=?", (device_mac,))
    if not cur.fetchone():
        conn.close()
        return jsonify({"ok": False, "error": "device not found"}), 404

    # current owner, if any
    cur.execute("""
        SELECT managed_user_id
        FROM managed_user_devices
        WHERE lower(device_mac)=?
        LIMIT 1
    """, (device_mac,))
    row = cur.fetchone()
    previous_user_id = int(row["managed_user_id"]) if row else None

    if previous_user_id == target_user_id:
        user = _user_with_devices(conn, target_user_id)
        conn.close()
        return jsonify({
            "ok": True,
            "moved": False,
            "previous_user_id": previous_user_id,
            "target_user_id": target_user_id,
            "item": user
        })

    # remove old owner if exists
    cur.execute("DELETE FROM managed_user_devices WHERE lower(device_mac)=?", (device_mac,))

    # assign to new owner
    cur.execute("""
        INSERT INTO managed_user_devices(managed_user_id, device_mac)
        VALUES (?, ?)
    """, (target_user_id, device_mac))
    conn.commit()

    user = _user_with_devices(conn, target_user_id)
    conn.close()

    return jsonify({
        "ok": True,
        "moved": previous_user_id is not None,
        "previous_user_id": previous_user_id,
        "target_user_id": target_user_id,
        "item": user
    })


@bp.route("/api/managed-users/<int:user_id>/overview", methods=["GET"])
@require_admin
def managed_user_overview(user_id):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, name, email, notes, created_at
        FROM managed_users
        WHERE id=?
    """, (user_id,))
    user_row = cur.fetchone()
    if not user_row:
        conn.close()
        return jsonify({"ok": False, "error": "not found"}), 404

    user = dict(user_row)

    cur.execute("""
        SELECT d.mac, d.name, d.last_ip, d.last_seen,
               d.approved, d.internet_blocked, d.dns_filtered
        FROM managed_user_devices mud
        JOIN devices d ON d.mac = mud.device_mac
        WHERE mud.managed_user_id=?
        ORDER BY d.name ASC, d.mac ASC
    """, (user_id,))
    devices = [dict(r) for r in cur.fetchall()]

    winners = latest_active_group_per_device()

    cur.execute("SELECT * FROM schedules WHERE enabled=1 ORDER BY id DESC")
    schedules = [dict(r) for r in cur.fetchall()]

    sched_by_group = {}
    for s in schedules:
        gid = int(s["group_id"])
        sched_by_group.setdefault(gid, []).append(s)

    now_hhmm = now_local_hhmm()
    day = today_key()

    device_details = []
    blocked_devices_count = 0
    dns_filtered_devices_count = 0
    pending_devices_count = 0

    for d in devices:
        mac = d["mac"].lower()

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
            SELECT s.id, s.group_id, s.start_time, s.end_time, s.days,
                   s.action, s.enabled
            FROM schedules s
            JOIN group_members gm ON gm.group_id = s.group_id
            WHERE gm.device_mac=?
            ORDER BY s.group_id ASC, s.id ASC
        """, (mac,))
        device_schedules = [dict(r) for r in cur.fetchall()]

        w = winners.get(mac)

        if w:
            gid = int(w["group_id"])
            d["winner_group_id"] = gid
            d["winner_group_name"] = next((g["name"] for g in groups if int(g["id"]) == gid), f"Group {gid}")
            d["winner_activated_at"] = w["activated_at"]
            d["winner_internet_blocked"] = int(w["internet_blocked"])
            d["winner_dns_filtered"] = int(w["dns_filtered"])
        else:
            d["winner_group_id"] = None
            d["winner_group_name"] = None
            d["winner_activated_at"] = None
            d["winner_internet_blocked"] = None
            d["winner_dns_filtered"] = None

        d["schedule_active"] = False
        d["schedule_action"] = None
        d["schedule_id"] = None

        approved = int(d.get("approved", 0))
        manual_block = int(d.get("internet_blocked", 0))
        manual_dns = int(d.get("dns_filtered", 0))

        if approved == 0:
            eff_block = 1
            eff_dns = manual_dns
            reason = "pending"
            pending_devices_count += 1
        elif manual_block == 1:
            eff_block = 1
            eff_dns = manual_dns
            reason = "manual_block"
            blocked_devices_count += 1
        elif not w:
            eff_block = 0
            eff_dns = manual_dns
            reason = "no_active_group"
        else:
            base_block = int(w["internet_blocked"])
            base_dns = int(w["dns_filtered"])

            eff_block = base_block
            eff_dns = 1 if (manual_dns == 1 or base_dns == 1) else 0
            reason = "winner_group"

            gid = int(w["group_id"])
            for s in sched_by_group.get(gid, []):
                days = [x.strip() for x in (s.get("days") or "").split(",") if x.strip()]
                if day not in days:
                    continue

                active = time_in_window(s["start_time"], s["end_time"], now_hhmm)
                if not active:
                    continue

                d["schedule_active"] = True
                d["schedule_action"] = s["action"]
                d["schedule_id"] = s["id"]

                if s["action"] == "allow":
                    eff_block = 0
                    eff_dns = manual_dns
                    reason = "schedule_allow"
                else:
                    eff_block = 1
                    eff_dns = 1 if (manual_dns == 1 or base_dns == 1) else 0
                    reason = "schedule_block"
                break

            if eff_block == 1:
                blocked_devices_count += 1

        if eff_dns:
            dns_filtered_devices_count += 1

        if reason == "pending":
            effective_status = "pending"
        elif reason == "manual_block":
            effective_status = "blocked"
        elif reason == "schedule_block":
            effective_status = "blocked_by_schedule"
        elif reason == "winner_group" and eff_block == 1:
            effective_status = "blocked_by_group"
        else:
            effective_status = "allowed"

        d["effective_internet_blocked"] = eff_block
        d["effective_dns_filtered"] = bool(eff_dns)
        d["effective_reason"] = reason
        d["effective_status"] = effective_status
        d["groups"] = groups
        d["schedules"] = device_schedules

        device_details.append(d)

    conn.close()

    return jsonify({
        "ok": True,
        "user": user,
        "devices": device_details,
        "summary": {
            "devices_count": len(device_details),
            "blocked_devices_count": blocked_devices_count,
            "dns_filtered_devices_count": dns_filtered_devices_count,
            "pending_devices_count": pending_devices_count,
        }
    })


@bp.route("/api/managed-users/<int:user_id>/analytics/ai", methods=["GET"])
@require_admin
def managed_user_ai_analytics(user_id):
    try:
        days = int(request.args.get("days", "7"))
    except ValueError:
        days = 7
    days = 30 if days >= 30 else 7

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM managed_users WHERE id=?", (user_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"ok": False, "error": "not found"}), 404

    report = managed_user_ai_report(user_id=user_id, days=days)
    return jsonify({
        "ok": True,
        "user": {"id": row["id"], "name": row["name"]},
        "report": report
    })
