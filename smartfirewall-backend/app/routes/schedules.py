from flask import Blueprint, jsonify, request

from app.auth import require_admin
from app.db import get_db
from app.services.audit import log_action
from app.services.alerts import create_alert
from app.services.policy import enforce_policies_periodic

bp = Blueprint("schedules", __name__)


def _normalize_days(days):
    if isinstance(days, list):
        days = ",".join([str(x).strip().lower() for x in days if str(x).strip()])
    else:
        days = (days or "").strip().lower()

    return days or "mon,tue,wed,thu,fri,sat,sun"


@bp.route("/api/schedules", methods=["POST"])
@require_admin
def schedule_create():
    if not request.is_json:
        return jsonify({"ok": False, "error": "json required"}), 400

    try:
        group_id = int(request.json.get("group_id"))
    except Exception:
        return jsonify({"ok": False, "error": "valid group_id required"}), 400

    start_time = (request.json.get("start_time") or "").strip()
    end_time = (request.json.get("end_time") or "").strip()
    days = _normalize_days(request.json.get("days", "mon,tue,wed,thu,fri,sat,sun"))
    action = (request.json.get("action") or "allow").strip().lower()

    if not start_time or not end_time:
        return jsonify({"ok": False, "error": "start_time and end_time required"}), 400

    if action not in ("allow", "block"):
        return jsonify({"ok": False, "error": "action must be allow or block"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO schedules(group_id, start_time, end_time, days, action, enabled)
        VALUES(?,?,?,?,?,1)
        """,
        (group_id, start_time, end_time, days, action),
    )
    conn.commit()
    schedule_id = cur.lastrowid
    conn.close()

    enforce_policies_periodic()

    log_action(
        action="schedule.create",
        target_type="schedule",
        target_id=schedule_id,
        payload={
            "group_id": group_id,
            "start_time": start_time,
            "end_time": end_time,
            "days": days,
            "action": action,
        },
    )

    create_alert(
        level="info",
        category="schedule",
        title="Schedule created",
        message=f"Schedule created for group {group_id}: {action} from {start_time} to {end_time}.",
        related_type="schedule",
        related_id=schedule_id,
        send_email=False,
    )

    return jsonify({"ok": True, "id": schedule_id})


@bp.route("/api/schedules", methods=["GET"])
@require_admin
def schedule_list():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT s.*, g.name AS group_name
        FROM schedules s
        LEFT JOIN groups g ON g.id = s.group_id
        ORDER BY s.id DESC
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@bp.route("/api/schedules/<int:schedule_id>", methods=["PUT"])
@require_admin
def schedule_update(schedule_id):
    if not request.is_json:
        return jsonify({"ok": False, "error": "json required"}), 400

    try:
        group_id = int(request.json.get("group_id"))
    except Exception:
        return jsonify({"ok": False, "error": "valid group_id required"}), 400

    start_time = (request.json.get("start_time") or "").strip()
    end_time = (request.json.get("end_time") or "").strip()
    days = _normalize_days(request.json.get("days", "mon,tue,wed,thu,fri,sat,sun"))
    action = (request.json.get("action") or "allow").strip().lower()
    enabled = 1 if bool(request.json.get("enabled", True)) else 0

    if not start_time or not end_time:
        return jsonify({"ok": False, "error": "start_time and end_time required"}), 400

    if action not in ("allow", "block"):
        return jsonify({"ok": False, "error": "action must be allow or block"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE schedules
        SET group_id=?, start_time=?, end_time=?, days=?, action=?, enabled=?
        WHERE id=?
    """, (group_id, start_time, end_time, days, action, enabled, schedule_id))
    changed = cur.rowcount
    conn.commit()
    conn.close()

    enforce_policies_periodic()

    log_action(
        action="schedule.update",
        target_type="schedule",
        target_id=schedule_id,
        payload={
            "group_id": group_id,
            "start_time": start_time,
            "end_time": end_time,
            "days": days,
            "action": action,
            "enabled": enabled,
        },
    )

    create_alert(
        level="info",
        category="schedule",
        title="Schedule updated",
        message=f"Schedule id {schedule_id} was updated.",
        related_type="schedule",
        related_id=schedule_id,
        send_email=False,
    )

    return jsonify({"ok": True, "id": schedule_id, "updated": changed})


@bp.route("/api/schedules/<int:schedule_id>/enable", methods=["POST"])
@require_admin
def schedule_enable(schedule_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE schedules SET enabled=1 WHERE id=?", (schedule_id,))
    changed = cur.rowcount
    conn.commit()
    conn.close()

    enforce_policies_periodic()

    log_action(
        action="schedule.enable",
        target_type="schedule",
        target_id=schedule_id,
        payload={"enabled": 1},
    )

    create_alert(
        level="info",
        category="schedule",
        title="Schedule enabled",
        message=f"Schedule id {schedule_id} was enabled.",
        related_type="schedule",
        related_id=schedule_id,
        send_email=False,
    )

    return jsonify({"ok": True, "id": schedule_id, "updated": changed})


@bp.route("/api/schedules/<int:schedule_id>/disable", methods=["POST"])
@require_admin
def schedule_disable(schedule_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE schedules SET enabled=0 WHERE id=?", (schedule_id,))
    changed = cur.rowcount
    conn.commit()
    conn.close()

    enforce_policies_periodic()

    log_action(
        action="schedule.disable",
        target_type="schedule",
        target_id=schedule_id,
        payload={"enabled": 0},
    )

    create_alert(
        level="info",
        category="schedule",
        title="Schedule disabled",
        message=f"Schedule id {schedule_id} was disabled.",
        related_type="schedule",
        related_id=schedule_id,
        send_email=False,
    )

    return jsonify({"ok": True, "id": schedule_id, "updated": changed})


@bp.route("/api/schedules/<int:schedule_id>", methods=["DELETE"])
@require_admin
def schedule_delete(schedule_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM schedules WHERE id=?", (schedule_id,))
    changed = cur.rowcount
    conn.commit()
    conn.close()

    enforce_policies_periodic()

    log_action(
        action="schedule.delete",
        target_type="schedule",
        target_id=schedule_id,
        payload={},
    )

    create_alert(
        level="warning",
        category="schedule",
        title="Schedule deleted",
        message=f"Schedule id {schedule_id} was deleted.",
        related_type="schedule",
        related_id=schedule_id,
        send_email=False,
    )

    return jsonify({"ok": True, "id": schedule_id, "deleted": changed})
