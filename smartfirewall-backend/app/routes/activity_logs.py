from flask import Blueprint, jsonify, request

from app.auth import require_admin
from app.services.activity_logs import list_activity_logs, activity_summary

bp = Blueprint("activity_logs", __name__)


@bp.route("/api/activity-logs", methods=["GET"])
@require_admin
def activity_logs_list():
    limit = int(request.args.get("limit", 100))
    category = (request.args.get("category") or "").strip()
    device_ip = (request.args.get("device_ip") or "").strip()
    device_mac = (request.args.get("device_mac") or "").strip()

    rows = list_activity_logs(
        limit=limit,
        category=category,
        device_ip=device_ip,
        device_mac=device_mac,
    )
    return jsonify({"ok": True, "items": rows})


@bp.route("/api/activity-logs/summary", methods=["GET"])
@require_admin
def activity_logs_summary():
    limit = int(request.args.get("limit", 200))
    data = activity_summary(limit=limit)
    return jsonify({"ok": True, **data})
