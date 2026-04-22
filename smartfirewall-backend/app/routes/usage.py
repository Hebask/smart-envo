from flask import Blueprint, jsonify, request

from app.auth import require_admin
from app.services.usage import usage_summary, usage_by_devices, usage_for_device

bp = Blueprint("usage", __name__)


@bp.route("/api/usage/summary", methods=["GET"])
@require_admin
def usage_summary_route():
    """
    Overall usage totals for the recent window.
    Query:
      - hours (default 24)
    """
    try:
        hours = int(request.args.get("hours", "24"))
    except ValueError:
        hours = 24

    hours = max(1, min(hours, 24 * 30))
    return jsonify({"ok": True, "summary": usage_summary(hours=hours)})


@bp.route("/api/usage/devices", methods=["GET"])
@require_admin
def usage_devices_route():
    """
    Per-device usage totals for the recent window.
    Query:
      - hours (default 24)
    """
    try:
        hours = int(request.args.get("hours", "24"))
    except ValueError:
        hours = 24

    hours = max(1, min(hours, 24 * 30))
    rows = usage_by_devices(hours=hours)
    return jsonify({"ok": True, "devices": rows, "hours": hours})


@bp.route("/api/usage/device/<mac>", methods=["GET"])
@require_admin
def usage_device_route(mac):
    """
    Recent usage snapshots for one device.
    Query:
      - hours (default 24)
      - limit (default 60, max 500)
    """
    try:
        hours = int(request.args.get("hours", "24"))
    except ValueError:
        hours = 24

    try:
        limit = int(request.args.get("limit", "60"))
    except ValueError:
        limit = 60

    hours = max(1, min(hours, 24 * 30))
    limit = max(1, min(limit, 500))

    data = usage_for_device(mac=mac, limit=limit, hours=hours)
    return jsonify({"ok": True, **data})
