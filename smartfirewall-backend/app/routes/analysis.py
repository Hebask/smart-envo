from flask import Blueprint, jsonify, request

from app.auth import require_admin
from app.services.analysis import (
    analysis_overview,
    build_monitor_feed,
    device_activity_analysis,
    detect_anomalies,
    group_content_analytics,
)
from app.services.ai_analysis import (
    overview_ai_summary,
    device_ai_summary,
)
from app.services.usage import usage_by_devices

bp = Blueprint("analysis", __name__)


@bp.route("/api/analysis/overview", methods=["GET"])
@require_admin
def analysis_overview_route():
    try:
        hours = int(request.args.get("hours", "24"))
    except ValueError:
        hours = 24
    hours = max(1, min(hours, 24 * 30))
    return jsonify({"ok": True, "overview": analysis_overview(hours=hours)})


@bp.route("/api/analysis/overview/ai", methods=["GET"])
@require_admin
def analysis_overview_ai_route():
    try:
        hours = int(request.args.get("hours", "24"))
    except ValueError:
        hours = 24
    hours = max(1, min(hours, 24 * 30))
    return jsonify({"ok": True, "ai": overview_ai_summary(hours=hours)})


@bp.route("/api/analysis/top-devices", methods=["GET"])
@require_admin
def analysis_top_devices_route():
    try:
        hours = int(request.args.get("hours", "24"))
    except ValueError:
        hours = 24

    try:
        limit = int(request.args.get("limit", "10"))
    except ValueError:
        limit = 10

    hours = max(1, min(hours, 24 * 30))
    limit = max(1, min(limit, 100))

    rows = usage_by_devices(hours=hours)[:limit]
    return jsonify({"ok": True, "hours": hours, "devices": rows})


@bp.route("/api/analysis/device/<mac>", methods=["GET"])
@require_admin
def analysis_device_route(mac):
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

    data = device_activity_analysis(mac=mac, hours=hours, limit=limit)
    return jsonify({"ok": True, **data})


@bp.route("/api/analysis/device/<mac>/ai", methods=["GET"])
@require_admin
def analysis_device_ai_route(mac):
    try:
        hours = int(request.args.get("hours", "24"))
    except ValueError:
        hours = 24

    try:
        limit = int(request.args.get("limit", "20"))
    except ValueError:
        limit = 20

    hours = max(1, min(hours, 24 * 30))
    limit = max(1, min(limit, 200))

    return jsonify({"ok": True, "ai": device_ai_summary(mac=mac, hours=hours, limit=limit)})


@bp.route("/api/analysis/anomalies", methods=["GET"])
@require_admin
def analysis_anomalies_route():
    try:
        hours = int(request.args.get("hours", "24"))
    except ValueError:
        hours = 24

    hours = max(1, min(hours, 24 * 30))
    rows = detect_anomalies(hours=hours)
    return jsonify({"ok": True, "hours": hours, "anomalies": rows})


@bp.route("/api/monitor/feed", methods=["GET"])
@require_admin
def monitor_feed_route():
    try:
        limit = int(request.args.get("limit", "100"))
    except ValueError:
        limit = 100

    limit = max(1, min(limit, 500))
    rows = build_monitor_feed(limit=limit)
    return jsonify({"ok": True, "items": rows})


@bp.route("/api/analysis/group/<int:group_id>/content", methods=["GET"])
@require_admin
def group_content_analytics_route(group_id):
    try:
        days = int(request.args.get("days", "7"))
    except ValueError:
        days = 7

    days = max(1, min(days, 90))
    data = group_content_analytics(group_id=group_id, days=days)
    return jsonify({"ok": True, **data})
