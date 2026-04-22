from flask import Blueprint, jsonify, request

from app.auth import require_admin
from app.services.alerts import list_alerts, mark_alert_read

bp = Blueprint("alerts", __name__)


@bp.route("/api/alerts", methods=["GET"])
@require_admin
def alerts_list():
    """
    Return recent alerts for the dashboard/alerts page.

    Query params:
      - limit: default 50, max 200
      - unread_only: true/false
    """
    try:
        limit = int(request.args.get("limit", "50"))
    except ValueError:
        limit = 50

    limit = max(1, min(limit, 200))
    unread_only = request.args.get("unread_only", "false").lower() == "true"

    rows = list_alerts(limit=limit, unread_only=unread_only)
    return jsonify({"ok": True, "alerts": rows})


@bp.route("/api/alerts/<int:alert_id>/read", methods=["POST"])
@require_admin
def alerts_mark_read(alert_id):
    """
    Mark a single alert as read.
    Useful for the frontend alert center.
    """
    changed = mark_alert_read(alert_id)
    return jsonify({"ok": True, "id": alert_id, "updated": changed})
