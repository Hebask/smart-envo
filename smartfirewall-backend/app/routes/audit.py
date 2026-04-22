from flask import Blueprint, jsonify, request

from app.auth import require_admin
from app.services.audit import list_audit_logs

bp = Blueprint("audit", __name__)


@bp.route("/api/audit", methods=["GET"])
@require_admin
def audit_list():
    """
    Admin-only: return newest audit log entries.

    Query params:
      - limit: optional, default 50, max 200
    """
    try:
        limit = int(request.args.get("limit", "50"))
    except ValueError:
        limit = 50

    limit = max(1, min(limit, 200))
    rows = list_audit_logs(limit=limit)
    return jsonify({"ok": True, "logs": rows})
