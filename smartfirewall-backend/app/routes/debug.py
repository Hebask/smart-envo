from flask import Blueprint, jsonify
from app.db import get_db
from app.auth import require_admin
from app.services.audit import log_action

bp = Blueprint("debug", __name__)

@bp.route("/api/debug/tables", methods=["GET"])
@require_admin
def debug_tables():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [r["name"] for r in cur.fetchall()]
    conn.close()
    log_action(action="debug.tables",target_type="table",payload={"tables": tables})
    return jsonify({"ok": True, "tables": tables})
