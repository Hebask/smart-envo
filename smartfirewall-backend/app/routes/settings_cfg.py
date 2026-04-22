from datetime import datetime
from flask import Blueprint, jsonify, request

from app.auth import require_admin
from app.db import get_db
from app.services.audit import log_action
from app.services.alerts import create_alert

bp = Blueprint("settings_cfg", __name__)


@bp.route("/api/settings", methods=["GET"])
@require_admin
def settings_get():
    hidden_keys = {"intrusion_detection_enabled"}

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT key, value, updated_at FROM settings ORDER BY key ASC")
    rows = [dict(r) for r in cur.fetchall() if r["key"] not in hidden_keys]
    conn.close()

    settings = {r["key"]: r["value"] for r in rows}
    return jsonify({"ok": True, "settings": settings, "items": rows})


@bp.route("/api/settings", methods=["PUT"])
@require_admin
def settings_update():
    if not request.is_json:
        return jsonify({"ok": False, "error": "json required"}), 400

    allowed_keys = {
        "firewall_enabled",
        "auto_block_unknown_devices",
        "device_discovery_enabled",
        "realtime_monitoring_enabled",
        "email_notifications_enabled",
    }

    updates = {}
    for key, value in request.json.items():
        if key in allowed_keys:
            updates[key] = str(value).lower() if isinstance(value, bool) else str(value)

    if not updates:
        return jsonify({"ok": False, "error": "no valid settings provided"}), 400

    conn = get_db()
    cur = conn.cursor()

    now = datetime.utcnow().isoformat()
    for key, value in updates.items():
        cur.execute("""
            INSERT INTO settings(key, value, updated_at)
            VALUES(?,?,?)
            ON CONFLICT(key) DO UPDATE SET
                value=excluded.value,
                updated_at=excluded.updated_at
        """, (key, value, now))

    conn.commit()

    cur.execute("SELECT key, value, updated_at FROM settings ORDER BY key ASC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    log_action(
        action="settings.update",
        target_type="settings",
        target_id="global",
        payload=updates,
    )

    create_alert(
        level="info",
        category="security",
        title="Settings updated",
        message="Global firewall settings were updated.",
        related_type="settings",
        related_id="global",
        send_email=False,
    )

    settings = {r["key"]: r["value"] for r in rows}
    return jsonify({"ok": True, "settings": settings, "items": rows})
