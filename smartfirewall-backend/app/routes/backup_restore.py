from flask import Blueprint, jsonify, request

from app.auth import require_super_admin
from app.services.backup_restore import (
    list_backups,
    create_sqlite_backup,
    create_json_export,
    restore_from_sqlite_backup,
    restore_from_json_export,
)

bp = Blueprint("backup_restore", __name__)


@bp.route("/api/backups", methods=["GET"])
@require_super_admin
def backups_list():
    return jsonify({"ok": True, "items": list_backups()})


@bp.route("/api/backups/sqlite", methods=["POST"])
@require_super_admin
def backup_create_sqlite():
    item = create_sqlite_backup()
    return jsonify({"ok": True, "backup": item})


@bp.route("/api/backups/json", methods=["POST"])
@require_super_admin
def backup_create_json():
    item = create_json_export()
    return jsonify({"ok": True, "backup": item})


@bp.route("/api/backups/restore/sqlite", methods=["POST"])
@require_super_admin
def backup_restore_sqlite():
    if not request.is_json:
        return jsonify({"ok": False, "error": "json required"}), 400

    filename = (request.json.get("filename") or "").strip()
    if not filename:
        return jsonify({"ok": False, "error": "filename required"}), 400

    try:
        result = restore_from_sqlite_backup(filename)
        return jsonify({"ok": True, **result})
    except FileNotFoundError as e:
        return jsonify({"ok": False, "error": str(e)}), 404
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/api/backups/restore/json", methods=["POST"])
@require_super_admin
def backup_restore_json():
    if not request.is_json:
        return jsonify({"ok": False, "error": "json required"}), 400

    filename = (request.json.get("filename") or "").strip()
    if not filename:
        return jsonify({"ok": False, "error": "filename required"}), 400

    try:
        result = restore_from_json_export(filename)
        return jsonify({"ok": True, **result})
    except FileNotFoundError as e:
        return jsonify({"ok": False, "error": str(e)}), 404
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
