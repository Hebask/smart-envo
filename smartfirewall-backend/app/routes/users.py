from flask import Blueprint, jsonify, request

from app.auth import require_admin
from app.db import get_db

bp = Blueprint("users", __name__)


def _public_user(row):
    if not row:
        return None
    return {
        "id": row["id"],
        "email": row["email"],
        "name": row["name"],
        "role": row["role"],
        "active": row["active"],
        "auth_provider": row["auth_provider"],
        "created_at": row["created_at"],
        "last_login": row["last_login"],
    }


def _get_user_by_email(email: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, email, name, role, active, auth_provider, created_at, last_login
        FROM users
        WHERE lower(email)=lower(?)
        LIMIT 1
    """, (email,))
    row = cur.fetchone()
    conn.close()
    return row


def _get_primary_admin():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, email, name, role, active, auth_provider, created_at, last_login
        FROM users
        WHERE active=1
        ORDER BY CASE role WHEN 'super_admin' THEN 0 ELSE 1 END, id
        LIMIT 1
    """)
    row = cur.fetchone()
    conn.close()
    return row


@bp.route("/api/me", methods=["GET"])
@require_admin
def me():
    supplied_email = (request.headers.get("X-User-Email") or "").strip()
    row = _get_user_by_email(supplied_email) if supplied_email else None
    if not row:
        row = _get_primary_admin()

    if not row:
        return jsonify({"ok": False, "error": "No active admin found"}), 404

    return jsonify({"ok": True, "user": _public_user(row)})


@bp.route("/api/users", methods=["GET"])
@require_admin
def users_list():
    """
    Single-admin model:
    keep this read-only for compatibility,
    but only return active admin users.
    """
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, email, name, role, active, auth_provider, created_at, last_login
        FROM users
        WHERE active=1
        ORDER BY CASE role WHEN 'super_admin' THEN 0 ELSE 1 END, id
    """)
    rows = [_public_user(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"ok": True, "users": rows})


@bp.route("/api/users/by-email/<path:email>", methods=["GET"])
@require_admin
def user_by_email(email):
    row = _get_user_by_email(email)
    if not row:
        return jsonify({"ok": False, "error": "User not found"}), 404
    return jsonify({"ok": True, "user": _public_user(row)})


@bp.route("/api/users", methods=["POST"])
@require_admin
def users_create_disabled():
    return jsonify({
        "ok": False,
        "error": "User creation is disabled in single-admin mode"
    }), 403


@bp.route("/api/users/<int:user_id>", methods=["PUT", "PATCH"])
@require_admin
def users_update_disabled(user_id):
    return jsonify({
        "ok": False,
        "error": "User editing is disabled in single-admin mode",
        "id": user_id
    }), 403


@bp.route("/api/users/<int:user_id>", methods=["DELETE"])
@require_admin
def users_delete_disabled(user_id):
    return jsonify({
        "ok": False,
        "error": "User deletion is disabled in single-admin mode",
        "id": user_id
    }), 403
