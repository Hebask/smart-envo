"""
app/auth.py

Authentication / authorization helpers.

Supports two modes:

1) Admin API key mode
   - X-API-Key: <ADMIN_API_KEY>
   - good for direct backend testing / development

2) Trusted frontend identity mode
   - X-User-Email: user@example.com
   - X-Frontend-Secret: <FRONTEND_SHARED_SECRET>
   - backend looks up that user in the local users table

Role checks:
- require_admin         => any authenticated admin user OR valid API key
- require_super_admin   => only super_admin user OR valid API key
"""

from functools import wraps
from flask import request, jsonify, g, current_app

from app.db import get_db


def _get_supplied_api_key():
    key = request.headers.get("X-API-Key")
    if key:
        return key.strip()

    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()

    return None


def _api_key_is_valid() -> bool:
    expected = current_app.config.get("ADMIN_API_KEY", "")
    supplied = _get_supplied_api_key()
    return bool(expected and supplied and supplied == expected)


def _frontend_secret_is_valid() -> bool:
    if not current_app.config.get("TRUST_FRONTEND_EMAIL_AUTH", True):
        return False

    expected = (current_app.config.get("FRONTEND_SHARED_SECRET", "") or "").strip()
    supplied = (request.headers.get("X-Frontend-Secret", "") or "").strip()

    return bool(expected and supplied and supplied == expected)


def _load_user_by_email(email: str):
    email = (email or "").strip().lower()
    if not email:
        return None

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM users
        WHERE lower(email)=?
          AND active=1
        LIMIT 1
    """, (email,))
    row = cur.fetchone()
    conn.close()

    return dict(row) if row else None


def get_current_user():
    """
    Resolve the current authenticated identity.

    Priority:
    1) valid API key => synthetic super_admin identity
    2) trusted frontend email + shared secret => DB-backed user
    """
    if _api_key_is_valid():
        return {
            "id": 0,
            "name": "API Key Admin",
            "email": "api-key@local",
            "role": "super_admin",
            "auth_provider": "api_key",
            "active": 1,
        }

    email = (request.headers.get("X-User-Email", "") or "").strip().lower()
    if email and _frontend_secret_is_valid():
        return _load_user_by_email(email)

    return None


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401

        if user.get("role") not in ("admin", "super_admin"):
            return jsonify({"ok": False, "error": "Forbidden"}), 403

        g.current_user = user
        return fn(*args, **kwargs)

    return wrapper


def require_super_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401

        if user.get("role") != "super_admin":
            return jsonify({"ok": False, "error": "Forbidden"}), 403

        g.current_user = user
        return fn(*args, **kwargs)

    return wrapper
