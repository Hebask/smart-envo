from flask import Blueprint, jsonify, request
from datetime import datetime

from app.auth import require_admin
from app.db import get_db
from app.services.audit import log_action
from app.services.alerts import create_alert
from app.services.dns_filter import rebuild_domains_file_from_db, sanitize_domain

bp = Blueprint("domains", __name__)


@bp.route("/api/domains", methods=["GET"])
@require_admin
def domains_list():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM blocked_domains ORDER BY domain ASC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@bp.route("/api/domains", methods=["POST"])
@require_admin
def domains_add():
    if not request.is_json or "domain" not in request.json:
        return jsonify({"ok": False, "error": "domain required"}), 400

    try:
        domain = sanitize_domain(request.json["domain"])
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO blocked_domains(domain, enabled, created_at)
        VALUES(?,?,?)
        ON CONFLICT(domain) DO UPDATE SET enabled=1
        """,
        (domain, 1, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()

    rebuild_domains_file_from_db()

    log_action(
        action="domain.add",
        target_type="domain",
        target_id=domain,
        payload={"domain": domain},
    )

    create_alert(
        level="warning",
        category="domain",
        title="Blocked domain added",
        message=f"Domain '{domain}' was added to the blocked list.",
        related_type="domain",
        related_id=domain,
        send_email=False,
    )

    return jsonify({"ok": True, "domain": domain})


@bp.route("/api/domains/<int:domain_id>/enable", methods=["POST"])
@require_admin
def domains_enable(domain_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE blocked_domains SET enabled=1 WHERE id=?", (domain_id,))
    changed = cur.rowcount
    conn.commit()
    conn.close()

    rebuild_domains_file_from_db()

    log_action(
        action="domain.enable",
        target_type="domain",
        target_id=domain_id,
        payload={"enabled": 1},
    )

    create_alert(
        level="info",
        category="domain",
        title="Blocked domain enabled",
        message=f"Blocked domain id {domain_id} was enabled.",
        related_type="domain",
        related_id=domain_id,
        send_email=False,
    )

    return jsonify({"ok": True, "id": domain_id, "updated": changed})


@bp.route("/api/domains/<int:domain_id>/disable", methods=["POST"])
@require_admin
def domains_disable(domain_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE blocked_domains SET enabled=0 WHERE id=?", (domain_id,))
    changed = cur.rowcount
    conn.commit()
    conn.close()

    rebuild_domains_file_from_db()

    log_action(
        action="domain.disable",
        target_type="domain",
        target_id=domain_id,
        payload={"enabled": 0},
    )

    create_alert(
        level="info",
        category="domain",
        title="Blocked domain disabled",
        message=f"Blocked domain id {domain_id} was disabled.",
        related_type="domain",
        related_id=domain_id,
        send_email=False,
    )

    return jsonify({"ok": True, "id": domain_id, "updated": changed})


@bp.route("/api/domains/<int:domain_id>", methods=["DELETE"])
@require_admin
def domains_delete(domain_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM blocked_domains WHERE id=?", (domain_id,))
    changed = cur.rowcount
    conn.commit()
    conn.close()

    rebuild_domains_file_from_db()

    log_action(
        action="domain.delete",
        target_type="domain",
        target_id=domain_id,
        payload={},
    )

    create_alert(
        level="warning",
        category="domain",
        title="Blocked domain deleted",
        message=f"Blocked domain id {domain_id} was deleted.",
        related_type="domain",
        related_id=domain_id,
        send_email=False,
    )

    return jsonify({"ok": True, "id": domain_id, "deleted": changed})
