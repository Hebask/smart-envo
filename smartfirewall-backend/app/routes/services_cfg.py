from datetime import datetime
from flask import Blueprint, jsonify, request
import sqlite3

from app.auth import require_admin
from app.db import get_db
from app.services.audit import log_action
from app.services.alerts import create_alert
from app.services.dns_filter import rebuild_domains_file_from_db, sanitize_domain
from app.services.service_enforcer import apply_service_blocks
from app.services.firewall import persist_rules

bp = Blueprint("services_cfg", __name__)


def _refresh_runtime_service_state():
    # 1) clean the shared filtered DNS file so service domains do not leak globally
    rebuild_domains_file_from_db()
    # 2) apply selective per-device/per-group service IP blocks
    apply_service_blocks()
    # 3) save current iptables state
    persist_rules()


@bp.route("/api/services", methods=["GET"])
@require_admin
def services_list():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM services ORDER BY id DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"ok": True, "services": rows})


@bp.route("/api/services/<int:service_id>", methods=["GET"])
@require_admin
def services_get(service_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM services WHERE id=?", (service_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"ok": False, "error": "service not found"}), 404

    return jsonify({"ok": True, "service": dict(row)})


@bp.route("/api/services", methods=["POST"])
@require_admin
def services_create():
    if not request.is_json:
        return jsonify({"ok": False, "error": "json required"}), 400

    name = (request.json.get("name") or "").strip()
    description = (request.json.get("description") or "").strip()
    category = (request.json.get("category") or "").strip()
    enabled = 1 if bool(request.json.get("enabled", True)) else 0
    applies_to = (request.json.get("applies_to") or "all").strip()
    device_mac = (request.json.get("device_mac") or "").strip().lower()
    group_id = request.json.get("group_id")

    if not name:
        return jsonify({"ok": False, "error": "name required"}), 400

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO services(name, description, category, enabled, applies_to, device_mac, group_id, created_at)
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                name,
                description,
                category,
                enabled,
                applies_to,
                device_mac,
                group_id,
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()
        service_id = cur.lastrowid
        conn.close()

        log_action(
            action="service.create",
            target_type="service",
            target_id=service_id,
            payload=request.json,
        )

        create_alert(
            level="info",
            category="security",
            title="Service created",
            message=f"Service '{name}' was created.",
            related_type="service",
            related_id=service_id,
            send_email=False,
        )

        _refresh_runtime_service_state()

        return jsonify({"ok": True, "id": service_id, "name": name})
    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "error": "service name already exists"}), 409


@bp.route("/api/services/<int:service_id>", methods=["PUT"])
@require_admin
def services_update(service_id):
    if not request.is_json:
        return jsonify({"ok": False, "error": "json required"}), 400

    name = (request.json.get("name") or "").strip()
    description = (request.json.get("description") or "").strip()
    category = (request.json.get("category") or "").strip()
    enabled = 1 if bool(request.json.get("enabled", True)) else 0
    applies_to = (request.json.get("applies_to") or "all").strip()
    device_mac = (request.json.get("device_mac") or "").strip().lower()
    group_id = request.json.get("group_id")

    if not name:
        return jsonify({"ok": False, "error": "name required"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE services
        SET name=?, description=?, category=?, enabled=?, applies_to=?, device_mac=?, group_id=?
        WHERE id=?
        """,
        (name, description, category, enabled, applies_to, device_mac, group_id, service_id),
    )
    changed = cur.rowcount
    conn.commit()
    conn.close()

    log_action(
        action="service.update",
        target_type="service",
        target_id=service_id,
        payload=request.json,
    )

    create_alert(
        level="info",
        category="security",
        title="Service updated",
        message=f"Service id {service_id} was updated.",
        related_type="service",
        related_id=service_id,
        send_email=False,
    )

    _refresh_runtime_service_state()

    return jsonify({"ok": True, "id": service_id, "updated": changed})


@bp.route("/api/services/<int:service_id>/enable", methods=["POST"])
@require_admin
def services_enable(service_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE services SET enabled=1 WHERE id=?", (service_id,))
    changed = cur.rowcount
    conn.commit()
    conn.close()

    log_action(
        action="service.enable",
        target_type="service",
        target_id=service_id,
        payload={"enabled": 1},
    )

    create_alert(
        level="info",
        category="security",
        title="Service enabled",
        message=f"Service id {service_id} was enabled.",
        related_type="service",
        related_id=service_id,
        send_email=False,
    )

    _refresh_runtime_service_state()

    return jsonify({"ok": True, "id": service_id, "updated": changed})


@bp.route("/api/services/<int:service_id>/disable", methods=["POST"])
@require_admin
def services_disable(service_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE services SET enabled=0 WHERE id=?", (service_id,))
    changed = cur.rowcount
    conn.commit()
    conn.close()

    log_action(
        action="service.disable",
        target_type="service",
        target_id=service_id,
        payload={"enabled": 0},
    )

    create_alert(
        level="info",
        category="security",
        title="Service disabled",
        message=f"Service id {service_id} was disabled.",
        related_type="service",
        related_id=service_id,
        send_email=False,
    )

    _refresh_runtime_service_state()

    return jsonify({"ok": True, "id": service_id, "updated": changed})


@bp.route("/api/services/<int:service_id>", methods=["DELETE"])
@require_admin
def services_delete(service_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM services WHERE id=?", (service_id,))
    changed = cur.rowcount
    conn.commit()
    conn.close()

    log_action(
        action="service.delete",
        target_type="service",
        target_id=service_id,
        payload={},
    )

    create_alert(
        level="warning",
        category="security",
        title="Service removed",
        message=f"Service id {service_id} was removed.",
        related_type="service",
        related_id=service_id,
        send_email=False,
    )

    _refresh_runtime_service_state()

    return jsonify({"ok": True, "id": service_id, "deleted": changed})


@bp.route("/api/services/<int:service_id>/domains", methods=["GET"])
@require_admin
def service_domains_list(service_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM service_domains
        WHERE service_id=?
        ORDER BY domain ASC
        """,
        (service_id,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"ok": True, "service_id": service_id, "domains": rows})


@bp.route("/api/services/<int:service_id>/domains", methods=["POST"])
@require_admin
def service_domain_add(service_id):
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
        INSERT INTO service_domains(service_id, domain, enabled, created_at)
        VALUES(?,?,1,?)
        ON CONFLICT(service_id, domain) DO UPDATE SET enabled=1
        """,
        (service_id, domain, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()

    log_action(
        action="service.add_domain",
        target_type="service",
        target_id=service_id,
        payload={"domain": domain},
    )

    create_alert(
        level="warning",
        category="security",
        title="Service domain added",
        message=f"Domain '{domain}' was added to service {service_id}.",
        related_type="service",
        related_id=service_id,
        send_email=False,
    )

    _refresh_runtime_service_state()

    return jsonify({"ok": True, "service_id": service_id, "domain": domain})


@bp.route("/api/services/domains/<int:service_domain_id>/enable", methods=["POST"])
@require_admin
def service_domain_enable(service_domain_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE service_domains SET enabled=1 WHERE id=?", (service_domain_id,))
    changed = cur.rowcount
    conn.commit()
    conn.close()

    log_action(
        action="service.enable_domain",
        target_type="service_domain",
        target_id=service_domain_id,
        payload={"enabled": 1},
    )

    create_alert(
        level="info",
        category="security",
        title="Service domain enabled",
        message=f"Service domain id {service_domain_id} was enabled.",
        related_type="service_domain",
        related_id=service_domain_id,
        send_email=False,
    )

    _refresh_runtime_service_state()

    return jsonify({"ok": True, "id": service_domain_id, "updated": changed})


@bp.route("/api/services/domains/<int:service_domain_id>/disable", methods=["POST"])
@require_admin
def service_domain_disable(service_domain_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE service_domains SET enabled=0 WHERE id=?", (service_domain_id,))
    changed = cur.rowcount
    conn.commit()
    conn.close()

    log_action(
        action="service.disable_domain",
        target_type="service_domain",
        target_id=service_domain_id,
        payload={"enabled": 0},
    )

    create_alert(
        level="info",
        category="security",
        title="Service domain disabled",
        message=f"Service domain id {service_domain_id} was disabled.",
        related_type="service_domain",
        related_id=service_domain_id,
        send_email=False,
    )

    _refresh_runtime_service_state()

    return jsonify({"ok": True, "id": service_domain_id, "updated": changed})


@bp.route("/api/services/domains/<int:service_domain_id>", methods=["DELETE"])
@require_admin
def service_domain_delete(service_domain_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM service_domains WHERE id=?", (service_domain_id,))
    changed = cur.rowcount
    conn.commit()
    conn.close()

    log_action(
        action="service.delete_domain",
        target_type="service_domain",
        target_id=service_domain_id,
        payload={},
    )

    create_alert(
        level="warning",
        category="security",
        title="Service domain deleted",
        message=f"Service domain id {service_domain_id} was deleted.",
        related_type="service_domain",
        related_id=service_domain_id,
        send_email=False,
    )

    _refresh_runtime_service_state()

    return jsonify({"ok": True, "id": service_domain_id, "deleted": changed})
