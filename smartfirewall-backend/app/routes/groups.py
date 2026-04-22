from flask import Blueprint, jsonify, request
import sqlite3
from datetime import datetime

from app.auth import require_admin
from app.db import get_db
from app.services.audit import log_action
from app.services.alerts import create_alert
from app.services.dns_filter import rebuild_domains_file_from_db, sanitize_domain
from app.services.firewall import persist_rules
from app.services.policy import enforce_policies_periodic

bp = Blueprint("groups", __name__)


@bp.route("/api/groups", methods=["GET"])
@require_admin
def groups_list():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM groups ORDER BY name ASC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@bp.route("/api/groups", methods=["POST"])
@require_admin
def groups_create():
    try:
        if not request.is_json:
            return jsonify({"ok": False, "error": "json required"}), 400

        name = (request.json.get("name") or "").strip()
        if not name:
            return jsonify({"ok": False, "error": "name required"}), 400

        internet_blocked = 1 if bool(request.json.get("internet_blocked", False)) else 0
        dns_filtered = 1 if bool(request.json.get("dns_filtered", False)) else 0

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO groups(name, internet_blocked, dns_filtered) VALUES(?,?,?)",
            (name, internet_blocked, dns_filtered),
        )
        conn.commit()
        gid = cur.lastrowid
        conn.close()

        log_action(
            action="group.create",
            target_type="group",
            target_id=gid,
            payload={
                "name": name,
                "internet_blocked": internet_blocked,
                "dns_filtered": dns_filtered,
            },
        )

        create_alert(
            level="info",
            category="group",
            title="Group created",
            message=f"Group '{name}' was created.",
            related_type="group",
            related_id=gid,
            send_email=False,
        )

        return jsonify({"ok": True, "id": gid, "name": name})

    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "error": "group name already exists"}), 409
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/api/groups/<int:group_id>", methods=["PUT"])
@require_admin
def groups_update(group_id):
    if not request.is_json:
        return jsonify({"ok": False, "error": "json required"}), 400

    name = (request.json.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "name required"}), 400

    internet_blocked = 1 if bool(request.json.get("internet_blocked", False)) else 0
    dns_filtered = 1 if bool(request.json.get("dns_filtered", False)) else 0

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            UPDATE groups
            SET name=?, internet_blocked=?, dns_filtered=?
            WHERE id=?
        """, (name, internet_blocked, dns_filtered, group_id))
        changed = cur.rowcount
        conn.commit()
        conn.close()

        enforce_policies_periodic()
        rebuild_domains_file_from_db()
        persist_rules()

        log_action(
            action="group.update",
            target_type="group",
            target_id=group_id,
            payload={
                "name": name,
                "internet_blocked": internet_blocked,
                "dns_filtered": dns_filtered,
            },
        )

        create_alert(
            level="info",
            category="group",
            title="Group updated",
            message=f"Group '{name}' was updated.",
            related_type="group",
            related_id=group_id,
            send_email=False,
        )

        return jsonify({"ok": True, "id": group_id, "updated": changed})
    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "error": "group name already exists"}), 409


@bp.route("/api/groups/<int:group_id>", methods=["DELETE"])
@require_admin
def groups_delete(group_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM groups WHERE id=?", (group_id,))
    changed = cur.rowcount
    conn.commit()
    conn.close()

    enforce_policies_periodic()
    rebuild_domains_file_from_db()
    persist_rules()

    log_action(
        action="group.delete",
        target_type="group",
        target_id=group_id,
        payload={},
    )

    create_alert(
        level="warning",
        category="group",
        title="Group deleted",
        message=f"Group id {group_id} was deleted.",
        related_type="group",
        related_id=group_id,
        send_email=False,
    )

    return jsonify({"ok": True, "id": group_id, "deleted": changed})


@bp.route("/api/groups/<int:group_id>/members", methods=["GET"])
@require_admin
def group_members_list(group_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT
            gm.group_id,
            gm.device_mac,
            d.name,
            '' AS owner_label,
            d.last_ip,
            d.last_seen
        FROM group_members gm
        LEFT JOIN devices d ON d.mac = gm.device_mac
        WHERE gm.group_id=?
        ORDER BY gm.device_mac ASC
    """, (group_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"ok": True, "group_id": group_id, "members": rows})


@bp.route("/api/groups/<int:group_id>/members", methods=["POST"])
@require_admin
def group_add_member(group_id):
    mac = (request.json.get("mac") if request.is_json else "") or ""
    mac = mac.lower().strip()
    if not mac:
        return jsonify({"ok": False, "error": "mac required"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT OR IGNORE INTO group_members(group_id, device_mac) VALUES(?,?)",
        (group_id, mac),
    )
    conn.commit()

    cur.execute("SELECT COUNT(*) AS c FROM group_members WHERE group_id=?", (group_id,))
    count = int(cur.fetchone()["c"])
    conn.close()

    enforce_policies_periodic()
    persist_rules()

    log_action(
        action="group.add_member",
        target_type="group",
        target_id=group_id,
        payload={"mac": mac, "members_after": count},
    )

    create_alert(
        level="info",
        category="group",
        title="Device added to group",
        message=f"Device {mac} was added to group {group_id}.",
        device_mac=mac,
        related_type="group",
        related_id=group_id,
        send_email=False,
    )

    return jsonify({"ok": True, "group_id": group_id, "mac": mac, "members": count})


@bp.route("/api/groups/<int:group_id>/members/<path:mac>", methods=["DELETE"])
@require_admin
def group_remove_member(group_id, mac):
    mac = (mac or "").strip().lower()
    if not mac:
        return jsonify({"ok": False, "error": "mac required"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM group_members WHERE group_id=? AND device_mac=?",
        (group_id, mac),
    )
    changed = cur.rowcount
    conn.commit()

    cur.execute("SELECT COUNT(*) AS c FROM group_members WHERE group_id=?", (group_id,))
    count = int(cur.fetchone()["c"])
    conn.close()

    enforce_policies_periodic()
    rebuild_domains_file_from_db()
    persist_rules()

    log_action(
        action="group.remove_member",
        target_type="group",
        target_id=group_id,
        payload={"mac": mac, "members_after": count},
    )

    create_alert(
        level="info",
        category="group",
        title="Device removed from group",
        message=f"Device {mac} was removed from group {group_id}.",
        device_mac=mac,
        related_type="group",
        related_id=group_id,
        send_email=False,
    )

    return jsonify({"ok": True, "group_id": group_id, "mac": mac, "removed": changed, "members": count})


@bp.route("/api/groups/<int:group_id>/domains", methods=["GET"])
@require_admin
def group_domains_list(group_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT group_id, domain, enabled
        FROM group_domains
        WHERE group_id=?
        ORDER BY domain ASC
    """, (group_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"ok": True, "group_id": group_id, "domains": rows})


@bp.route("/api/groups/<int:group_id>/domains", methods=["POST"])
@require_admin
def group_add_domain(group_id):
    if not request.is_json or "domain" not in request.json:
        return jsonify({"ok": False, "error": "domain required"}), 400

    try:
        domain = sanitize_domain(request.json["domain"])
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO group_domains(group_id, domain, enabled) VALUES(?,?,1)",
        (group_id, domain),
    )
    conn.commit()
    conn.close()

    rebuild_domains_file_from_db()

    log_action(
        action="group.add_domain",
        target_type="group",
        target_id=group_id,
        payload={"domain": domain},
    )

    create_alert(
        level="warning",
        category="group",
        title="Group domain added",
        message=f"Domain '{domain}' was added to group {group_id}.",
        related_type="group",
        related_id=group_id,
        send_email=False,
    )

    return jsonify({"ok": True, "domain": domain})


@bp.route("/api/groups/<int:group_id>/domains/<path:domain>/disable", methods=["POST"])
@require_admin
def group_disable_domain(group_id, domain):
    domain = (domain or "").strip().lower()
    if not domain:
        return jsonify({"ok": False, "error": "domain required"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE group_domains
        SET enabled=0
        WHERE group_id=? AND lower(domain)=?
    """, (group_id, domain))
    changed = cur.rowcount
    conn.commit()
    conn.close()

    rebuild_domains_file_from_db()

    log_action(
        action="group.disable_domain",
        target_type="group",
        target_id=group_id,
        payload={"domain": domain, "enabled": 0},
    )

    create_alert(
        level="info",
        category="group",
        title="Group domain disabled",
        message=f"Domain '{domain}' was disabled for group {group_id}.",
        related_type="group",
        related_id=group_id,
        send_email=False,
    )

    return jsonify({"ok": True, "group_id": group_id, "domain": domain, "updated": changed})


@bp.route("/api/groups/<int:group_id>/apply", methods=["POST"])
@require_admin
def group_apply(group_id):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM groups WHERE id=?", (group_id,))
    grp = cur.fetchone()
    if not grp:
        conn.close()
        return jsonify({"ok": False, "error": "group not found", "group_id": group_id}), 404

    activated_at = datetime.utcnow().isoformat()

    cur.execute(
        """
        INSERT INTO active_groups(group_id, active, activated_at)
        VALUES(?,1,?)
        ON CONFLICT(group_id) DO UPDATE SET active=1, activated_at=excluded.activated_at
        """,
        (group_id, activated_at),
    )

    cur.execute("SELECT device_mac FROM group_members WHERE group_id=?", (group_id,))
    macs = [r["device_mac"] for r in cur.fetchall()]

    conn.commit()
    conn.close()

    enforce_policies_periodic()
    rebuild_domains_file_from_db()
    persist_rules()

    log_action(
        action="group.activate",
        target_type="group",
        target_id=group_id,
        payload={"activated_at": activated_at, "applied_to": len(macs)},
    )

    create_alert(
        level="info",
        category="group",
        title="Group activated",
        message=f"Group {group_id} was activated and applied to {len(macs)} devices.",
        related_type="group",
        related_id=group_id,
        send_email=True,
    )

    return jsonify({"ok": True, "group_id": group_id, "active": True, "applied_to": len(macs)})


@bp.route("/api/groups/<int:group_id>/deactivate", methods=["POST"])
@require_admin
def group_deactivate(group_id):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("UPDATE active_groups SET active=0 WHERE group_id=?", (group_id,))
    changed = cur.rowcount

    conn.commit()
    conn.close()

    enforce_policies_periodic()
    rebuild_domains_file_from_db()
    persist_rules()

    log_action(
        action="group.deactivate",
        target_type="group",
        target_id=group_id,
        payload={"updated_rows": changed},
    )

    create_alert(
        level="info",
        category="group",
        title="Group deactivated",
        message=f"Group {group_id} was deactivated.",
        related_type="group",
        related_id=group_id,
        send_email=True,
    )

    return jsonify({"ok": True, "group_id": group_id, "active": False, "updated": changed})


@bp.route("/api/groups/active", methods=["GET"])
@require_admin
def groups_active():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT g.*, ag.active, ag.activated_at
        FROM groups g
        JOIN active_groups ag ON ag.group_id = g.id
        WHERE ag.active=1
        ORDER BY ag.activated_at DESC
        """
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)
