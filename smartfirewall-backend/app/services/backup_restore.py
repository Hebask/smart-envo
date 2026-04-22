import json
import os
import shutil
from datetime import datetime
from flask import current_app

from app.db import get_db
from app.services.audit import log_action
from app.services.alerts import create_alert
from app.services.dns_filter import rebuild_domains_file_from_db
from app.services.firewall import persist_rules
from app.services.policy import enforce_policies_periodic


EXPORT_TABLES = [
    "devices",
    "blocked_domains",
    "groups",
    "group_members",
    "group_domains",
    "schedules",
    "active_groups",
    "audit_log",
    "alerts",
    "usage_snapshots",
    "users",
    "services",
    "service_domains",
    "settings",
    "domain_categories",
    "activity_logs",
]


def _backup_dir():
    path = current_app.config["BACKUP_DIR"]
    os.makedirs(path, exist_ok=True)
    return path


def _db_path():
    return current_app.config["DB_PATH"]


def _stamp():
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def list_backups():
    path = _backup_dir()
    out = []

    for name in sorted(os.listdir(path), reverse=True):
        full = os.path.join(path, name)
        if not os.path.isfile(full):
            continue
        stat = os.stat(full)
        out.append({
            "name": name,
            "size_bytes": stat.st_size,
            "modified_at": datetime.utcfromtimestamp(stat.st_mtime).isoformat(),
        })
    return out


def create_sqlite_backup():
    backup_name = f"iot_backup_{_stamp()}.db"
    dst = os.path.join(_backup_dir(), backup_name)
    shutil.copy2(_db_path(), dst)

    log_action(
        action="backup.create_sqlite",
        target_type="backup",
        target_id=backup_name,
        payload={"path": dst},
    )

    create_alert(
        level="info",
        category="backup",
        title="SQLite backup created",
        message=f"Backup file '{backup_name}' was created.",
        related_type="backup",
        related_id=backup_name,
        send_email=False,
    )

    return {
        "type": "sqlite",
        "name": backup_name,
        "path": dst,
    }


def create_json_export():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    existing_tables = {r["name"] for r in cur.fetchall()}

    data = {
        "exported_at": datetime.utcnow().isoformat(),
        "tables": {},
        "skipped_tables": [],
    }

    for table in EXPORT_TABLES:
        if table not in existing_tables:
            data["skipped_tables"].append(table)
            continue

        cur.execute(f"SELECT * FROM {table}")
        data["tables"][table] = [dict(r) for r in cur.fetchall()]

    conn.close()

    export_name = f"iot_export_{_stamp()}.json"
    dst = os.path.join(_backup_dir(), export_name)

    with open(dst, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    log_action(
        action="backup.create_json",
        target_type="backup",
        target_id=export_name,
        payload={"path": dst, "skipped_tables": data["skipped_tables"]},
    )

    create_alert(
        level="info",
        category="backup",
        title="JSON export created",
        message=f"Export file '{export_name}' was created.",
        related_type="backup",
        related_id=export_name,
        send_email=False,
    )

    return {
        "type": "json",
        "name": export_name,
        "path": dst,
        "skipped_tables": data["skipped_tables"],
    }

def restore_from_sqlite_backup(filename: str):
    src = os.path.join(_backup_dir(), filename)
    if not os.path.exists(src):
        raise FileNotFoundError(f"Backup file not found: {filename}")

    shutil.copy2(src, _db_path())

    enforce_policies_periodic()
    rebuild_domains_file_from_db()
    persist_rules()

    log_action(
        action="backup.restore_sqlite",
        target_type="backup",
        target_id=filename,
        payload={"path": src},
    )

    create_alert(
        level="warning",
        category="backup",
        title="SQLite backup restored",
        message=f"Backup file '{filename}' was restored.",
        related_type="backup",
        related_id=filename,
        send_email=False,
    )

    return {"restored": filename}


def _clear_tables(conn):
    cur = conn.cursor()
    for table in reversed(EXPORT_TABLES):
        cur.execute(f"DELETE FROM {table}")
    conn.commit()


def restore_from_json_export(filename: str):
    src = os.path.join(_backup_dir(), filename)
    if not os.path.exists(src):
        raise FileNotFoundError(f"Export file not found: {filename}")

    with open(src, "r", encoding="utf-8") as f:
        data = json.load(f)

    tables = data.get("tables", {})

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    existing_tables = {r["name"] for r in cur.fetchall()}

    present_export_tables = [t for t in EXPORT_TABLES if t in tables and t in existing_tables]

    for table in reversed(present_export_tables):
        cur.execute(f"DELETE FROM {table}")
    conn.commit()

    for table in present_export_tables:
        rows = tables.get(table, [])
        if not rows:
            continue

        cols = list(rows[0].keys())
        placeholders = ",".join(["?"] * len(cols))
        col_sql = ",".join(cols)

        for row in rows:
            values = [row.get(c) for c in cols]
            cur.execute(
                f"INSERT INTO {table} ({col_sql}) VALUES ({placeholders})",
                values,
            )

    conn.commit()
    conn.close()

    enforce_policies_periodic()
    rebuild_domains_file_from_db()
    persist_rules()

    log_action(
        action="backup.restore_json",
        target_type="backup",
        target_id=filename,
        payload={"path": src},
    )

    create_alert(
        level="warning",
        category="backup",
        title="JSON export restored",
        message=f"Export file '{filename}' was restored.",
        related_type="backup",
        related_id=filename,
        send_email=False,
    )

    return {"restored": filename}
