"""
app/db.py

SQLite connection + schema init.
We keep:
- WAL mode
- longer timeouts
to reduce 'database is locked' issues.

This file also performs lightweight schema migration on startup so the
current Pi database does not depend on manual one-off sqlite changes.
"""

import os
import sqlite3
from flask import current_app


DEFAULT_DB_PATH = "/home/smart-envo/smartfirewall-backend/iot.db"


def _connect(db_path: str):
    conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def get_db():
    db_path = current_app.config["DB_PATH"]
    return _connect(db_path)


def _table_columns(cur, table_name: str):
    cur.execute(f"PRAGMA table_info({table_name})")
    return {row["name"] for row in cur.fetchall()}


def _ensure_column(cur, table_name: str, column_name: str, column_sql: str):
    cols = _table_columns(cur, table_name)
    if column_name not in cols:
        cur.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_sql}")



def cleanup_orphan_rows(conn):
    cur = conn.cursor()

    cur.execute("""
    DELETE FROM active_groups
    WHERE group_id NOT IN (SELECT id FROM groups)
    """)

    cur.execute("""
    DELETE FROM group_members
    WHERE group_id NOT IN (SELECT id FROM groups)
       OR device_mac NOT IN (SELECT mac FROM devices)
    """)

    cur.execute("""
    DELETE FROM group_domains
    WHERE group_id NOT IN (SELECT id FROM groups)
    """)

    cur.execute("""
    DELETE FROM schedules
    WHERE group_id NOT IN (SELECT id FROM groups)
    """)

    cur.execute("""
    DELETE FROM service_domains
    WHERE service_id NOT IN (SELECT id FROM services)
    """)

    cur.execute("""
    DELETE FROM managed_user_devices
    WHERE managed_user_id NOT IN (SELECT id FROM managed_users)
       OR device_mac NOT IN (SELECT mac FROM devices)
    """)

def init_db():
    db_path = os.getenv("DB_PATH", DEFAULT_DB_PATH)
    conn = _connect(db_path)
    cur = conn.cursor()

    # -----------------------
    # core tables
    # -----------------------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mac TEXT UNIQUE NOT NULL,
        name TEXT DEFAULT '',
        owner_label TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        last_ip TEXT DEFAULT '',
        approved INTEGER DEFAULT 0,
        internet_blocked INTEGER DEFAULT 0,
        dns_filtered INTEGER DEFAULT 0,
        last_seen TEXT DEFAULT ''
    )
    """)

    # migration safety for older Pi DBs
    _ensure_column(cur, "devices", "owner_label", "owner_label TEXT DEFAULT ''")
    _ensure_column(cur, "devices", "notes", "notes TEXT DEFAULT ''")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS blocked_domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        enabled INTEGER DEFAULT 1,
        created_at TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        internet_blocked INTEGER DEFAULT 0,
        dns_filtered INTEGER DEFAULT 0
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS group_members (
        group_id INTEGER NOT NULL,
        device_mac TEXT NOT NULL,
        PRIMARY KEY(group_id, device_mac),
        FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
        FOREIGN KEY(device_mac) REFERENCES devices(mac) ON DELETE CASCADE
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS group_domains (
        group_id INTEGER NOT NULL,
        domain TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        PRIMARY KEY(group_id, domain),
        FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS schedules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        days TEXT NOT NULL,
        action TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS active_groups (
        group_id INTEGER PRIMARY KEY,
        active INTEGER DEFAULT 1,
        activated_at TEXT NOT NULL,
        FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        actor_ip TEXT NOT NULL,
        actor TEXT DEFAULT 'admin',
        action TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT DEFAULT '',
        payload TEXT DEFAULT ''
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        level TEXT NOT NULL,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        device_mac TEXT DEFAULT '',
        related_type TEXT DEFAULT '',
        related_id TEXT DEFAULT '',
        read INTEGER DEFAULT 0
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS usage_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        mac TEXT NOT NULL,
        last_ip TEXT DEFAULT '',
        tx_bytes INTEGER DEFAULT 0,
        rx_bytes INTEGER DEFAULT 0,
        tx_packets INTEGER DEFAULT 0,
        rx_packets INTEGER DEFAULT 0
    )
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_usage_snapshots_mac_ts
    ON usage_snapshots(mac, ts)
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin',
        auth_provider TEXT NOT NULL DEFAULT 'google',
        active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL,
        last_login TEXT DEFAULT ''
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        description TEXT DEFAULT '',
        category TEXT DEFAULT '',
        enabled INTEGER DEFAULT 1,
        applies_to TEXT DEFAULT 'all',
        device_mac TEXT DEFAULT '',
        group_id INTEGER,
        created_at TEXT NOT NULL,
        FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE SET NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS service_domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service_id INTEGER NOT NULL,
        domain TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        created_at TEXT NOT NULL,
        UNIQUE(service_id, domain),
        FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)

    cur.execute("""
    INSERT OR IGNORE INTO settings(key, value, updated_at) VALUES
    ('firewall_enabled', 'true', datetime('now')),
    ('auto_block_unknown_devices', 'false', datetime('now')),
    ('device_discovery_enabled', 'true', datetime('now')),
    ('realtime_monitoring_enabled', 'true', datetime('now')),
    ('intrusion_detection_enabled', 'true', datetime('now')),
    ('email_notifications_enabled', 'true', datetime('now'))
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS domain_categories (
        domain TEXT PRIMARY KEY,
        app_name TEXT NOT NULL DEFAULT '',
        category TEXT NOT NULL DEFAULT 'Other'
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_ip TEXT NOT NULL DEFAULT '',
        device_mac TEXT NOT NULL DEFAULT '',
        domain TEXT NOT NULL DEFAULT '',
        app_name TEXT NOT NULL DEFAULT '',
        category TEXT NOT NULL DEFAULT 'Other',
        group_id INTEGER DEFAULT NULL,
        ts TEXT NOT NULL DEFAULT ''
    )
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_activity_logs_group_ts
    ON activity_logs(group_id, ts)
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_activity_logs_mac_ts
    ON activity_logs(device_mac, ts)
    """)

    # -----------------------
    # managed users/profile tables
    # -----------------------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS managed_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT,
        notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS managed_user_devices (
        managed_user_id INTEGER NOT NULL,
        device_mac TEXT NOT NULL,
        PRIMARY KEY (managed_user_id, device_mac),
        FOREIGN KEY (managed_user_id) REFERENCES managed_users(id) ON DELETE CASCADE
    )
    """)

    cur.execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS idx_managed_user_devices_device_mac
    ON managed_user_devices(device_mac)
    """)

    cleanup_orphan_rows(conn)
    conn.commit()
    conn.close()
