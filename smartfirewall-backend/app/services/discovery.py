"""
app/services/discovery.py

Device discovery from dnsmasq leases.
Updates devices table with last_ip, last_seen, and hostname as name (if name is empty).
Respects runtime setting: device_discovery_enabled
"""

import os
from datetime import datetime
from flask import current_app
from app.db import get_db
from app.services.runtime_settings import is_setting_enabled


def read_leases():
    leases_path = current_app.config["LEASES_PATH"]
    leases = []

    if not os.path.exists(leases_path):
        return leases

    with open(leases_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 4:
                continue
            expiry, mac, ip, hostname = parts[:4]
            leases.append({
                "mac": mac.lower(),
                "ip": ip,
                "hostname": "" if hostname == "*" else hostname,
                "expiry": expiry
            })
    return leases


def upsert_devices_from_leases():
    if not is_setting_enabled("device_discovery_enabled", True):
        return 0

    auto_block_unknown = is_setting_enabled("auto_block_unknown_devices", False)

    leases = read_leases()
    now = datetime.utcnow().isoformat()

    conn = get_db()
    cur = conn.cursor()

    changed = 0
    for l in leases:
        cur.execute("SELECT id, name FROM devices WHERE lower(mac)=?", (l["mac"],))
        existing = cur.fetchone()

        if existing:
            current_name = (existing["name"] or "").strip()
            next_name = current_name or l["hostname"] or ""
            cur.execute("""
                UPDATE devices
                SET name=?,
                    last_ip=?,
                    last_seen=?
                WHERE lower(mac)=?
            """, (next_name, l["ip"], now, l["mac"]))
        else:
            approved = 0
            internet_blocked = 1 if auto_block_unknown else 0
            cur.execute("""
                INSERT INTO devices(mac, name, last_ip, approved, internet_blocked, dns_filtered, last_seen)
                VALUES(?,?,?,?,?,?,?)
            """, (l["mac"], l["hostname"], l["ip"], approved, internet_blocked, 0, now))

        changed += 1

    conn.commit()
    conn.close()
    return changed
