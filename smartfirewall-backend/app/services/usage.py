"""
app/services/usage.py

Usage statistics collection using iptables counters.

Design:
- DEVICE_STATS chain is hooked into FORWARD near the top.
- For each device:
    TX rule matches wlan0 -> eth0 by MAC source
    RX rule matches eth0 -> wlan0 by destination IP
- Rules RETURN immediately after counting so they do not affect policy decisions.
- We collect cumulative counters from iptables-save -c and store snapshots in SQLite.

Important limitation:
- RX accounting depends on the device's current IP address.
- If a device IP changes, a new RX rule is added for the new IP.
  Old RX rules are harmless because they stop matching.
"""

import re
from datetime import datetime

from flask import current_app

from app.db import get_db
from app.services.firewall import sh, iptables_rule_exists, iptables_add_rule
from app.services.runtime_settings import is_setting_enabled


def _mac_suffix(mac: str) -> str:
    return re.sub(r"[^a-z0-9]", "", mac.lower())


def _tx_comment(mac: str) -> str:
    return f"USAGE_TX_{_mac_suffix(mac)}"


def _rx_comment(mac: str) -> str:
    return f"USAGE_RX_{_mac_suffix(mac)}"


def ensure_usage_chain_and_hook():
    if not is_setting_enabled("realtime_monitoring_enabled", True):
        return

    sh(["sudo", "iptables", "-N", "DEVICE_STATS"])

    if not iptables_rule_exists(None, "FORWARD", ["-j", "DEVICE_STATS"]):
        iptables_add_rule(None, "FORWARD", ["-j", "DEVICE_STATS"], insert=True, position=3)


def ensure_usage_rules_for_device(mac: str, ip: str):
    if not is_setting_enabled("realtime_monitoring_enabled", True):
        return

    ensure_usage_chain_and_hook()

    ap = current_app.config["AP_IFACE"]
    wan = current_app.config["WAN_IFACE"]
    mac = mac.lower().strip()

    tx_rule = [
        "-i", ap,
        "-o", wan,
        "-m", "mac", "--mac-source", mac,
        "-m", "comment", "--comment", _tx_comment(mac),
        "-j", "RETURN",
    ]

    if not iptables_rule_exists(None, "DEVICE_STATS", tx_rule):
        iptables_add_rule(None, "DEVICE_STATS", tx_rule)

    if ip:
        rx_rule = [
            "-i", wan,
            "-o", ap,
            "-d", ip,
            "-m", "comment", "--comment", _rx_comment(mac),
            "-j", "RETURN",
        ]
        if not iptables_rule_exists(None, "DEVICE_STATS", rx_rule):
            iptables_add_rule(None, "DEVICE_STATS", rx_rule)


def ensure_usage_rules_for_all_devices():
    if not is_setting_enabled("realtime_monitoring_enabled", True):
        return

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT mac, last_ip FROM devices")
    rows = cur.fetchall()
    conn.close()

    for r in rows:
        ensure_usage_rules_for_device(r["mac"], r["last_ip"] or "")


def _read_device_stats_counters():
    rc, out, err = sh(["sudo", "iptables-save", "-c"])
    if rc != 0:
        raise RuntimeError(err or out or "Failed to read iptables-save counters")

    counters = {}

    pattern = re.compile(
        r'^\[(\d+):(\d+)\]\s+-A DEVICE_STATS\b.*--comment(?:\s+"([^"]+)"|\s+(\S+))'
    )

    for line in out.splitlines():
        m = pattern.search(line)
        if not m:
            continue

        packets = int(m.group(1))
        bytes_ = int(m.group(2))
        comment = m.group(3) or m.group(4)

        counters[comment] = {
            "packets": packets,
            "bytes": bytes_,
        }

    return counters


def collect_usage_snapshot():
    if not is_setting_enabled("realtime_monitoring_enabled", True):
        return

    ensure_usage_rules_for_all_devices()
    counters = _read_device_stats_counters()

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT mac, last_ip FROM devices")
    devices = cur.fetchall()

    ts = datetime.utcnow().isoformat()

    for d in devices:
        mac = d["mac"].lower()
        last_ip = d["last_ip"] or ""

        tx = counters.get(_tx_comment(mac), {"packets": 0, "bytes": 0})
        rx = counters.get(_rx_comment(mac), {"packets": 0, "bytes": 0})

        cur.execute("""
            INSERT INTO usage_snapshots(
                ts, mac, last_ip, tx_bytes, rx_bytes, tx_packets, rx_packets
            )
            VALUES(?,?,?,?,?,?,?)
        """, (
            ts,
            mac,
            last_ip,
            int(tx["bytes"]),
            int(rx["bytes"]),
            int(tx["packets"]),
            int(rx["packets"]),
        ))

    conn.commit()
    conn.close()


def _delta(first_value: int, last_value: int) -> int:
    if last_value >= first_value:
        return last_value - first_value
    return last_value if last_value > 0 else 0


def _series_total(rows, field: str) -> int:
    if not rows:
        return 0

    values = [int((r.get(field, 0) or 0)) for r in rows]

    if len(values) == 1:
        return values[0]

    total = 0
    prev = values[0]
    for curr in values[1:]:
        if curr >= prev:
            total += curr - prev
        else:
            total += curr if curr > 0 else 0
        prev = curr

    return total


def _window_start_sql(hours: int) -> str:
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT datetime('now', '-{int(hours)} hours') AS cutoff")
    cutoff = cur.fetchone()["cutoff"]
    conn.close()
    return cutoff


def _is_zero_point(row: dict) -> bool:
    return (
        int(row.get("tx_bytes", 0) or 0) == 0
        and int(row.get("rx_bytes", 0) or 0) == 0
        and int(row.get("tx_packets", 0) or 0) == 0
        and int(row.get("rx_packets", 0) or 0) == 0
    )


def _normalize_points(rows):
    if not rows:
        return rows

    has_nonzero = any(not _is_zero_point(r) for r in rows)
    if not has_nonzero:
        return rows

    cleaned = [r for r in rows if not _is_zero_point(r)]
    return cleaned or rows


def usage_summary(hours: int = 24):
    cutoff = _window_start_sql(hours)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM usage_snapshots
        WHERE ts >= ?
        ORDER BY mac ASC, ts ASC
    """, (cutoff,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    by_mac = {}
    for r in rows:
        by_mac.setdefault(r["mac"], []).append(r)

    total_tx = 0
    total_rx = 0

    for mac, items in by_mac.items():
        items = _normalize_points(items)
        tx = _series_total(items, "tx_bytes")
        rx = _series_total(items, "rx_bytes")
        total_tx += tx
        total_rx += rx

    return {
        "hours": hours,
        "devices_count": len(by_mac),
        "total_tx_bytes": total_tx,
        "total_rx_bytes": total_rx,
        "total_bytes": total_tx + total_rx,
        "monitoring_enabled": is_setting_enabled("realtime_monitoring_enabled", True),
    }


def usage_by_devices(hours: int = 24):
    cutoff = _window_start_sql(hours)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM usage_snapshots
        WHERE ts >= ?
        ORDER BY mac ASC, ts ASC
    """, (cutoff,))
    rows = [dict(r) for r in cur.fetchall()]

    cur.execute("SELECT mac, name, last_ip FROM devices")
    devices = {
        r["mac"].lower(): {"name": r["name"], "last_ip": r["last_ip"]}
        for r in cur.fetchall()
    }
    conn.close()

    by_mac = {}
    for r in rows:
        by_mac.setdefault(r["mac"], []).append(r)

    out = []
    for mac, items in by_mac.items():
        items = _normalize_points(items)

        tx = _series_total(items, "tx_bytes")
        rx = _series_total(items, "rx_bytes")
        txp = _series_total(items, "tx_packets")
        rxp = _series_total(items, "rx_packets")

        meta = devices.get(mac, {})
        out.append({
            "mac": mac,
            "name": meta.get("name") or "Unknown Device",
            "last_ip": meta.get("last_ip") or "",
            "tx_bytes": tx,
            "rx_bytes": rx,
            "total_bytes": tx + rx,
            "tx_packets": txp,
            "rx_packets": rxp,
            "total_packets": txp + rxp,
        })

    out.sort(key=lambda x: x["total_bytes"], reverse=True)
    return out


def usage_for_device(mac: str, limit: int = 100, hours: int = 24):
    mac = mac.lower().strip()
    hours = max(1, int(hours))
    limit = max(1, min(int(limit), 500))
    cutoff = _window_start_sql(hours)

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT mac, name, last_ip FROM devices WHERE lower(mac)=?", (mac,))
    device_row = cur.fetchone()
    device = dict(device_row) if device_row else {"mac": mac, "name": "", "last_ip": ""}

    cur.execute("""
        SELECT *
        FROM (
            SELECT *
            FROM usage_snapshots
            WHERE lower(mac)=? AND ts >= ?
            ORDER BY ts DESC
            LIMIT ?
        ) s
        ORDER BY ts ASC
    """, (mac, cutoff, limit))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    points = []
    for r in rows:
        tx_bytes = int(r.get("tx_bytes", 0) or 0)
        rx_bytes = int(r.get("rx_bytes", 0) or 0)
        tx_packets = int(r.get("tx_packets", 0) or 0)
        rx_packets = int(r.get("rx_packets", 0) or 0)
        points.append({
            "ts": r.get("ts", ""),
            "last_ip": r.get("last_ip", "") or "",
            "tx_bytes": tx_bytes,
            "rx_bytes": rx_bytes,
            "total_bytes": tx_bytes + rx_bytes,
            "tx_packets": tx_packets,
            "rx_packets": rx_packets,
            "total_packets": tx_packets + rx_packets,
        })

    points = _normalize_points(points)

    if points:
        tx = _series_total(points, "tx_bytes")
        rx = _series_total(points, "rx_bytes")
        txp = _series_total(points, "tx_packets")
        rxp = _series_total(points, "rx_packets")
    else:
        tx = rx = txp = rxp = 0

    summary = {
        "tx_bytes": tx,
        "rx_bytes": rx,
        "total_bytes": tx + rx,
        "tx_packets": txp,
        "rx_packets": rxp,
        "total_packets": txp + rxp,
        "snapshots_count": len(points),
        "monitoring_enabled": is_setting_enabled("realtime_monitoring_enabled", True),
    }

    return {
        "mac": mac,
        "name": device.get("name") or "Unknown Device",
        "last_ip": device.get("last_ip") or "",
        "hours": hours,
        "limit": limit,
        "summary": summary,
        "points": points,
        "snapshots": points,
    }
