"""
app/dns_sniffer.py

Captures client DNS requests from the AP side.
Looks up device MAC + active group from the current device IP.
Logs every visit to activity_logs.

Run with sudo:
    sudo python -c "
    from app import create_app
    from app.dns_sniffer import start_sniffer
    app = create_app()
    with app.app_context():
        start_sniffer()
    "
"""

from datetime import datetime, timezone

from flask import current_app
from scapy.all import sniff, DNS, DNSQR, IP

from app.db import get_db
from app.categorizer import detect

SKIP_SUFFIXES = (
    ".local", ".arpa", "localhost",
    ".internal", ".lan", ".home"
)


def get_mac_and_group_for_ip(device_ip: str):
    """
    Look up device MAC and active group_id using the client's current IP.
    Returns (mac, group_id). mac may be '' and group_id may be None.
    """
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT mac FROM devices WHERE last_ip=?",
        (device_ip,)
    )
    row = cur.fetchone()
    mac = row["mac"] if row else ""

    group_id = None
    if mac:
        cur.execute("""
            SELECT gm.group_id
            FROM group_members gm
            JOIN active_groups ag ON ag.group_id = gm.group_id
            WHERE gm.device_mac=? AND ag.active=1
            ORDER BY ag.activated_at DESC
            LIMIT 1
        """, (mac,))
        grow = cur.fetchone()
        if grow:
            group_id = grow["group_id"]

    conn.close()
    return mac, group_id


def process_packet(packet):
    if not packet.haslayer(IP):
        return
    if not packet.haslayer(DNS):
        return
    if not packet.haslayer(DNSQR):
        return

    dns = packet.getlayer(DNS)
    if dns.qr != 0:
        return

    try:
        domain = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".").lower()
        device_ip = packet[IP].src

        if not domain:
            return

        if any(domain.endswith(s) for s in SKIP_SUFFIXES):
            return

        if len(domain) < 4:
            return

        mac, group_id = get_mac_and_group_for_ip(device_ip)
        app_name, category = detect(domain)

        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z")
        if ts.endswith("+0000"):
            ts = ts[:-5] + "+00:00"

        conn = get_db()
        conn.execute(
            """
            INSERT INTO activity_logs
            (device_ip, device_mac, domain, app_name, category, group_id, ts)
            VALUES (?,?,?,?,?,?,?)
            """,
            (device_ip, mac, domain, app_name, category, group_id, ts)
        )
        conn.commit()
        conn.close()

        print(f"[{ts}] {device_ip} ({mac}) → {domain} → {app_name} [{category}] group={group_id}")

    except Exception as e:
        print(f"[dns_sniffer] Error: {e}")


def start_sniffer():
    ap_iface = current_app.config.get("AP_IFACE", "wlan0")
    print(f"[dns_sniffer] Starting DNS capture on interface {ap_iface}, udp dst port 53...")
    sniff(
        iface=ap_iface,
        filter="udp dst port 53",
        prn=process_packet,
        store=0,
    )
