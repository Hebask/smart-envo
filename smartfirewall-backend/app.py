import os
import re
import sqlite3
import subprocess
from datetime import datetime
from flask import Flask, request, jsonify
from apscheduler.schedulers.background import BackgroundScheduler

AP_IFACE = "wlan0"
WAN_IFACE = "eth0"

DB_PATH = os.path.expanduser("~/iotfirewall-backend/iot.db")
LEASES_PATH = "/var/lib/misc/dnsmasq.leases"

DOMAINS_FILE = "/etc/dnsmasq-filtered.d/domains.conf"
FILTERED_DNS_SERVICE = "dnsmasq-filtered"

APP_PORT = 5000

app = Flask(__name__)

# -------------------------
# Helpers: DB
# -------------------------
def db():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mac TEXT UNIQUE NOT NULL,
        name TEXT DEFAULT '',
        last_ip TEXT DEFAULT '',
        approved INTEGER DEFAULT 0,
        internet_blocked INTEGER DEFAULT 0,
        dns_filtered INTEGER DEFAULT 0,
        last_seen TEXT DEFAULT ''
    )
    """)

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

    conn.commit()
    conn.close()

# -------------------------
# Helpers: time
# -------------------------
def now_local_hhmm():
    return datetime.now().strftime("%H:%M")

def today_key():
    return datetime.now().strftime("%a").lower()[:3]  # mon,tue,...

def time_in_window(start_hhmm, end_hhmm, now_hhmm):
    if start_hhmm <= end_hhmm:
        return start_hhmm <= now_hhmm <= end_hhmm
    return now_hhmm >= start_hhmm or now_hhmm <= end_hhmm

def parse_iso(ts: str):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return datetime.min

# -------------------------
# Helpers: iptables
# -------------------------
DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

def sh(cmd: list[str]) -> tuple[int, str, str]:
    env = dict(os.environ)
    env["PATH"] = DEFAULT_PATH
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def run_cmd(args):
    r = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(args)}\n{r.stderr.strip()}")
    return r.stdout.strip()

def iptables_rule_exists(table, chain, rule_parts):
    cmd = ["sudo", "iptables"]
    if table:
        cmd += ["-t", table]
    cmd += ["-C", chain] + rule_parts
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return r.returncode == 0

def iptables_add_rule(table, chain, rule_parts, insert=False, position=1):
    cmd = ["sudo", "iptables"]
    if table:
        cmd += ["-t", table]
    if insert:
        cmd += ["-I", chain, str(position)] + rule_parts
    else:
        cmd += ["-A", chain] + rule_parts
    run_cmd(cmd)

def iptables_delete_rule(table, chain, rule_parts):
    cmd = ["sudo", "iptables"]
    if table:
        cmd += ["-t", table]
    cmd += ["-D", chain] + rule_parts
    while True:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if r.returncode != 0:
            break

def ensure_chains_exist():
    sh(["sudo", "iptables", "-N", "IOT_BLOCK"])
    sh(["sudo", "iptables", "-N", "IOT_ALLOW"])
    sh(["sudo", "iptables", "-t", "nat", "-N", "DNS_FILTER"])

def enforce_pending_block(mac, should_block: bool):
    ensure_chains_exist()
    mac = mac.lower().strip()
    rule = ["-i", AP_IFACE, "-o", WAN_IFACE, "-m", "mac", "--mac-source", mac, "-j", "DROP"]
    if should_block:
        if not iptables_rule_exists(None, "IOT_BLOCK", rule):
            iptables_add_rule(None, "IOT_BLOCK", rule, insert=True, position=1)
    else:
        iptables_delete_rule(None, "IOT_BLOCK", rule)

def set_internet_block(mac: str, blocked: bool):
    ensure_chains_exist()
    mac = mac.lower().strip()
    rule = ["-i", AP_IFACE, "-o", WAN_IFACE, "-m", "mac", "--mac-source", mac, "-j", "DROP"]
    if blocked:
        if not iptables_rule_exists(None, "IOT_BLOCK", rule):
            iptables_add_rule(None, "IOT_BLOCK", rule, insert=True, position=1)
    else:
        iptables_delete_rule(None, "IOT_BLOCK", rule)

def set_dns_filter(mac: str, enabled: bool):
    ensure_chains_exist()
    mac = mac.lower().strip()

    rule_udp = ["-m", "mac", "--mac-source", mac, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353"]
    rule_tcp = ["-m", "mac", "--mac-source", mac, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353"]

    if enabled:
        if not iptables_rule_exists("nat", "DNS_FILTER", rule_udp):
            iptables_add_rule("nat", "DNS_FILTER", rule_udp)
        if not iptables_rule_exists("nat", "DNS_FILTER", rule_tcp):
            iptables_add_rule("nat", "DNS_FILTER", rule_tcp)
    else:
        iptables_delete_rule("nat", "DNS_FILTER", rule_udp)
        iptables_delete_rule("nat", "DNS_FILTER", rule_tcp)

# -------------------------
# Group winner logic (canonical)
# -------------------------
def latest_active_group_per_device():
    """
    Newest activated active group wins per device.
    Returns {mac: {group_id, internet_blocked, dns_filtered, activated_at}}
    """
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        SELECT gm.device_mac AS mac,
               g.id AS group_id,
               g.internet_blocked,
               g.dns_filtered,
               ag.activated_at
        FROM group_members gm
        JOIN active_groups ag ON ag.group_id = gm.group_id
        JOIN groups g ON g.id = ag.group_id
        WHERE ag.active=1
    """)
    rows = cur.fetchall()
    conn.close()

    best = {}
    for r in rows:
        mac = r["mac"].lower()
        if mac not in best or parse_iso(r["activated_at"]) > parse_iso(best[mac]["activated_at"]):
            best[mac] = dict(r)
    return best

# -------------------------
# Scheduler policy enforcement
# -------------------------
def enforce_schedules():
    now_hhmm = now_local_hhmm()
    day = today_key()

    winner = latest_active_group_per_device()

    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT mac, approved, internet_blocked, dns_filtered FROM devices")
    device_state = {
        r["mac"].lower(): {
            "approved": int(r["approved"]),
            "manual_block": int(r["internet_blocked"]),
            "manual_dns": int(r["dns_filtered"]),
        }
        for r in cur.fetchall()
    }

    cur.execute("""
        SELECT * FROM schedules
        WHERE enabled=1
        ORDER BY id DESC
    """)
    sched_by_group = {}
    for s in cur.fetchall():
        gid = int(s["group_id"])
        sched_by_group.setdefault(gid, []).append(dict(s))

    conn.close()

    for mac, grp in winner.items():
        mac = mac.lower()
        st = device_state.get(mac, {"approved": 0, "manual_block": 0, "manual_dns": 0})

        if st["approved"] == 0:
            enforce_pending_block(mac, should_block=True)
            continue
        else:
            enforce_pending_block(mac, should_block=False)

        if st["manual_block"] == 1:
            set_internet_block(mac, True)
            set_dns_filter(mac, st["manual_dns"] == 1)
            continue

        base_block = bool(grp["internet_blocked"])
        base_dns = bool(grp["dns_filtered"])
        desired_block = base_block
        desired_dns = base_dns

        gid = int(grp["group_id"])
        for s in sched_by_group.get(gid, []):
            days = [d.strip() for d in (s["days"] or "").split(",") if d.strip()]
            if day not in days:
                continue

            active = time_in_window(s["start_time"], s["end_time"], now_hhmm)
            if not active:
                continue

            if s["action"] == "allow":
                desired_block = False
                desired_dns = False
            else:
                desired_block = True
                desired_dns = base_dns
            break

        set_internet_block(mac, desired_block)
        set_dns_filter(mac, desired_dns)

# -------------------------
# Leases parsing
# -------------------------
def read_leases():
    leases = []
    if not os.path.exists(LEASES_PATH):
        return leases

    with open(LEASES_PATH, "r", encoding="utf-8", errors="ignore") as f:
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
    leases = read_leases()
    now = datetime.utcnow().isoformat()

    conn = db()
    cur = conn.cursor()

    for l in leases:
        cur.execute("""
        INSERT INTO devices(mac, name, last_ip, last_seen)
        VALUES(?,?,?,?)
        ON CONFLICT(mac) DO UPDATE SET
            last_ip=excluded.last_ip,
            last_seen=excluded.last_seen
        """, (l["mac"], l["hostname"], l["ip"], now))

    conn.commit()
    conn.close()

# -------------------------
# Domains file management
# -------------------------
def sanitize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if not re.fullmatch(r"[a-z0-9.-]+", domain):
        raise ValueError("Invalid domain format")
    if ".." in domain or domain.startswith(".") or domain.endswith("."):
        raise ValueError("Invalid domain format")
    return domain

def rebuild_domains_file_from_db():
    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT domain FROM blocked_domains WHERE enabled=1")
    domains = set([r["domain"] for r in cur.fetchall()])

    cur.execute("""
        SELECT gd.domain
        FROM group_domains gd
        JOIN active_groups ag ON ag.group_id = gd.group_id
        WHERE ag.active=1 AND gd.enabled=1
    """)
    for r in cur.fetchall():
        domains.add(r["domain"])

    conn.close()

    domains = sorted(domains)
    lines = ["# Auto-generated by Smart Firewall backend"]
    for d in domains:
        lines.append(f"address=/{d}/0.0.0.0")
        lines.append(f"address=/www.{d}/0.0.0.0")
    content = "\n".join(lines) + "\n"

    p = subprocess.run(["sudo", "tee", DOMAINS_FILE], input=content, text=True, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or "Failed to write domains file")

    rc, out, err = sh(["sudo", "systemctl", "restart", FILTERED_DNS_SERVICE])
    if rc != 0:
        raise RuntimeError(err or out or "Failed to restart dnsmasq-filtered")

# -------------------------
# API
# -------------------------
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"ok": True})

@app.route("/api/debug/tables", methods=["GET"])
def debug_tables():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [r["name"] for r in cur.fetchall()]
    conn.close()
    return jsonify({"ok": True, "tables": tables})

@app.route("/api/devices/sync", methods=["POST"])
def devices_sync():
    upsert_devices_from_leases()

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT mac, approved FROM devices")
    devices = cur.fetchall()
    conn.close()

    for d in devices:
        mac = d["mac"]
        approved = int(d["approved"])
        enforce_pending_block(mac, should_block=(approved == 0))

    sh(["sudo", "netfilter-persistent", "save"])
    enforce_schedules()
    return jsonify({"ok": True, "synced": len(devices)})

@app.route("/api/devices", methods=["GET"])
def devices_list():
    upsert_devices_from_leases()
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices ORDER BY last_seen DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route("/api/devices/effective", methods=["GET"])
def devices_effective():
    # Winner per device (newest active group)
    winners = latest_active_group_per_device()

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices ORDER BY last_seen DESC")
    devices = [dict(r) for r in cur.fetchall()]

    # Preload group names for winners
    group_names = {}
    if winners:
        ids = sorted({int(v["group_id"]) for v in winners.values()})
        qmarks = ",".join(["?"] * len(ids))
        cur.execute(f"SELECT id, name FROM groups WHERE id IN ({qmarks})", ids)
        group_names = {int(r["id"]): r["name"] for r in cur.fetchall()}

    conn.close()

    out = []
    for d in devices:
        mac = d["mac"].lower()
        w = winners.get(mac)

        # winner info
        if w:
            gid = int(w["group_id"])
            d["winner_group_id"] = gid
            d["winner_group_name"] = group_names.get(gid, f"Group {gid}")
            d["winner_activated_at"] = w["activated_at"]
            d["winner_internet_blocked"] = int(w["internet_blocked"])
            d["winner_dns_filtered"] = int(w["dns_filtered"])
        else:
            d["winner_group_id"] = None
            d["winner_group_name"] = None
            d["winner_activated_at"] = None
            d["winner_internet_blocked"] = None
            d["winner_dns_filtered"] = None

        # FINAL effective policy (matches enforce_schedules precedence)
        approved = int(d.get("approved", 0))
        manual_block = int(d.get("internet_blocked", 0))
        manual_dns = int(d.get("dns_filtered", 0))

        if approved == 0:
            d["effective_internet_blocked"] = 1
            d["effective_dns_filtered"] = manual_dns  # doesn't really matter if internet blocked
            d["effective_reason"] = "pending"
        elif manual_block == 1:
            d["effective_internet_blocked"] = 1
            d["effective_dns_filtered"] = manual_dns
            d["effective_reason"] = "manual_block"
        else:
            # base from winner group (schedules can change it in real-time;
            # this endpoint reflects base winner, not current schedule window)
            if w:
                d["effective_internet_blocked"] = int(w["internet_blocked"])
                d["effective_dns_filtered"] = int(w["dns_filtered"])
                d["effective_reason"] = "winner_group"
            else:
                d["effective_internet_blocked"] = 0
                d["effective_dns_filtered"] = 0
                d["effective_reason"] = "no_active_group"

        out.append(d)

    return jsonify({"ok": True, "devices": out})

@app.route("/api/devices/<mac>/groups", methods=["GET"])
def device_groups(mac):
    mac = mac.lower().strip()
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        SELECT g.id, g.name,
               g.internet_blocked, g.dns_filtered,
               COALESCE(ag.active, 0) AS active,
               ag.activated_at
        FROM group_members gm
        JOIN groups g ON g.id = gm.group_id
        LEFT JOIN active_groups ag ON ag.group_id = g.id
        WHERE gm.device_mac=?
        ORDER BY COALESCE(ag.activated_at, '') DESC, g.name ASC
    """, (mac,))
    groups = [dict(r) for r in cur.fetchall()]
    conn.close()

    winner = None
    for g in groups:
        if int(g.get("active", 0)) == 1 and g.get("activated_at"):
            winner = g
            break

    return jsonify({"ok": True, "mac": mac, "groups": groups, "winner": winner})

@app.route("/api/devices/<mac>/approve", methods=["POST"])
def device_approve(mac):
    mac = mac.lower().strip()
    approved = 1 if (request.is_json and request.json.get("approved", True)) else 0

    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE devices SET approved=? WHERE mac=?", (approved, mac))
    conn.commit()
    conn.close()

    enforce_pending_block(mac, should_block=(approved == 0))
    sh(["sudo", "netfilter-persistent", "save"])
    enforce_schedules()
    return jsonify({"ok": True, "mac": mac, "approved": approved})

@app.route("/api/devices/<mac>/block_internet", methods=["POST"])
def device_block_internet(mac):
    blocked = int(bool(request.json.get("blocked", True))) if request.is_json else 1
    set_internet_block(mac, blocked == 1)

    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE devices SET internet_blocked=? WHERE mac=?", (blocked, mac.lower()))
    conn.commit()
    conn.close()

    sh(["sudo", "netfilter-persistent", "save"])
    enforce_schedules()
    return jsonify({"ok": True, "mac": mac, "internet_blocked": blocked})

@app.route("/api/devices/<mac>/dns_filter", methods=["POST"])
def device_dns_filter(mac):
    enabled = int(bool(request.json.get("enabled", True))) if request.is_json else 1
    set_dns_filter(mac, enabled == 1)

    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE devices SET dns_filtered=? WHERE mac=?", (enabled, mac.lower()))
    conn.commit()
    conn.close()

    sh(["sudo", "netfilter-persistent", "save"])
    enforce_schedules()
    return jsonify({"ok": True, "mac": mac, "dns_filtered": enabled})

@app.route("/api/domains", methods=["GET"])
def domains_list():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM blocked_domains ORDER BY domain ASC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route("/api/domains", methods=["POST"])
def domains_add():
    if not request.is_json or "domain" not in request.json:
        return jsonify({"ok": False, "error": "domain required"}), 400

    try:
        domain = sanitize_domain(request.json["domain"])
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    conn = db()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO blocked_domains(domain, enabled, created_at)
    VALUES(?,?,?)
    ON CONFLICT(domain) DO UPDATE SET enabled=1
    """, (domain, 1, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

    rebuild_domains_file_from_db()
    return jsonify({"ok": True, "domain": domain})

@app.route("/api/domains/<int:domain_id>/disable", methods=["POST"])
def domains_disable(domain_id):
    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE blocked_domains SET enabled=0 WHERE id=?", (domain_id,))
    conn.commit()
    conn.close()

    rebuild_domains_file_from_db()
    return jsonify({"ok": True, "id": domain_id, "enabled": 0})

@app.route("/api/groups", methods=["GET"])
def groups_list():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM groups ORDER BY name ASC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route("/api/groups", methods=["POST"])
def groups_create():
    try:
        if not request.is_json:
            return jsonify({"ok": False, "error": "json required"}), 400

        name = (request.json.get("name") or "").strip()
        if not name:
            return jsonify({"ok": False, "error": "name required"}), 400

        internet_blocked = int(bool(request.json.get("internet_blocked", False)))
        dns_filtered = int(bool(request.json.get("dns_filtered", False)))

        conn = db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO groups(name, internet_blocked, dns_filtered) VALUES(?,?,?)",
            (name, internet_blocked, dns_filtered),
        )
        conn.commit()
        gid = cur.lastrowid
        conn.close()

        return jsonify({"ok": True, "id": gid, "name": name})

    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "error": "group name already exists"}), 409
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/groups/<int:group_id>/members", methods=["POST"])
def group_add_member(group_id):
    mac = (request.json.get("mac") if request.is_json else "") or ""
    mac = mac.lower().strip()
    if not mac:
        return jsonify({"ok": False, "error": "mac required"}), 400

    conn = db()
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO group_members(group_id, device_mac) VALUES(?,?)", (group_id, mac))
    conn.commit()

    cur.execute("SELECT COUNT(*) AS c FROM group_members WHERE group_id=?", (group_id,))
    count = int(cur.fetchone()["c"])
    conn.close()

    enforce_schedules()
    return jsonify({"ok": True, "group_id": group_id, "mac": mac, "members": count})

@app.route("/api/groups/<int:group_id>/domains", methods=["POST"])
def group_add_domain(group_id):
    if not request.is_json or "domain" not in request.json:
        return jsonify({"ok": False, "error": "domain required"}), 400

    try:
        domain = sanitize_domain(request.json["domain"])
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    conn = db()
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO group_domains(group_id, domain, enabled) VALUES(?,?,1)", (group_id, domain))
    conn.commit()
    conn.close()

    rebuild_domains_file_from_db()
    return jsonify({"ok": True, "domain": domain})

@app.route("/api/schedules", methods=["POST"])
def schedule_create():
    if not request.is_json:
        return jsonify({"ok": False, "error": "json required"}), 400

    group_id = int(request.json.get("group_id"))
    start_time = request.json.get("start_time")
    end_time = request.json.get("end_time")
    days = request.json.get("days", "mon,tue,wed,thu,fri,sat,sun")
    action = request.json.get("action", "allow")

    if action not in ("allow", "block"):
        return jsonify({"ok": False, "error": "action must be allow or block"}), 400

    conn = db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO schedules(group_id, start_time, end_time, days, action, enabled)
        VALUES(?,?,?,?,?,1)
    """, (group_id, start_time, end_time, days, action))
    conn.commit()
    conn.close()

    enforce_schedules()
    return jsonify({"ok": True})

@app.route("/api/schedules", methods=["GET"])
def schedule_list():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM schedules ORDER BY id DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route("/api/groups/<int:group_id>/apply", methods=["POST"])
def group_apply(group_id):
    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM groups WHERE id=?", (group_id,))
    grp = cur.fetchone()
    if not grp:
        conn.close()
        return jsonify({"ok": False, "error": "group not found", "group_id": group_id}), 404

    cur.execute("""
        INSERT INTO active_groups(group_id, active, activated_at)
        VALUES(?,1,?)
        ON CONFLICT(group_id) DO UPDATE SET active=1, activated_at=excluded.activated_at
    """, (group_id, datetime.utcnow().isoformat()))

    cur.execute("SELECT device_mac FROM group_members WHERE group_id=?", (group_id,))
    macs = [r["device_mac"] for r in cur.fetchall()]

    conn.commit()
    conn.close()

    enforce_schedules()
    rebuild_domains_file_from_db()
    sh(["sudo", "netfilter-persistent", "save"])

    return jsonify({"ok": True, "group_id": group_id, "active": True, "applied_to": len(macs)})

@app.route("/api/groups/<int:group_id>/deactivate", methods=["POST"])
def group_deactivate(group_id):
    conn = db()
    cur = conn.cursor()

    cur.execute("UPDATE active_groups SET active=0 WHERE group_id=?", (group_id,))
    changed = cur.rowcount
    conn.commit()
    conn.close()

    enforce_schedules()
    rebuild_domains_file_from_db()
    sh(["sudo", "netfilter-persistent", "save"])

    return jsonify({"ok": True, "group_id": group_id, "active": False, "updated": changed})

@app.route("/api/groups/active", methods=["GET"])
def groups_active():
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        SELECT g.*, ag.active, ag.activated_at
        FROM groups g
        JOIN active_groups ag ON ag.group_id = g.id
        WHERE ag.active=1
        ORDER BY ag.activated_at DESC
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)

if __name__ == "__main__":
    init_db()
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(enforce_schedules, "interval", minutes=1)
    scheduler.start()
    app.run(host="0.0.0.0", port=APP_PORT, debug=False, use_reloader=False)
