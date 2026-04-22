from app.db import get_db


DEFAULT_SETTINGS = {
    "firewall_enabled": True,
    "auto_block_unknown_devices": False,
    "device_discovery_enabled": True,
    "realtime_monitoring_enabled": True,
    "intrusion_detection_enabled": True,
    "email_notifications_enabled": True,
}


def get_setting(key: str, default: str = "") -> str:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT value FROM settings WHERE key=? LIMIT 1", (key,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return default
    return str(row["value"])


def is_setting_enabled(key: str, default: bool = False) -> bool:
    raw = get_setting(key, "true" if default else "false").strip().lower()
    return raw in ("1", "true", "yes", "on")


def get_all_runtime_flags():
    return {
        key: is_setting_enabled(key, default)
        for key, default in DEFAULT_SETTINGS.items()
    }
