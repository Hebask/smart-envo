"""
app/config.py
"""

import os
from pathlib import Path


PROJECT_ROOT = Path("/home/smart-envo/smartfirewall-backend")
ENV_FILE = PROJECT_ROOT / ".env"


def _load_env_file():
    """
    Minimal .env loader so the backend does not depend on shell state.
    Existing exported env vars win over .env values.
    """
    if not ENV_FILE.exists():
        return

    for raw_line in ENV_FILE.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if not key:
            continue

        # strip matching quotes if present
        if len(value) >= 2 and (
            (value.startswith('"') and value.endswith('"')) or
            (value.startswith("'") and value.endswith("'"))
        ):
            value = value[1:-1]

        os.environ.setdefault(key, value)


def load_config(app):
    _load_env_file()

    app.config["AP_IFACE"] = os.getenv("AP_IFACE", "wlan0")
    app.config["WAN_IFACE"] = os.getenv("WAN_IFACE", "eth0")

    app.config["DB_PATH"] = os.getenv(
        "DB_PATH",
        "/home/smart-envo/smartfirewall-backend/iot.db"
    )

    app.config["LEASES_PATH"] = os.getenv("LEASES_PATH", "/var/lib/misc/dnsmasq.leases")
    app.config["DOMAINS_FILE"] = os.getenv("DOMAINS_FILE", "/etc/dnsmasq-filtered.d/domains.conf")
    app.config["FILTERED_DNS_SERVICE"] = os.getenv("FILTERED_DNS_SERVICE", "dnsmasq-filtered")
    app.config["APP_PORT"] = int(os.getenv("APP_PORT", "5000"))

    app.config["BACKUP_DIR"] = os.getenv(
        "BACKUP_DIR",
        "/home/smart-envo/smartfirewall-backups"
    )

    app.config["ADMIN_API_KEY"] = os.getenv("ADMIN_API_KEY", "")
    app.config["FRONTEND_SHARED_SECRET"] = os.getenv("FRONTEND_SHARED_SECRET", "")
    app.config["TRUST_FRONTEND_EMAIL_AUTH"] = os.getenv("TRUST_FRONTEND_EMAIL_AUTH", "true").lower() == "true"

    app.config["SMTP_HOST"] = os.getenv("SMTP_HOST", "")
    app.config["SMTP_PORT"] = int(os.getenv("SMTP_PORT", "587"))
    app.config["SMTP_USER"] = os.getenv("SMTP_USER", "")
    app.config["SMTP_PASS"] = os.getenv("SMTP_PASS", "")
    app.config["SMTP_FROM"] = os.getenv("SMTP_FROM", "")
    app.config["ALERT_EMAIL_TO"] = os.getenv("ALERT_EMAIL_TO", "")
    app.config["SMTP_USE_TLS"] = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
