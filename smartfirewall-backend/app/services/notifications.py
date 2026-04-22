"""
app/services/notifications.py
"""

import smtplib
from email.message import EmailMessage
from flask import current_app
from app.services.runtime_settings import is_setting_enabled


def email_is_configured() -> bool:
    return all([
        current_app.config.get("SMTP_HOST"),
        current_app.config.get("SMTP_PORT"),
        current_app.config.get("SMTP_FROM"),
        current_app.config.get("ALERT_EMAIL_TO"),
    ])


def send_email(subject: str, body: str) -> bool:
    if not is_setting_enabled("email_notifications_enabled", True):
        return False

    if not email_is_configured():
        return False

    smtp_host = current_app.config["SMTP_HOST"]
    smtp_port = current_app.config["SMTP_PORT"]
    smtp_user = current_app.config.get("SMTP_USER", "")
    smtp_pass = current_app.config.get("SMTP_PASS", "")
    smtp_from = current_app.config["SMTP_FROM"]
    alert_to = current_app.config["ALERT_EMAIL_TO"]
    use_tls = current_app.config.get("SMTP_USE_TLS", True)

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = alert_to
    msg.set_content(body)

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
            if use_tls:
                server.starttls()

            if smtp_user:
                server.login(smtp_user, smtp_pass)

            server.send_message(msg)

        return True
    except Exception:
        return False


def send_alert_email(title: str, message: str, level: str = "info") -> bool:
    subject = f"[Smart Firewall] {level.upper()}: {title}"
    body = f"{title}\n\nLevel: {level}\n\n{message}"
    return send_email(subject, body)
