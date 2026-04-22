"""
wsgi.py

Gunicorn entrypoint for smart-envo backend.
Keeps the existing APScheduler jobs alive.
"""

from apscheduler.schedulers.background import BackgroundScheduler

from app import create_app
from app.db import init_db
from app.services.policy import enforce_policies_periodic
from app.services.usage import collect_usage_snapshot
from app.services.runtime_settings import is_setting_enabled

init_db()
app = create_app()


def policy_job():
    with app.app_context():
        enforce_policies_periodic()


def usage_job():
    with app.app_context():
        if is_setting_enabled("realtime_monitoring_enabled", True):
            collect_usage_snapshot()


scheduler = BackgroundScheduler(daemon=True)
scheduler.add_job(policy_job, "interval", minutes=1, id="policy_job", replace_existing=True)
scheduler.add_job(usage_job, "interval", minutes=1, id="usage_job", replace_existing=True)
scheduler.start()
