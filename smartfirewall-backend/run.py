"""
run.py
"""

from apscheduler.schedulers.background import BackgroundScheduler

from app import create_app
from app.db import init_db
from app.services.policy import enforce_policies_periodic
from app.services.usage import collect_usage_snapshot
from app.services.runtime_settings import is_setting_enabled
from app.services.ai_user_reports import generate_and_store_all_managed_user_reports


def main():
    init_db()
    app = create_app()

    def policy_job():
        with app.app_context():
            enforce_policies_periodic()

    def usage_job():
        with app.app_context():
            if is_setting_enabled("realtime_monitoring_enabled", True):
                collect_usage_snapshot()

    def ai_reports_job():
        with app.app_context():
            try:
                r7 = generate_and_store_all_managed_user_reports(7)
                r30 = generate_and_store_all_managed_user_reports(30)
                print(f"[ai_reports_job] 7d={r7} 30d={r30}")
            except Exception as e:
                print(f"[ai_reports_job] ERROR: {e}")

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(policy_job, "interval", minutes=1)
    scheduler.add_job(usage_job, "interval", minutes=1)
    scheduler.add_job(ai_reports_job, "interval", hours=12)
    scheduler.start()

    app.run(host="0.0.0.0", port=app.config["APP_PORT"], debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
