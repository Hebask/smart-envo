"""
app/__init__.py

Flask app factory pattern:
- allows clean modular structure
- helps testing in the future
- keeps routes separated in Blueprints
"""

from flask import Flask


def create_app():
    app = Flask(__name__)

    from .config import load_config
    load_config(app)

    from .routes.health import bp as health_bp
    from .routes.debug import bp as debug_bp
    from .routes.devices import bp as devices_bp
    from .routes.groups import bp as groups_bp
    from .routes.domains import bp as domains_bp
    from .routes.schedules import bp as schedules_bp
    from .routes.audit import bp as audit_bp
    from .routes.alerts import bp as alerts_bp
    from .routes.dashboard import bp as dashboard_bp
    from .routes.usage import bp as usage_bp
    from .routes.analysis import bp as analysis_bp
    from .routes.users import bp as users_bp
    from .routes.services_cfg import bp as services_cfg_bp
    from .routes.settings_cfg import bp as settings_cfg_bp
    from app.routes.backup_restore import bp as backup_restore_bp
    from app.routes.activity_logs import bp as activity_logs_bp
    from app.routes.managed_users import bp as managed_users_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(debug_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(groups_bp)
    app.register_blueprint(domains_bp)
    app.register_blueprint(schedules_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(usage_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(services_cfg_bp)
    app.register_blueprint(settings_cfg_bp)
    app.register_blueprint(backup_restore_bp)
    app.register_blueprint(activity_logs_bp)
    app.register_blueprint(managed_users_bp)

    return app
