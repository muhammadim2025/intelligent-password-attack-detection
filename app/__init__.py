"""Flask application package and application factory."""

from __future__ import annotations

import os

from flask import Flask, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config import (
    auth_event_retention_days,
    auth_event_retention_enabled,
    database_path,
    manual_detection_lab_enabled,
    soc_demo_database_path,
    soc_demo_mode_enabled,
)
from app.models.db import connect, get_user_by_id, initialize
from app.auth.user import User

csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=[],
)
login_manager = LoginManager()


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _debug_enabled() -> bool:
    return _env_flag("FLASK_DEBUG", False)


def _session_cookie_secure(debug_enabled: bool) -> bool:
    configured = os.getenv("SESSION_COOKIE_SECURE")
    if configured is None:
        return not debug_enabled
    return configured.lower() in {"1", "true", "yes", "on"}


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    debug_enabled = _debug_enabled()
    session_cookie_secure = _session_cookie_secure(debug_enabled)
    manual_detection_lab = manual_detection_lab_enabled() if debug_enabled else False
    app.config.update(
        DEBUG=False,
        TESTING=False,
        PROPAGATE_EXCEPTIONS=False,
        SECRET_KEY=os.getenv("SECRET_KEY"),
        DATABASE_PATH=database_path(),
        SOC_DEMO_MODE=soc_demo_mode_enabled(),
        MANUAL_DETECTION_LAB=manual_detection_lab,
        PRIVACY_HMAC_KEY=os.getenv("PRIVACY_HMAC_KEY"),
        AUTH_EVENT_RETENTION_DAYS=auth_event_retention_days(),
        AUTH_EVENT_RETENTION_ENABLED=auth_event_retention_enabled(),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=session_cookie_secure,
        WTF_CSRF_TIME_LIMIT=3600,
        RATELIMIT_ENABLED=True,
        PREFERRED_URL_SCHEME="https" if session_cookie_secure else "http",
    )
    if test_config:
        app.config.update(test_config)
        if app.config.get("TESTING"):
            app.config["MANUAL_DETECTION_LAB"] = bool(
                app.config.get("MANUAL_DETECTION_LAB", False)
            )
    if app.config["SOC_DEMO_MODE"] and not app.config.get("TESTING"):
        app.config["DATABASE_PATH"] = soc_demo_database_path()

    secret_key = app.config.get("SECRET_KEY")
    if not secret_key:
        if app.config.get("TESTING"):
            app.config["SECRET_KEY"] = "test-only-secret-key"
        else:
            raise RuntimeError("SECRET_KEY must be set in the environment.")

    app.config["SESSION_COOKIE_SECURE"] = bool(
        app.config.get("SESSION_COOKIE_SECURE", False)
    )
    app.config["PREFERRED_URL_SCHEME"] = (
        "https" if app.config["SESSION_COOKIE_SECURE"] else "http"
    )

    trust_proxy_headers = _env_flag("TRUST_PROXY_HEADERS", _env_flag("RENDER", False))
    if trust_proxy_headers and not app.config.get("TESTING"):
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=1,
            x_proto=1,
            x_host=1,
            x_port=1,
            x_prefix=1,
        )

    csrf.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"
    login_manager.session_protection = "strong"

    @app.get("/health")
    @limiter.exempt
    def health_check():
        return jsonify({"status": "ok"}), 200

    @app.context_processor
    def soc_context():
        return {
            "soc_demo_mode": bool(app.config["SOC_DEMO_MODE"]),
        }

    @login_manager.user_loader
    def load_user(user_id: str):
        connection = connect(app.config["DATABASE_PATH"])
        try:
            row = get_user_by_id(connection, int(user_id))
        finally:
            connection.close()
        if row is None:
            return None
        return User(
            id=int(row["id"]),
            username=row["username"],
            password_hash=row["password_hash"],
            is_admin=bool(row["is_admin"]),
        )

    @app.before_request
    def initialize_database() -> None:
        connection = connect(app.config["DATABASE_PATH"])
        try:
            initialize(connection)
            if app.config["AUTH_EVENT_RETENTION_ENABLED"]:
                from app.services.login_events import purge_expired_authentication_events
                purge_expired_authentication_events(
                    connection,
                    retention_days=int(app.config["AUTH_EVENT_RETENTION_DAYS"]),
                )
        finally:
            connection.close()

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )
        if not app.config.get("TESTING"):
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response

    @app.errorhandler(429)
    def rate_limited(_error):
        from flask import render_template, request

        if request.path == "/login" and request.method == "POST":
            from app.detection.predictor import (
                ModelUnavailableError,
                feature_explanation,
                predict,
            )
            from app.services.alerts import create_alert
            from app.services.login_events import record_authentication_event

            connection = connect(app.config["DATABASE_PATH"])
            try:
                username = request.form.get("username", "").strip()
                from app.privacy import pseudonymize_source
                source_identifier = pseudonymize_source(
                    request.remote_addr or "unknown",
                    str(app.config.get("PRIVACY_HMAC_KEY") or app.config["SECRET_KEY"]),
                )
                event_id, research_features = record_authentication_event(
                    connection,
                    username=username,
                    source_ip=source_identifier,
                    success=0,
                )
                try:
                    prediction, probability = predict(research_features)
                    connection.execute(
                        "UPDATE login_events SET model_prediction = ?, model_probability = ? WHERE id = ?",
                        (prediction, probability, event_id),
                    )
                    if prediction == 1:
                        create_alert(
                            connection,
                            event_id=event_id,
                            severity="high" if probability >= 0.8 else "medium",
                            explanation=feature_explanation(research_features),
                        )
                    connection.commit()
                except ModelUnavailableError:
                    pass
            finally:
                connection.close()
        return render_template("error.html", message="Too many attempts. Try again later."), 429

    @app.errorhandler(403)
    def forbidden(_error):
        from flask import render_template
        return render_template("error.html", message="Access denied."), 403

    from app.routes.pages import register_routes
    register_routes(app)

    return app

