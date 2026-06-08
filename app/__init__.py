"""
Flask application factory.

Usage:
    PROFILE=INSECURE flask run          # default — vulnerable variant
    PROFILE=SECURE   flask run          # hardened variant (Sprint 3)

Or via run.py:
    python run.py                       # INSECURE
    python run.py --secure              # SECURE
"""

import os

from flask import Flask
from flask_session import Session

from .config import InsecureConfig, SecureConfig
from .models import db


def create_app(profile: str | None = None) -> Flask:
    app = Flask(__name__)

    # Resolve profile: argument > env var > default INSECURE
    resolved = (profile or os.environ.get("PROFILE", "INSECURE")).upper()
    if resolved == "SECURE":
        app.config.from_object(SecureConfig)
    else:
        app.config.from_object(InsecureConfig)

    db.init_app(app)
    Session(app)   # server-side filesystem sessions — cookie is now an opaque ID

    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # Make the active profile available to EVERY template (login, register, etc.)
    # so the banner always reflects the real profile instead of defaulting to INSECURE.
    @app.context_processor
    def inject_profile():
        return {"profile": app.config.get("PROFILE", "INSECURE")}

    with app.app_context():
        db.create_all()

    # ── Security headers (SECURE profile only) ───────────────────────────────
    # Applied as an after_request hook so they are added to every response.
    # In INSECURE mode these headers are deliberately absent to keep the attack
    # surface realistic and comparable with the vulnerable variant.
    @app.after_request
    def security_headers(response):
        if app.config.get("PROFILE") == "SECURE":
            # CSP — the key S3 defence:
            #   script-src 'self'  → only same-origin .js files run; injected inline
            #                        <script> payloads are blocked, and cross-origin
            #                        fetch() exfiltration is blocked by default-src.
            #   style-src allows 'unsafe-inline' so the app's own CSS still renders;
            #     styles cannot read or exfiltrate tokens, so this is a safe relaxation.
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "object-src 'none'; base-uri 'self'"
            )
            # Prevent MIME-type sniffing attacks.
            response.headers["X-Content-Type-Options"] = "nosniff"
            # Deny embedding in iframes (clickjacking protection).
            response.headers["X-Frame-Options"] = "DENY"
            # Instruct browsers to use HTTPS for the next year (requires HTTPS transport).
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response

    return app
