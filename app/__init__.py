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

    with app.app_context():
        db.create_all()

    return app
