"""
Cookie-based (server-side session) authentication.

With flask-session the cookie carries an opaque session ID that points to a
file on the server.  The cookie value no longer changes when session data
changes — this is what makes session fixation actually demonstrable.

INSECURE profile behaviour (S1, S2):
  - Cookie attributes Secure/HttpOnly/SameSite are absent (set via config).
  - Session ID is NOT regenerated after login — an attacker who planted the ID
    before login now has a valid authenticated session (S2).

SECURE profile behaviour (Sprint 3 mitigations):
  - Cookie attributes present via SecureConfig.
  - session.clear() is called on login, which causes flask-session to delete the
    old server-side file and generate a fresh session ID for the response cookie.
    The planted ID becomes an orphan pointing to nothing.
"""

from flask import session, current_app
from werkzeug.security import check_password_hash

from .models import User


def login_user_session(username: str, password: str) -> User | None:
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return None

    if current_app.config.get("REGENERATE_SESSION"):
        # SECURE: clear deletes the old server-side session file and forces
        # flask-session to issue a brand-new session ID in the response cookie.
        session.clear()
    # INSECURE (S2): session ID in the cookie stays the same — the server just
    # writes user_id into the existing server-side file for that ID.
    # An attacker who planted that ID before login now owns the session.

    session["user_id"] = user.id
    session["username"] = user.username
    return user


def logout_user_session() -> None:
    session.clear()
