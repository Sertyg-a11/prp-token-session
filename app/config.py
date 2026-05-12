import os


class BaseConfig:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-do-not-use-in-prod")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///prp.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_SECRET = os.environ.get("JWT_SECRET", "jwt-secret-dev-key-min32chars!!!")
    JWT_ALGORITHM = "HS256"
    # Long expiry deliberately chosen so S4 (token replay after logout) is easy to demo
    JWT_EXPIRY_SECONDS = 3600

    # flask-session: store sessions on the filesystem so the cookie is an opaque ID.
    # This is what makes S2 (session fixation) actually demonstrable — the cookie
    # value no longer changes when session data changes, only the server-side file does.
    SESSION_TYPE = "filesystem"
    SESSION_FILE_DIR = os.path.join(os.path.dirname(__file__), "..", "flask_sessions")
    SESSION_FILE_THRESHOLD = 500
    SESSION_USE_SIGNER = False   # INSECURE: unsigned session IDs make fixation trivial
    SESSION_PERMANENT = False


class InsecureConfig(BaseConfig):
    DEBUG = True
    PROFILE = "INSECURE"

    # S1 — Missing cookie security flags
    SESSION_COOKIE_SECURE = False       # cookie sent over plain HTTP
    SESSION_COOKIE_HTTPONLY = False     # JavaScript can read via document.cookie
    SESSION_COOKIE_SAMESITE = None      # no CSRF protection

    # S2 — Session fixation: do NOT regenerate session ID on login
    REGENERATE_SESSION = False

    # S3 — JWT stored in localStorage (handled in dashboard template / JS)
    JWT_STORAGE = "localStorage"

    # S4 — No server-side token revocation on logout
    JWT_REVOCATION = False


class SecureConfig(BaseConfig):
    DEBUG = False
    PROFILE = "SECURE"

    # Hardened cookie attributes
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Sign the session ID so an attacker cannot guess or plant one
    SESSION_USE_SIGNER = True

    # Regenerate session ID on login to prevent fixation
    REGENERATE_SESSION = True

    # JWT held in memory only; refresh via HttpOnly cookie
    JWT_STORAGE = "memory"

    # Server-side revocation list checked on every protected request
    JWT_REVOCATION = True

    # Short-lived tokens limit the window even if revocation fails
    JWT_EXPIRY_SECONDS = 300
