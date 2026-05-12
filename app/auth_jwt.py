"""
JWT bearer-token authentication.

INSECURE profile behaviour (S3, S4):
  - Token payload is returned to the client as JSON; the dashboard JS stores it in
    window.localStorage — readable by any same-origin script (S3).
  - /api/logout performs NO server-side operation; a captured token remains valid
    until its natural expiry (S4).

SECURE profile behaviour (mitigations applied in Sprint 3):
  - Token is set as an HttpOnly, Secure cookie instead of localStorage.
  - On /api/logout the jti claim is inserted into the RevokedToken deny-list and
    every protected route checks that list before trusting the token.
"""

import uuid
from datetime import datetime, timezone, timedelta

import jwt
from flask import current_app

from .models import db, RevokedToken


def issue_token(user) -> str:
    cfg = current_app.config
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "iat": now,
        "exp": now + timedelta(seconds=cfg["JWT_EXPIRY_SECONDS"]),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, cfg["JWT_SECRET"], algorithm=cfg["JWT_ALGORITHM"])


def verify_token(token: str) -> tuple[dict | None, str | None]:
    """Return (payload, None) on success or (None, error_message) on failure."""
    cfg = current_app.config
    try:
        payload = jwt.decode(
            token,
            cfg["JWT_SECRET"],
            algorithms=[cfg["JWT_ALGORITHM"]],
        )
    except jwt.ExpiredSignatureError:
        return None, "Token expired"
    except jwt.InvalidTokenError as exc:
        return None, f"Invalid token: {exc}"

    if cfg.get("JWT_REVOCATION"):
        # SECURE: check deny-list on every request
        if RevokedToken.query.filter_by(jti=payload["jti"]).first():
            return None, "Token has been revoked"
    # INSECURE (S4): no revocation check — token valid until exp regardless of logout

    return payload, None


def revoke_token(token: str) -> None:
    """Add the token's jti to the deny-list. No-op in INSECURE profile (S4 weakness)."""
    cfg = current_app.config
    if not cfg.get("JWT_REVOCATION"):
        # S4: server performs no revocation; client-side deletion is the only action
        return
    try:
        payload = jwt.decode(
            token,
            cfg["JWT_SECRET"],
            algorithms=[cfg["JWT_ALGORITHM"]],
            options={"verify_exp": False},  # allow revoking already-expired tokens
        )
        jti = payload.get("jti")
        if jti and not RevokedToken.query.filter_by(jti=jti).first():
            db.session.add(RevokedToken(jti=jti))
            db.session.commit()
    except jwt.InvalidTokenError:
        pass
