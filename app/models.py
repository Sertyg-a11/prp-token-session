from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    notes = db.relationship("Note", backref="author", lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User {self.username}>"


class Note(db.Model):
    """Public note — deliberately stored without sanitisation for the S3 XSS sink."""

    __tablename__ = "notes"

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<Note {self.id} by user {self.user_id}>"


class RevokedToken(db.Model):
    """Deny-list entry for a JWT jti claim. Only populated in SECURE profile (S4 fix)."""

    __tablename__ = "revoked_tokens"

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True, nullable=False, index=True)
    revoked_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<RevokedToken {self.jti}>"
