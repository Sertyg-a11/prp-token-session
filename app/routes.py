"""
All HTTP routes for the PoC application.

Cookie-session path: /register  /login  /dashboard  /notes/add  /logout  /set
JWT API path:        /api/login  /api/me  /api/notes  /api/logout

The /set endpoint is the session-fixation helper used by the attacker in S2.
The notes feature contains a deliberate |safe render (XSS sink) for S3.
"""

import functools

from flask import (
    Blueprint,
    after_this_request,
    current_app,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from .auth_jwt import issue_token, revoke_token, verify_token
from .auth_session import login_user_session, logout_user_session
from .models import Note, User, db

main = Blueprint("main", __name__)


# ─── decorators ─────────────────────────────────────────────────────────────


def session_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("main.login_page"))
        return f(*args, **kwargs)

    return decorated


def jwt_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
        if not token:
            # SECURE: token is delivered as an HttpOnly cookie rather than in
            # the response body, so JavaScript never sees it.  The browser
            # attaches it automatically on same-origin requests; read it here
            # so that @jwt_required routes work end-to-end in SECURE mode.
            token = request.cookies.get("access_token")
        if not token:
            return jsonify({"error": "Authorization header missing or malformed"}), 401
        payload, err = verify_token(token)
        if err:
            return jsonify({"error": err}), 401
        request.jwt_payload = payload
        return f(*args, **kwargs)

    return decorated


# ─── page routes — cookie-session path ──────────────────────────────────────


@main.route("/")
def index():
    return redirect(url_for("main.login_page"))


@main.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not password:
            return render_template("register.html", error="All fields are required.")
        if User.query.filter_by(username=username).first():
            return render_template("register.html", error="Username already taken.")
        user = User(
            username=username,
            password_hash=generate_password_hash(password),
        )
        db.session.add(user)
        db.session.commit()
        return redirect(url_for("main.login_page"))
    return render_template("register.html")


@main.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        user = login_user_session(username, password)
        if not user:
            return render_template("login.html", error="Invalid username or password.")
        return redirect(url_for("main.dashboard"))
    return render_template("login.html")


@main.route("/dashboard")
@session_required
def dashboard():
    user = User.query.get(session["user_id"])
    # All notes from all users are shown — demonstrates the XSS blast radius (S3)
    notes = Note.query.order_by(Note.created_at.desc()).all()
    profile = current_app.config.get("PROFILE", "INSECURE")
    jwt_storage = current_app.config.get("JWT_STORAGE", "localStorage")
    return render_template(
        "dashboard.html",
        user=user,
        notes=notes,
        profile=profile,
        jwt_storage=jwt_storage,
    )


@main.route("/notes/add", methods=["POST"])
@session_required
def add_note():
    content = request.form.get("content", "")
    # INSECURE (S3): content is stored raw — no sanitisation at write time.
    # The template renders it with |safe, executing any injected <script> tags.
    note = Note(content=content, user_id=session["user_id"])
    db.session.add(note)
    db.session.commit()
    return redirect(url_for("main.dashboard"))


@main.route("/logout")
@session_required
def logout():
    logout_user_session()
    return redirect(url_for("main.login_page"))


# ─── session-fixation helper (S2) ───────────────────────────────────────────


@main.route("/set")
def set_session():
    """
    S2 Session fixation helper — two-step operation.

    Step A — Attacker gets a real session ID (no ?sid= parameter):
        GET /set
        The server writes a marker into the session, creating a real server-side
        session file for the attacker.  The response body shows the session ID
        and the Set-Cookie header carries it.  The attacker copies this value.

    Step B — Attacker plants the ID in the victim's browser (?sid= parameter):
        GET /set?sid=<ATTACKER_SESSION_ID>
        The server overwrites the victim's session cookie with the attacker's ID
        and redirects to /login.  Because REGENERATE_SESSION=False, the victim's
        login just writes user_id into the existing session file for that ID.
        The attacker then uses the same cookie and gets the authenticated session.

    Only active in INSECURE profile.
    """
    if current_app.config.get("PROFILE") != "INSECURE":
        return "This debug endpoint is disabled in SECURE mode.", 403

    sid = request.args.get("sid", "").strip()

    if not sid:
        # Step A: create a real server-side session so the attacker gets a valid ID
        session["fixation_marker"] = "attacker_pre_auth"
        session.modified = True
        # Read back the session ID that flask-session assigned
        from flask import request as freq
        cookie_name = current_app.config.get("SESSION_COOKIE_NAME", "session")
        # We need to let the response write the cookie first; use after_this_request
        attacker_id_holder = {}

        @after_this_request
        def capture_sid(response):
            cookie = response.headers.get("Set-Cookie", "")
            if cookie_name in cookie:
                for part in cookie.split(";"):
                    part = part.strip()
                    if part.startswith(cookie_name + "="):
                        attacker_id_holder["sid"] = part[len(cookie_name) + 1:]
            return response

        return (
            "<h2>S2 — Attacker: your session ID will appear in the Set-Cookie header.</h2>"
            "<p>Copy the <code>session=</code> value from DevTools → Network → this request's response headers.</p>"
            "<p>Then send the victim: <code>http://localhost:5000/set?sid=YOUR_SESSION_ID</code></p>"
        ), 200

    # Step B: plant the attacker's real session ID into the victim's browser
    response = make_response(redirect(url_for("main.login_page")))
    cookie_name = current_app.config.get("SESSION_COOKIE_NAME", "session")
    response.set_cookie(
        cookie_name,
        sid,
        httponly=False,
        secure=False,
        samesite=None,
        path="/",
    )
    return response


# ─── API routes — JWT bearer path ───────────────────────────────────────────


@main.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True, silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401

    token = issue_token(user)
    storage = current_app.config.get("JWT_STORAGE", "localStorage")

    if storage == "httponly_cookie":
        # SECURE path: deliver token as HttpOnly cookie — JS never sees the value.
        # secure= matches SESSION_COOKIE_SECURE so the demo works over plain HTTP
        # while still showing the correct flag in DevTools.
        resp = jsonify({"message": "Logged in", "storage": storage})
        resp.set_cookie(
            "access_token",
            token,
            httponly=True,
            secure=current_app.config.get("SESSION_COOKIE_SECURE", False),
            samesite="Strict",
            max_age=current_app.config["JWT_EXPIRY_SECONDS"],
        )
        return resp

    # INSECURE path (S3): token returned in JSON body; client stores in localStorage
    return jsonify({"token": token, "storage": storage})


@main.route("/api/me")
@jwt_required
def api_me():
    payload = request.jwt_payload
    return jsonify(
        {
            "user_id": int(payload["sub"]),
            "username": payload["username"],
            "exp": payload["exp"],
            "jti": payload["jti"],
        }
    )


@main.route("/api/notes")
@jwt_required
def api_notes():
    notes = Note.query.filter_by(user_id=int(request.jwt_payload["sub"])).all()
    return jsonify(
        [{"id": n.id, "content": n.content, "created_at": str(n.created_at)} for n in notes]
    )


@main.route("/api/logout", methods=["POST"])
def api_logout():
    """
    INSECURE (S4): only instructs the client to discard the token.
    Server performs no state change — the token remains valid until exp.

    SECURE (Sprint 3 mitigation): revoke_token() adds the jti to RevokedToken.
    Every subsequent verify_token() call will reject it immediately.
    """
    # Read token from Authorization header (INSECURE / localStorage path)
    # or from the HttpOnly cookie (SECURE path) — whichever is present
    token = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
    if not token:
        token = request.cookies.get("access_token")

    if token:
        revoke_token(token)   # no-op in INSECURE, deny-list insert in SECURE

    resp = jsonify({"message": "Logged out"})
    resp.delete_cookie("access_token")
    return resp
