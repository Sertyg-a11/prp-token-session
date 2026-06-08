#!/usr/bin/env python3
"""
Entry point for the PRP Token/Session PoC application.

Usage
-----
    python run.py               # INSECURE profile on http://localhost:5000
    python run.py --secure      # SECURE profile on http://localhost:5000
    python run.py --port 8080   # custom port
"""

import argparse
import os

from app import create_app


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PRP Token/Session Handling PoC — Sprint 2"
    )
    parser.add_argument(
        "--secure",
        action="store_true",
        help="Run in SECURE profile (hardened controls — Sprint 3 variant)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port to listen on (default: 5000)",
    )
    args = parser.parse_args()

    # Resolve profile: --secure flag wins, otherwise honour the PROFILE env var
    # (set by docker-compose), otherwise default to INSECURE.
    if args.secure:
        profile = "SECURE"
    else:
        profile = os.environ.get("PROFILE", "INSECURE").upper()
    app = create_app(profile=profile)

    print(f"\n  PRP PoC starting in [{profile}] profile on http://localhost:{args.port}\n")

    app.run(
        host="0.0.0.0",
        port=args.port,
        debug=(profile == "INSECURE"),  # debug off in SECURE to avoid info leakage
    )


if __name__ == "__main__":
    main()
