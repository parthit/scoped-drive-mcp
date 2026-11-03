"""Generate SESSION_SECRET and ENCRYPTION_KEY for the dashboard.

Usage:
    uv run python scripts/make_secrets.py

Paste both lines into Vercel -> Settings -> Environment Variables. Keep them secret.
Changing SESSION_SECRET signs everyone out. Changing ENCRYPTION_KEY makes the stored
refresh tokens unreadable, so you would have to sign in and connect the bot again.
"""

import secrets

from cryptography.fernet import Fernet


def main() -> None:
    print(f"SESSION_SECRET={secrets.token_urlsafe(48)}")
    print(f"ENCRYPTION_KEY={Fernet.generate_key().decode()}")


if __name__ == "__main__":
    main()
