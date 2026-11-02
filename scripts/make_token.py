"""Generate a random API token and its API_TOKENS entry.

Usage:
    uv run python scripts/make_token.py grok-viewer viewer
    uv run python scripts/make_token.py --hash-only my-existing-token
"""

import argparse
import hashlib
import secrets
import sys

ROLES = ("viewer", "editor", "admin")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an API token and its SHA-256 hash.")
    parser.add_argument("name", nargs="?", help="token name, e.g. grok-viewer")
    parser.add_argument("role", nargs="?", choices=ROLES)
    parser.add_argument("--hash-only", metavar="TOKEN", help="only print the hash of TOKEN")
    args = parser.parse_args()

    if args.hash_only:
        print(hashlib.sha256(args.hash_only.encode()).hexdigest())
        return
    if not args.name or not args.role:
        parser.print_help()
        sys.exit(2)

    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    print(
        f"Token (give this to Grok; store it somewhere safe, it is shown only once):\n  {token}\n"
    )
    print(f"API_TOKENS entry (put this in Vercel):\n  {args.name}:{args.role}:{digest}")


if __name__ == "__main__":
    main()
