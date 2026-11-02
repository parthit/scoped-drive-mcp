"""One-time local script: sign in AS THE BOT GMAIL ACCOUNT and print its refresh token.

Usage (pick one):
    export GOOGLE_OAUTH_CLIENT_ID=... GOOGLE_OAUTH_CLIENT_SECRET=...
    uv run python scripts/bootstrap_oauth.py

    uv run python scripts/bootstrap_oauth.py --client-secrets ~/Downloads/client_secret_XXXX.json

The client must be a "Desktop app" OAuth client. Keep the JSON file outside this repo
(or delete it afterwards); never commit it or the printed refresh token.
"""

import argparse
import json
import os
import sys
from pathlib import Path

from google_auth_oauthlib.flow import InstalledAppFlow

DRIVE_SCOPE = "https://www.googleapis.com/auth/drive"
AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
TOKEN_URI = "https://oauth2.googleapis.com/token"  # noqa: S105 - public endpoint


def _client_config(args: argparse.Namespace) -> dict:
    if args.client_secrets:
        path = Path(args.client_secrets).expanduser()
        return json.loads(path.read_text())
    client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
    if not client_id or not client_secret:
        sys.exit(
            "Set GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET, "
            "or pass --client-secrets path/to/client_secret.json"
        )
    return {
        "installed": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": AUTH_URI,
            "token_uri": TOKEN_URI,
            "redirect_uris": ["http://localhost"],
        }
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--client-secrets", help="path to the downloaded Desktop OAuth client JSON")
    parser.add_argument("--port", type=int, default=0, help="local redirect port (0 = random)")
    parser.add_argument(
        "--no-browser", action="store_true", help="print the sign-in URL instead of opening it"
    )
    args = parser.parse_args()

    flow = InstalledAppFlow.from_client_config(_client_config(args), scopes=[DRIVE_SCOPE])
    print("A browser window will open. Sign in as the BOT Gmail account, not your own.\n")
    creds = flow.run_local_server(
        port=args.port,
        open_browser=not args.no_browser,
        access_type="offline",
        prompt="consent",
        authorization_prompt_message="If the browser did not open, visit:\n{url}\n",
    )
    if not creds.refresh_token:
        sys.exit("Google did not return a refresh token. Revoke the app's access and retry.")

    print("\nSuccess. Store this as GOOGLE_OAUTH_REFRESH_TOKEN in Vercel (keep it secret):\n")
    print(creds.refresh_token)


if __name__ == "__main__":
    main()
