"""Web dashboard: sign-in, connections, Drive browser, allowlist, access requests, activity.

Google is asked twice. Step 1 (`/auth/login`) signs the person in with `openid` and
`email` only, and sets a signed, httponly, SameSite=Lax session cookie. Step 2
(`/connect`) is a separate, explicit choice that asks for the wider scopes of one
connection (Google Drive today, see `connections.py`) and stores that refresh token.
Pages that need Drive send a signed-in person without a connection to `/connect`.
Each person sees only their own data.
`OWNER_EMAIL` is the admin and the only account that can open `/admin`. MCP bearer tokens
are never consulted here, and the MCP endpoint never reads this cookie (it is a separate
ASGI app behind BearerAuthMiddleware). Every POST requires the per-session CSRF token, and
a cross-origin `Origin` is refused.
"""

import functools
import hashlib
import hmac
import html
import logging
import re
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import date
from functools import partial
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

import anyio.to_thread
from itsdangerous import BadSignature, URLSafeTimedSerializer
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .access import PENDING, AccessRequests
from .audit import audit_owner
from .auth import current_actor
from .bridge import MailboxError
from .config import Settings
from .connections import CONNECTIONS, Connection, get_connection
from .drive_client import (
    DRIVE_SCOPE,
    FOLDER_MIME,
    SHORTCUT_MIME,
    DriveNotFoundError,
    LazyBotDriveClient,
    OwnerDriveClient,
)
from .errors import report_exception
from .external import SharedAccessError, normalize_email
from .grants import OWNER_FIELDS, GrantError, GrantService
from .humanize import (
    ACTIVITY_FILTERS,
    MISSING,
    app_names,
    assistant_label,
    describe,
    group_repeats,
    item_ids,
    matches,
    parse_ts,
    when,
)
from .mcp_oauth import SCOPE, AuthorizeError, McpOAuth, QueryMapping
from .oauth import SIGN_IN_SCOPES, OAuthClient, OAuthError, refresh_access_token
from .ratelimit import allow, client_ip
from .scope import InvalidInputError, clean_search_text, parents_clause, validate_drive_id
from .store import (
    AUDIENCE_LINKED,
    EXTERNAL_ALLOWLIST_KEY,
    ActivityLog,
    Allowlist,
    TokenVault,
)

logger = logging.getLogger(__name__)

SESSION_COOKIE = "sdm_session"
SESSION_MAX_AGE = 8 * 3600
STATE_MAX_AGE = 600
STATE_SALT = "sdm-oauth-state"
BROWSE_PAGE_SIZE = 200
ACTIVITY_PAGE = 50
# Drive lookups for names the activity page cannot find in the person's own lists.
ACTIVITY_LOOKUPS = 10
MAX_BREADCRUMBS = 25

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)

SECURITY_HEADERS = [
    (b"x-frame-options", b"DENY"),
    (b"x-content-type-options", b"nosniff"),
    # `no-referrer` makes browsers send `Origin: null` on HTML form POSTs (Fetch:
    # non-GET, non-cors). check_csrf treats that as a cross-origin request, so a
    # signed-in Sign out fails before the session token is compared. `same-origin`
    # still withholds the referrer from other sites, and a same-origin form POST
    # carries this app's origin.
    (b"referrer-policy", b"same-origin"),
    (b"cache-control", b"no-store"),
    (
        b"content-security-policy",
        # Google Picker loads api.js from apis.google.com (that script evaluates code),
        # then opens Drive in a frame. frame-ancestors stays none so this site is not embedded.
        b"default-src 'self'; "
        b"script-src 'self' https://apis.google.com https://www.gstatic.com 'unsafe-eval'; "
        b"style-src 'self' 'unsafe-inline'; "
        b"img-src 'self' data: https://*.googleusercontent.com https://*.gstatic.com; "
        b"connect-src 'self' https://www.googleapis.com https://content.googleapis.com; "
        b"frame-src https://docs.google.com https://drive.google.com https://accounts.google.com "
        b"https://content.googleapis.com https://*.google.com https://*.googleusercontent.com; "
        b"worker-src 'self' blob:; "
        b"form-action 'self' https://accounts.google.com; "
        b"frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
    ),
]

_LOGIN_HINT = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Searches per person per minute on "Shared with me". Each one reads every sharer's Drive.
SHARED_SEARCH_LIMIT = 20
# Folder lookups one Files page may make to work out search-result paths and
# folder-inherited access. Past this, the remaining rows say to open their folder.
SEARCH_LOOKUPS = 40
# Name matches shown for one Browse search. More than this and the page says to narrow it.
SEARCH_PAGE = 100
# Item ids in "Shared with me" links. Drive ids fit; other sources must too.
_SHARED_ID = re.compile(r"[A-Za-z0-9_.:\-]{1,200}")


class OwnerNotConnectedError(Exception):
    """Signed in, but Google Drive is not connected yet (send them to /connect)."""


@dataclass
class DashboardContext:
    settings: Settings
    store: Any
    allowlist: Allowlist
    vault: TokenVault
    requests: AccessRequests
    activity: ActivityLog
    oauth: OAuthClient | None
    owner_drive_factory: Callable[[str], OwnerDriveClient]
    bot_drive: Any = None
    on_allowlist_change: Callable[[], None] = lambda: None
    mcp_oauth: McpOAuth | None = None
    directory: Any = None
    drive_router: Any = None
    mailbox: Any = None
    # The list other people's assistants may read (external.py). None disables Sharing.
    ext_allowlist: Allowlist | None = None
    on_ext_change: Callable[[], None] = lambda: None
    # What paired people share with this person, across every source (shared_sources.py).
    # None hides the "Shared with me" pages.
    shared_with_me: Any = None
    # (caller email, file id) -> the paired person whose Sharing list covers that id,
    # including files inside a shared folder (ExternalShares.sharer_of).
    sharer_of: Callable[[str, str], str | None] | None = None
    _owner_clients: dict[str, tuple[str, OwnerDriveClient]] = field(
        default_factory=dict, repr=False
    )

    def _admin_actor(self) -> bool:
        actor = current_actor.get()
        return not actor or actor == self.settings.owner_email

    def owner_drive(self) -> OwnerDriveClient:
        record = self.vault.owner()
        if not record or not record.get("t"):
            raise OwnerNotConnectedError
        token = record["t"]
        actor = current_actor.get() or ""
        cached = self._owner_clients.get(actor)
        if cached is None or cached[0] != token:
            self._owner_clients[actor] = (token, self.owner_drive_factory(token))
        return self._owner_clients[actor][1]

    def grants(self) -> GrantService:
        return GrantService(
            self.owner_drive,
            self.allowlist,
            self.requests,
            None,
            on_change=self.on_allowlist_change,
        )

    def ext_grants(self) -> GrantService:
        """Grant and revoke on the external list. Same checks as the own-bot list (the item
        must be in this person's Drive, not trashed, not My Drive's root; a shortcut adds
        its target). No Drive permission is created."""
        if self.ext_allowlist is None:
            raise GrantError("Sharing is not set up on this server.")
        return GrantService(
            self.owner_drive,
            self.ext_allowlist,
            self.requests,
            None,
            on_change=self.on_ext_change,
            audience=AUDIENCE_LINKED,
            audit_actions=("share_external", "unshare_external"),
        )

    def ext_ids(self) -> set[str]:
        return set(self.ext_allowlist.entries()) if self.ext_allowlist is not None else set()

    def visible_root_folder_id(self) -> str | None:
        """The deployment root is the admin's folder. Other people do not see its id."""
        if self._admin_actor():
            return self.settings.root_folder_id
        return None

    def forget_drive(self, email: str | None = None) -> None:
        if isinstance(self.bot_drive, LazyBotDriveClient) and (
            email is None or email == self.settings.owner_email
        ):
            self.bot_drive.invalidate()
        if self.drive_router is not None:
            self.drive_router.invalidate(email)

    def bot_status(self) -> dict[str, Any]:
        """Which Google account the MCP tools act as, and where its token comes from."""
        if self._admin_actor() and self.settings.env_bot_refresh_token:
            return {"connected": True, "source": "env", "email": self.settings.owner_email}
        record = self.vault.owner() if self.vault.enabled else None
        if record and record.get("t"):
            return {"connected": True, "source": "owner", "email": record.get("email")}
        return {"connected": False, "source": None, "email": None}

    def owner_connected(self) -> bool:
        return bool(self.vault.enabled and self.vault.owner())

    def drive_connected(self) -> bool:
        """Step 2 is done: a Google Drive refresh token is stored for this person."""
        if not self.vault.enabled:
            return False
        record = self.vault.owner()
        return bool(record and record.get("t"))

    def connection_rows(self) -> list[dict[str, Any]]:
        """Each connection and whether this person has finished it."""
        rows = []
        for conn in CONNECTIONS.values():
            connected = self.drive_connected() if conn.key == "google_drive" else False
            # A stored token without the full scope (old drive.file, or no scope stamp)
            # still works for what it covers, but has to be upgraded by connecting again.
            needs_upgrade = connected and conn.key == "google_drive" and self.reconsent_needed()
            rows.append(
                {"connection": conn, "connected": connected, "needs_upgrade": needs_upgrade}
            )
        return rows

    def disconnect_drive(self) -> str | None:
        """Forget this person's Drive token. Returns the token so Google can revoke it."""
        record = self.vault.owner() if self.vault.enabled else None
        token = record.get("t") if record else None
        self.vault.clear_owner()
        return token

    def reconsent_needed(self) -> bool:
        """True when the saved sign-in cannot see the whole Drive.

        A missing scope stamp, or a token that only has drive.file, has to sign in
        again. A token that already includes full Drive does not.
        """
        if not self.vault.enabled:
            return False
        record = self.vault.owner()
        if not record or not record.get("t"):
            return False
        scopes = set(str(record.get("scopes") or "").split())
        return DRIVE_SCOPE not in scopes


async def blocking[T](fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    return await anyio.to_thread.run_sync(partial(fn, *args, **kwargs))


WAKE_HOME = "/settings#assistants"
LIST_FIELDS = OWNER_FIELDS + ",modifiedTime"
COVER_CHECK_LIMIT = 25


def _end_of_day(day: str) -> str | None:
    """A date from the Sharing form ("2026-12-31") as the last second of that day, UTC,
    in the same ISO form as utc_now() so the two compare as strings."""
    day = day.strip()
    if not day:
        return None
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
        raise ValueError(day)
    date.fromisoformat(day)
    return f"{day}T23:59:59+00:00"


def _dupes(rows: list[dict[str, Any]]) -> set[str]:
    seen: dict[str, int] = {}
    for row in rows:
        key = str(row.get("name") or "").strip().casefold()
        seen[key] = seen.get(key, 0) + 1
    return {name for name, n in seen.items() if n > 1}


def icon_kind(mime: str) -> str:
    """Which small icon a row gets: folder, doc, sheet, slides, pdf, image, video, file."""
    if mime == FOLDER_MIME:
        return "folder"
    if mime == SHORTCUT_MIME:
        return "shortcut"
    if mime.endswith(".document") or "wordprocessing" in mime or mime == "application/msword":
        return "doc"
    if (
        mime.endswith(".spreadsheet")
        or "spreadsheetml" in mime
        or mime
        in (
            "application/vnd.ms-excel",
            "text/csv",
        )
    ):
        return "sheet"
    if mime.endswith(".presentation") or "presentationml" in mime or "powerpoint" in mime:
        return "slides"
    if mime == "application/pdf":
        return "pdf"
    if mime.startswith("image/"):
        return "image"
    if mime.startswith("video/"):
        return "video"
    return "file"


def safe_next(value: str | None) -> str:
    """A same-site path, else "/". Browsers drop tabs and newlines from a URL, so
    "/\t/evil.example" in a link would become "//evil.example"; refuse those too."""
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    if any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in value):
        return "/"
    return value


def origin_of(url: str) -> str:
    scheme, _, rest = url.partition("://")
    return f"{scheme}://{rest.split('/', 1)[0]}"


# Two years, the value browsers' preload lists expect. Only sent over HTTPS deployments.
HSTS_HEADER = (b"strict-transport-security", b"max-age=63072000; includeSubDomains")


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, *, hsts: bool = False):
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                # Pages are never cached. A static asset sets its own policy and keeps it.
                cacheable = any(key.lower() == b"cache-control" for key, _ in headers)
                headers += [
                    item
                    for item in SECURITY_HEADERS
                    if not (cacheable and item[0] == b"cache-control")
                ]
                if self.hsts:
                    headers.append(HSTS_HEADER)
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


# ---- rendering helpers ----------------------------------------------------


def _csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


def flash(request: Request, kind: str, message: str) -> None:
    messages = list(request.session.get("flash", []))
    messages.append([kind, message])
    request.session["flash"] = messages[-5:]


def wants_json(request: Request) -> bool:
    """True when ui.js submitted a row action in the background (Accept: application/json)."""
    return "application/json" in request.headers.get("accept", "")


def action_done(
    request: Request, kind: str, message: str, next_url: str, *, changed: bool | None = None
) -> Response:
    """Finish a dashboard action that changes one row.

    ui.js sends these in the background and updates only the affected row, so it gets
    JSON back. A plain form POST (no JavaScript) still gets a flash and a redirect.
    `changed` says whether the row's state changed. It defaults to success, but a revoke
    can remove the item from the list and still report a Drive error.
    """
    if wants_json(request):
        return JSONResponse(
            {
                "ok": kind == "ok",
                "kind": kind,
                "message": message,
                "changed": (kind == "ok") if changed is None else changed,
            },
            status_code=200 if kind == "ok" else 400,
        )
    flash(request, kind, message)
    return RedirectResponse(next_url, status_code=303)


def render(request: Request, template: str, status_code: int = 200, **ctx: Any) -> HTMLResponse:
    owner = request.session.get("owner")
    admin_email = getattr(request.app.state, "owner_email", None)
    # Callers that already loaded the waiting-request count pass it. Otherwise use the
    # count stashed for this request. Rendering itself does not read the store.
    pending_count = ctx.pop("pending_count", None)
    if pending_count is None:
        pending_count = getattr(request.state, "pending_count", 0)
    reconsent = ctx.pop("reconsent", None)
    if reconsent is None:
        reconsent = getattr(request.state, "reconsent", False)
    ctx.setdefault("mailbox_count", getattr(request.state, "mailbox_count", 0))
    ctx.setdefault("allow_count", getattr(request.state, "allow_count", None))
    html = _env.get_template(template).render(
        request=request,
        owner=owner,
        is_admin=bool(owner and admin_email and owner == admin_email),
        csrf=_csrf_token(request) if owner else None,
        flashes=request.session.pop("flash", []) if owner else [],
        nav=request.url.path,
        pending_count=pending_count,
        reconsent=reconsent,
        status_code=status_code,
        **ctx,
    )
    return HTMLResponse(html, status_code=status_code)


def render_plain(template: str, status_code: int = 200, **ctx: Any) -> HTMLResponse:
    html = _env.get_template(template).render(
        owner=None, csrf=None, flashes=[], nav="", reconsent=False, pending_count=0, **ctx
    )
    return HTMLResponse(html, status_code=status_code)


async def terms_page(_: Request) -> Response:
    return render_plain("terms.html")


async def privacy_page(_: Request) -> Response:
    return render_plain("privacy.html")


@functools.lru_cache(maxsize=16)
def _asset(name: str) -> tuple[bytes, str]:
    data = (TEMPLATES_DIR / name).read_bytes()
    return data, '"' + hashlib.sha256(data).hexdigest()[:32] + '"'


def _file_response(request: Request, name: str, media: str, cache: str = "no-cache") -> Response:
    """A bundled asset. `no-cache` still lets the browser keep it: it revalidates with the
    ETag and gets a 304, so a new deployment's CSS and JS are picked up at once."""
    data, etag = _asset(name)
    headers = {"etag": etag, "cache-control": cache}
    if etag in (request.headers.get("if-none-match") or ""):
        return Response(status_code=304, headers=headers)
    return Response(data, media_type=media, headers=headers)


def favicon(_: Request) -> Response:
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img">'
        '<rect width="64" height="64" rx="14" fill="#f6f2ea"/>'
        '<g transform="translate(3.8 4.975) scale(2.35)">'
        '<path id="scoped-mark" fill="#1e1915" fill-rule="evenodd" '
        'd="M5 20V10a7 7 0 0 1 14 0v10h-3.2V10a3.8 3.8 0 0 0-7.6 0v10H5z"/>'
        "</g></svg>"
    )
    return Response(svg, media_type="image/svg+xml")


_FONT_FILES = {
    "geist-400.woff2": "fonts/geist-400.woff2",
    "geist-500.woff2": "fonts/geist-500.woff2",
    "geist-600.woff2": "fonts/geist-600.woff2",
    "geist-mono-500.woff2": "fonts/geist-mono-500.woff2",
}


def font_asset(request: Request) -> Response:
    rel = _FONT_FILES.get(request.path_params["name"])
    if rel is None:
        return Response(status_code=404)
    # Font files never change under the same name.
    return _file_response(request, rel, "font/woff2", "public, max-age=2592000")


def robots(_: Request) -> Response:
    body = "User-agent: *\nAllow: /$\nAllow: /login\nAllow: /privacy\nAllow: /terms\nDisallow: /\n"
    return Response(body, media_type="text/plain; charset=utf-8")


def stylesheet(request: Request) -> Response:
    return _file_response(request, "app.css", "text/css; charset=utf-8")


def ui_script(request: Request) -> Response:
    return _file_response(request, "ui.js", "text/javascript; charset=utf-8")


def legal_routes() -> list[Route]:
    """Public pages and assets. Google's OAuth screen links to /terms and /privacy."""
    return [
        Route("/terms", terms_page, methods=["GET"]),
        Route("/privacy", privacy_page, methods=["GET"]),
        Route("/favicon.ico", favicon, methods=["GET"]),
        Route("/favicon.svg", favicon, methods=["GET"]),
        Route("/robots.txt", robots, methods=["GET"]),
        Route("/app.css", stylesheet, methods=["GET"]),
        Route("/ui.js", ui_script, methods=["GET"]),
        Route("/fonts/{name}", font_asset, methods=["GET"]),
    ]


Handler = Callable[[Request], Awaitable[Response]]


def build_dashboard(ctx: DashboardContext) -> Starlette:
    settings = ctx.settings
    missing = settings.dashboard_missing()
    if missing or ctx.oauth is None:

        async def not_configured(request: Request) -> Response:
            return render_plain("setup.html", status_code=503, missing=missing)

        return Starlette(
            routes=[
                *legal_routes(),
                Route("/{path:path}", not_configured, methods=["GET", "POST"]),
            ],
            middleware=[Middleware(SecurityHeadersMiddleware)],
        )

    assert settings.session_secret is not None and settings.app_base_url is not None
    oauth = ctx.oauth
    serializer = URLSafeTimedSerializer(settings.session_secret.get_secret_value(), STATE_SALT)
    app_origin = origin_of(settings.app_base_url)

    async def remember_pending(request: Request) -> None:
        """One waiting-request count for this page, off the event loop. The nav reads it."""
        try:
            request.state.pending_count = await blocking(ctx.requests.pending_count)
        except Exception:
            logger.exception("pending request count failed")
            request.state.pending_count = 0
        try:
            request.state.reconsent = await blocking(ctx.reconsent_needed)
        except Exception:
            logger.exception("reconsent check failed")
            request.state.reconsent = False
        # Mailbox nav badge: pairings waiting on this person's approval.
        actor = current_actor.get()
        request.state.mailbox_count = 0
        if ctx.mailbox is not None and actor:
            try:
                request.state.mailbox_count = await blocking(
                    ctx.mailbox.needs_approval_count, actor
                )
            except Exception:
                logger.exception("mailbox approval count failed")

    def session_user(request: Request) -> str | None:
        """Signed-in email (step 1). A Drive connection (step 2) is not required here."""
        owner = request.session.get("owner")
        if not isinstance(owner, str) or not owner or ctx.directory is None:
            return None
        if not settings.sign_in_allowed(owner):
            return None
        if not ctx.directory.is_known_user(owner):
            return None
        return owner

    def connect_redirect(request: Request) -> RedirectResponse:
        target = request.url.path
        if request.url.query:
            target += "?" + request.url.query
        if request.method != "GET":
            target = "/"
        return RedirectResponse(f"/connect?{urlencode({'next': target})}", status_code=303)

    def refused(
        request: Request, status: int, message: str, *, title: str | None = None
    ) -> Response:
        """An error for a dashboard request: JSON for a background row action (ui.js
        shows the message next to the row), otherwise the styled error page."""
        if wants_json(request):
            return JSONResponse(
                {"ok": False, "kind": "error", "message": message, "changed": False},
                status_code=status,
            )
        return render(request, "error.html", status, message=message, title=title)

    def safely(handler: Handler) -> Handler:
        """For pages that handle sign-in themselves: a store or network failure becomes
        the styled error page (with the security headers) instead of a bare 500."""

        async def wrapped(request: Request) -> Response:
            try:
                return await handler(request)
            except Exception as exc:
                report_exception(exc, where="dashboard")
                return refused(request, 500, "Something went wrong on our side. Try again.")

        return wrapped

    def owner_only(handler: Handler) -> Handler:
        async def wrapped(request: Request) -> Response:
            email = session_user(request)
            if not email:
                if request.method != "GET":
                    return refused(
                        request,
                        403,
                        "You are signed out. Sign in again, then repeat that step.",
                        title="Signed out",
                    )
                target = request.url.path
                if request.url.query:
                    target += "?" + request.url.query
                return RedirectResponse(f"/login?{urlencode({'next': target})}", status_code=303)
            reset = current_actor.set(email)
            try:
                await remember_pending(request)
                return await handler(request)
            except OwnerNotConnectedError:
                if wants_json(request):
                    return refused(
                        request, 409, "Google Drive is not connected. Open Connections first."
                    )
                return connect_redirect(request)
            except InvalidInputError as exc:
                return refused(request, 400, str(exc))
            except Exception as exc:
                report_exception(exc, where="dashboard")
                return refused(request, 502, "A Google Drive request failed. Try again.")
            finally:
                current_actor.reset(reset)

        return wrapped

    async def check_csrf(request: Request) -> dict[str, str] | None:
        origin = request.headers.get("origin")
        if origin is not None and origin != app_origin:
            return None
        form = await request.form()
        sent = form.get("csrf")
        expected = request.session.get("csrf")
        if (
            not isinstance(sent, str)
            or not isinstance(expected, str)
            or not expected
            # Bytes: compare_digest raises TypeError on non-ASCII text.
            or not hmac.compare_digest(sent.encode(), expected.encode())
        ):
            return None
        return {k: v for k, v in form.items() if isinstance(v, str)}

    def csrf_protected(
        handler: Callable[[Request, dict[str, str]], Awaitable[Response]],
    ) -> Handler:
        async def wrapped(request: Request) -> Response:
            form = await check_csrf(request)
            if form is None:
                audit_owner("csrf", "deny", path=request.url.path)
                return refused(
                    request,
                    403,
                    "This page was open too long to be sure the request came from you. "
                    "Go back, reload the page and try again.",
                    title="Please try again",
                )
            return await handler(request, form)

        return owner_only(wrapped)

    # ---- sign-in -------------------------------------------------------

    def start_oauth(
        request: Request,
        flow: str,
        login_hint: str | None,
        connection: Connection | None = None,
    ) -> RedirectResponse:
        """Step 1 (`flow="signin"`) or step 2 (`flow="connect"` with a connection)."""
        nonce = secrets.token_urlsafe(24)
        request.session["oauth_nonce"] = nonce
        payload: dict[str, str] = {"flow": flow, "nonce": nonce}
        if connection is None:
            url_scopes = SIGN_IN_SCOPES
            offline = False
        else:
            payload["connection"] = connection.key
            url_scopes = SIGN_IN_SCOPES + connection.scopes
            offline = True
        state = serializer.dumps(payload)
        url = oauth.authorization_url(state, login_hint, scopes=url_scopes, offline=offline)
        return RedirectResponse(url, status_code=303)

    async def login_rate_limited(request: Request) -> Response | None:
        ip = client_ip(
            [(k.encode(), v.encode()) for k, v in request.headers.items()],
            request.client.host if request.client else "unknown",
        )
        allowed = await blocking(
            allow,
            ctx.store,
            "login",
            "ip:" + ip,
            settings.login_rate_limit,
            settings.login_rate_window_seconds,
        )
        if allowed:
            return None
        page = render(
            request,
            "error.html",
            429,
            message=(
                "Too many sign-in attempts from this network. Wait a few minutes and try again."
            ),
        )
        page.headers["retry-after"] = str(settings.login_rate_window_seconds)
        return page

    async def login(request: Request) -> Response:
        if session_user(request):
            return RedirectResponse(safe_next(request.query_params.get("next")), status_code=303)
        next_url = safe_next(request.query_params.get("next"))
        purpose = hint = None
        if next_url.startswith("/requests/"):
            purpose = "review an access request"
            hint = "Use the Google account that owns the assistant that asked."
        elif next_url.startswith("/oauth/authorize"):
            purpose = "connect an assistant"
            hint = "Use the Google account whose files the assistant should work with."
        return render(
            request,
            "login.html",
            next=next_url,
            purpose=purpose,
            purpose_hint=hint,
            signed_out=request.query_params.get("signed_out") == "1",
        )

    def supplied_login_hint(request: Request) -> str | None:
        """A hint only when this visitor typed one. Never the server's owner address."""
        raw = request.query_params.get("login_hint")
        if not isinstance(raw, str):
            return None
        raw = raw.strip().lower()
        if not raw or len(raw) > 254 or not _LOGIN_HINT.fullmatch(raw):
            return None
        return raw

    async def auth_login(request: Request) -> Response:
        limited = await login_rate_limited(request)
        if limited is not None:
            return limited
        request.session["oauth_next"] = safe_next(request.query_params.get("next"))
        return start_oauth(request, "signin", supplied_login_hint(request))

    async def auth_callback(request: Request) -> Response:
        params = request.query_params
        if params.get("error"):
            return oauth_cancelled(request, params)
        try:
            data = serializer.loads(params.get("state", ""), max_age=STATE_MAX_AGE)
        except BadSignature:
            return render(request, "error.html", 400, message="Invalid sign-in state. Try again.")
        nonce = request.session.pop("oauth_nonce", None)
        if (
            not isinstance(data, dict)
            or not nonce
            or not hmac.compare_digest(str(nonce), str(data.get("nonce", "")))
        ):
            return render(request, "error.html", 400, message="Sign-in expired. Try again.")
        flow = data.get("flow")
        if flow not in ("signin", "connect"):
            return render(request, "error.html", 400, message="Invalid sign-in state.")
        code = params.get("code")
        if not code:
            return render(request, "error.html", 400, message="Google did not return a code.")

        try:
            tokens = await blocking(oauth.exchange_code, code)
            info = await blocking(oauth.userinfo, tokens.access_token)
        except OAuthError as exc:
            return render(request, "error.html", 502, message=f"Sign-in failed: {exc}.")

        email = str(info.get("email", "")).strip().lower()
        verified = info.get("email_verified") in (True, "true")
        if not verified or not settings.sign_in_allowed(email):
            await blocking(oauth.revoke, tokens.refresh_token or tokens.access_token)
            audit_owner("login", "deny", reason="wrong_account")
            return render(
                request,
                "error.html",
                403,
                message="This Google account is not allowed to use this dashboard.",
            )
        if flow == "connect":
            return await finish_connect(request, data, tokens, email)
        return await finish_sign_in(request, email)

    def oauth_cancelled(request: Request, params: Any) -> Response:
        """Google sent the person back without a code (they chose Cancel, or Google
        refused). Say which step it was and offer to try that step again."""
        flow = None
        connection = None
        try:
            data = serializer.loads(params.get("state", ""), max_age=STATE_MAX_AGE)
        except BadSignature:
            data = None
        if isinstance(data, dict):
            flow = data.get("flow")
            connection = get_connection(str(data.get("connection") or ""))
        request.session.pop("oauth_nonce", None)
        next_url = safe_next(request.session.get("oauth_next"))
        cancelled = params.get("error") == "access_denied"
        if flow == "connect" and session_user(request):
            name = connection.name if connection else "Google Drive"
            retry = "/connect" + (f"?{urlencode({'next': next_url})}" if next_url != "/" else "")
            return render(
                request,
                "error.html",
                400,
                title=f"You didn’t connect {name}" if cancelled else f"{name} isn’t connected",
                message=(
                    f"You cancelled on Google’s screen, so nothing changed. Your assistant "
                    f"can’t reach {name} until you connect it."
                    if cancelled
                    else f"Google didn’t finish connecting {name}. Nothing changed."
                ),
                actions=[
                    {"label": "Try again", "href": retry, "primary": True},
                    {"label": "Back to Overview", "href": "/"},
                ],
            )
        retry = "/login" + (f"?{urlencode({'next': next_url})}" if next_url != "/" else "")
        return render(
            request,
            "error.html",
            400,
            title="Sign-in cancelled" if cancelled else "Sign-in didn’t finish",
            message=(
                "You cancelled on Google’s screen, so you are not signed in."
                if cancelled
                else "Google didn’t finish signing you in. Nothing was changed."
            ),
            actions=[
                {"label": "Try again", "href": retry, "primary": True},
                {"label": "Back to home", "href": "/"},
            ],
        )

    async def finish_sign_in(request: Request, email: str) -> Response:
        """Step 1 done. Nothing from Google is stored except that this address signed in."""
        if ctx.directory is not None:
            reset = current_actor.set(email)
            try:
                await blocking(ctx.directory.remember_user, email)
            finally:
                current_actor.reset(reset)
        next_url = safe_next(request.session.get("oauth_next"))
        request.session.clear()
        request.session["owner"] = email
        request.session["csrf"] = secrets.token_urlsafe(32)
        audit_owner("login")
        reset = current_actor.set(email)
        try:
            connected = await blocking(ctx.drive_connected)
        finally:
            current_actor.reset(reset)
        if not connected:
            # Step 2 is its own page and its own click, never chained silently.
            return RedirectResponse(f"/connect?{urlencode({'next': next_url})}", status_code=303)
        return RedirectResponse(next_url, status_code=303)

    async def finish_connect(
        request: Request, data: dict[str, Any], tokens: Any, email: str
    ) -> Response:
        """Step 2 done. Store the refresh token for the signed-in person."""

        async def refuse_token() -> None:
            # Google's revoke ends this app's whole grant for that Google account, which
            # would also kill a token already stored for it (a reconnect that was
            # declined, or another person's account). Only revoke when none is stored.
            if ctx.directory is not None:
                stored = await blocking(ctx.directory.has_owner_refresh, email)
            else:
                stored = True
            if not stored:
                await blocking(oauth.revoke, tokens.refresh_token or tokens.access_token)

        signed_in = session_user(request)
        connection = get_connection(str(data.get("connection") or ""))
        if not signed_in or connection is None:
            await refuse_token()
            return render(request, "error.html", 400, message="Sign in first, then connect.")
        if email != signed_in:
            # The Drive an assistant uses must belong to the person who signed in.
            await refuse_token()
            audit_owner("connect", "deny", reason="different_account")
            next_url = safe_next(request.session.get("oauth_next"))
            retry = "/connect" + (f"?{urlencode({'next': next_url})}" if next_url != "/" else "")
            return render(
                request,
                "error.html",
                403,
                title="That was a different Google account",
                message=(
                    f"You are signed in as {signed_in}, but Google returned a different "
                    f"account. Connect {connection.name} with {signed_in}."
                ),
                actions=[
                    {"label": "Try again", "href": retry, "primary": True},
                    {"label": "Back to Overview", "href": "/"},
                ],
            )
        if connection.required_scope not in tokens.scopes:
            await refuse_token()
            return render(
                request,
                "error.html",
                400,
                message=(
                    f"{connection.name} access was not granted. Choose Connect again and "
                    f"allow access to your Drive."
                ),
            )
        if not tokens.refresh_token:
            return render(
                request,
                "error.html",
                400,
                message="Google did not return a refresh token. Remove the app at "
                "myaccount.google.com/permissions and try again.",
            )

        reset = current_actor.set(email)
        try:
            scope_stamp = " ".join(sorted(tokens.scopes))
            await blocking(ctx.vault.set_owner, tokens.refresh_token, email, scope_stamp)
            if ctx.directory is not None:
                await blocking(ctx.directory.remember_user, email)
        finally:
            current_actor.reset(reset)
        ctx.forget_drive(email)
        audit_owner("connect", connection=connection.key)
        next_url = safe_next(request.session.pop("oauth_next", None))
        flash(request, "ok", f"{connection.name} is connected.")
        return RedirectResponse(next_url, status_code=303)

    # ---- connections (step 2) -------------------------------------------

    def waiting_client(next_url: str) -> str | None:
        """The app whose connection sent this person here (/oauth/authorize?...), if any."""
        if ctx.mcp_oauth is None or not next_url.startswith("/oauth/authorize?"):
            return None
        params = dict(parse_qsl(urlsplit(next_url).query, keep_blank_values=True))
        try:
            return ctx.mcp_oauth.parse_authorize(QueryMapping(params)).client_name
        except AuthorizeError:
            return None

    async def connect_page(request: Request) -> Response:
        rows = await blocking(ctx.connection_rows)
        next_url = safe_next(request.query_params.get("next"))
        if next_url.startswith("/connect"):
            next_url = "/"
        client_name = await blocking(waiting_client, next_url)
        if any(r["connected"] for r in rows) and next_url == "/" and not client_name:
            # Set up already: the services list lives in Settings now.
            return RedirectResponse("/settings#services", status_code=303)
        return render(
            request,
            "connect.html",
            rows=rows,
            next=next_url,
            waiting_client=client_name,
            drive_connected=any(r["connected"] for r in rows),
        )

    async def connect_start(request: Request, form: dict[str, str]) -> Response:
        connection = get_connection(request.path_params.get("key"))
        if connection is None:
            return render(request, "error.html", 404, message="Unknown connection.")
        limited = await login_rate_limited(request)
        if limited is not None:
            return limited
        request.session["oauth_next"] = safe_next(form.get("next"))
        return start_oauth(request, "connect", current_actor.get() or None, connection)

    async def connect_remove(request: Request, form: dict[str, str]) -> Response:
        connection = get_connection(request.path_params.get("key"))
        if connection is None:
            return render(request, "error.html", 404, message="Unknown connection.")
        email = current_actor.get()
        token = await blocking(ctx.disconnect_drive)
        if token:
            # Google's revoke also ends this app's sign-in grant. Step 1 holds no token,
            # so the dashboard session is unaffected.
            await blocking(oauth.revoke, token)
        ctx.forget_drive(email)
        audit_owner("disconnect", connection=connection.key)
        flash(
            request,
            "ok",
            f"{connection.name} is disconnected. Assistants can no longer reach it.",
        )
        return RedirectResponse("/connect", status_code=303)

    async def logout(request: Request, form: dict[str, str]) -> Response:
        audit_owner("logout")
        request.session.clear()
        # "Switch account" on a request page and "Use a different account" on the consent
        # page sign out, then signs in with ?next back.
        pairs = [("signed_out", "1")]
        next_url = safe_next(form.get("next"))
        if next_url != "/":
            pairs.append(("next", next_url))
        return RedirectResponse(f"/login?{urlencode(pairs)}", status_code=303)

    # ---- pages -----------------------------------------------------------

    async def home(request: Request) -> Response:
        # Logged-out visitors get the public page linked from the Google consent screen.
        email = session_user(request)
        if not email:
            return render_plain("home.html")
        reset = current_actor.set(email)
        try:
            await remember_pending(request)
            return await overview(request)
        finally:
            current_actor.reset(reset)

    async def overview(request: Request) -> Response:
        def gather() -> dict[str, Any]:
            entries = ctx.allowlist.entries()
            bot = ctx.bot_status()
            return {
                "bot": bot,
                "owner_connected": ctx.owner_connected(),
                # Step 2 done for this person. Browse, Allow and Sharing need it, even
                # when the deployment's own bot token (bot.connected) is set.
                "drive_connected": ctx.drive_connected(),
                "connections": ctx.connection_rows(),
                "allow_count": len(entries),
                "grants": (ctx.mcp_oauth.list_grants(current_actor.get()) if ctx.mcp_oauth else []),
                "missing_wakeups": (
                    ctx.mailbox.missing_wakeups(str(current_actor.get() or ""))
                    if ctx.mailbox is not None
                    else []
                ),
                **people_summary(str(current_actor.get() or "")),
            }

        data = await blocking(gather)
        return render(
            request,
            "overview.html",
            missing=settings.missing_settings(),
            store_kind=getattr(ctx.store, "kind", "custom"),
            root_folder_id=ctx.visible_root_folder_id(),
            mcp_url=f"{settings.app_base_url}/mcp",
            picker_ready=settings.picker_configured,
            env_token_set=bool(
                settings.env_bot_refresh_token and session_user(request) == settings.owner_email
            ),
            **data,
        )

    def people_summary(email: str) -> dict[str, Any]:
        """Mailbox and Shared with me counts for Overview. Store reads only, no Drive call."""
        mailbox = None
        if ctx.mailbox is not None and email:
            try:
                mailbox = ctx.mailbox.summary(email)
            except Exception:
                logger.exception("mailbox summary failed")
        shared = None
        if ctx.shared_with_me is not None and email:
            try:
                people = ctx.shared_with_me.overview(email)
                shared = {
                    "people": len(people),
                    "item_count": sum(p.item_count for p in people),
                }
            except Exception:
                logger.exception("shared with me summary failed")
        return {"mailbox_summary": mailbox, "shared_summary": shared}

    def browse_data(folder: str, q: str | None, page_token: str | None) -> dict[str, Any]:
        drive = ctx.owner_drive()
        # drive.file cannot files.get("root") until the app has opened My Drive.
        # The alias still works in a parents query, which is enough to list files
        # this app created or the user picked.
        root_id: str | None
        try:
            root_id = str(drive.get_file("root", fields="id")["id"])
        except DriveNotFoundError:
            root_id = None
        entries = ctx.allowlist.entries()
        shared = ctx.ext_ids()
        crumbs: list[dict[str, str]] = []
        # The nearest allowed folder at or above the one being browsed, and its id so
        # the breadcrumb can offer to remove that folder's own entry.
        covered_by: str | None = None
        covered_id: str | None = None
        # The nearest folder on the Sharing list above the one being browsed. Everything
        # inside it is readable by paired people's assistants, as the guest guard allows.
        shared_by: str | None = None
        shared_id: str | None = None
        next_token: str | None = None
        more_matches = False
        current: dict[str, Any] | None = None
        if q:
            term = clean_search_text(q)
            query = f"trashed=false and name contains '{term}'"
            resp = drive.list_files(query, fields=LIST_FIELDS, page_size=SEARCH_PAGE)
            items = resp.get("files", [])
            more_matches = bool(resp.get("nextPageToken"))
        else:
            if folder == "root":
                folder_id = root_id or "root"
            else:
                folder_id = validate_drive_id(folder, "folder")
            if folder_id == "root":
                current = {
                    "id": "root",
                    "name": "My Drive",
                    "mimeType": FOLDER_MIME,
                    "parents": [],
                }
            else:
                try:
                    current = drive.get_file(folder_id, fields=OWNER_FIELDS)
                except DriveNotFoundError:
                    raise InvalidInputError("folder not found in your Drive") from None
                if current.get("mimeType") != FOLDER_MIME:
                    raise InvalidInputError("that is not a folder")
            node: dict[str, Any] | None = current
            seen: set[str] = set()
            while node is not None and len(crumbs) < MAX_BREADCRUMBS:
                nid = str(node["id"])
                if nid in seen:
                    break
                seen.add(nid)
                name = "My Drive" if nid == root_id or nid == "root" else str(node.get("name", ""))
                crumbs.insert(0, {"id": "root" if nid == root_id else nid, "name": name})
                if covered_by is None and nid in entries:
                    covered_by, covered_id = name, nid
                if shared_by is None and nid in shared:
                    shared_by, shared_id = name, nid
                parents = node.get("parents") or []
                if nid == root_id or nid == "root" or not parents:
                    break
                try:
                    node = drive.get_file(str(parents[0]), fields=OWNER_FIELDS)
                except DriveNotFoundError:
                    node = None
            if folder_id == "root":
                query = "'root' in parents and trashed=false"
            else:
                query = f"{parents_clause([folder_id])} and trashed=false"
            resp = drive.list_files(
                query, fields=LIST_FIELDS, page_size=BROWSE_PAGE_SIZE, page_token=page_token
            )
            items = resp.get("files", [])
            # Drive's parents filter can echo a file that merely mentions the folder.
            # The alias "root" is not the id Drive returns on a file, so it cannot be
            # used for that check.
            if folder_id != "root":
                items = [i for i in items if folder_id in (i.get("parents") or [])]
            next_token = resp.get("nextPageToken")
        items.sort(key=lambda i: (i.get("mimeType") != FOLDER_MIME, str(i.get("name", "")).lower()))

        # Folder metadata looked up while working out search results and shortcut
        # targets. Many results share folders, so each folder is fetched once.
        metas: dict[str, dict[str, Any] | None] = {}
        if current is not None:
            metas[str(current["id"])] = current

        lookups = [0]

        class _OutOfLookups(Exception):
            pass

        def meta_of(fid: str) -> dict[str, Any] | None:
            if fid not in metas:
                if lookups[0] >= SEARCH_LOOKUPS:
                    raise _OutOfLookups
                lookups[0] += 1
                try:
                    metas[fid] = drive.get_file(fid, fields=OWNER_FIELDS)
                except DriveNotFoundError:
                    metas[fid] = None
            return metas[fid]

        def lineage(item: dict[str, Any]) -> list[tuple[str, str]] | None:
            """(id, name) of the folders above `item`, nearest first, up to My Drive.
            Follows the first parent, as the breadcrumbs do. None when the page's lookup
            budget ran out before reaching the top, so the answer would be a guess."""
            out: list[tuple[str, str]] = []
            seen_ids = {str(item.get("id", ""))}
            parents = item.get("parents") or []
            try:
                while parents and len(out) < MAX_BREADCRUMBS:
                    pid = str(parents[0])
                    if pid in seen_ids or pid == root_id or pid == "root":
                        break
                    seen_ids.add(pid)
                    node_meta = meta_of(pid)
                    if node_meta is None:
                        break
                    out.append((pid, str(node_meta.get("name", ""))))
                    parents = node_meta.get("parents") or []
            except _OutOfLookups:
                return None
            return out

        def nearest(chain: list[tuple[str, str]], ids: Any) -> tuple[str, str] | None:
            return next(((fid, name) for fid, name in chain if fid in ids), None)

        # In a folder view every row sits under the same folders, so the folder-level
        # answer applies. Search results come from anywhere, so each works out its own.
        folder_cover = (covered_id, covered_by) if covered_by and covered_id else None
        folder_share = (shared_id, shared_by) if shared_by and shared_id else None
        rows = []
        for item in items:
            iid = str(item["id"])
            mime = str(item.get("mimeType", ""))
            is_shortcut = mime == SHORTCUT_MIME
            path: str | None = None
            unsure = False
            if q:
                chain = lineage(item)
                if chain is None:
                    # Too many folders to look up on one page: don't guess the status.
                    unsure, cover, share, parent_id = True, None, None, None
                else:
                    cover = nearest(chain, entries)
                    share = nearest(chain, shared)
                    path = " / ".join(["My Drive", *(name for _, name in reversed(chain))])
                    parent_id = chain[0][0] if chain else "root"
            else:
                cover, share = folder_cover, folder_share
                parent_id = None
            # A shortcut is not on the lists itself: Allow stores its target. So the row
            # shows the target's state, and Remove / Stop sharing act on the target.
            acts_on = iid
            target: dict[str, Any] | None = None
            if is_shortcut:
                target_id = str((item.get("shortcutDetails") or {}).get("targetId") or "")
                try:
                    target_meta = meta_of(target_id) if target_id else None
                except _OutOfLookups:
                    target_meta, unsure = None, True
                tchain = lineage(target_meta) if target_meta is not None else None
                if target_meta is not None and tchain is None:
                    unsure = True
                if unsure and target_id:
                    # Out of lookups: still act on the target (Allow stores the target),
                    # but don't guess its folder state from the shortcut's own folder.
                    acts_on, cover, share = target_id, None, None
                if target_meta is not None and tchain is not None:
                    # The row's state is the target's, and that is known.
                    acts_on, unsure = target_id, False
                    cover = nearest(tchain, entries)
                    share = nearest(tchain, shared)
                    item_parents = [str(p) for p in item.get("parents") or []]
                    target_parents = [str(p) for p in target_meta.get("parents") or []]
                    target = {
                        "id": target_id,
                        "name": str(target_meta.get("name", "")),
                        "folder": tchain[0][1] if tchain else "My Drive",
                        "elsewhere": not set(item_parents) & set(target_parents),
                    }
            rows.append(
                {
                    "id": iid,
                    "acts_on": acts_on,
                    "name": str(item.get("name", "")),
                    "is_folder": mime == FOLDER_MIME,
                    "is_shortcut": is_shortcut,
                    "target": target,
                    "kind": describe_mime(mime),
                    "icon": icon_kind(mime),
                    "modified": item.get("modifiedTime"),
                    "link": item.get("webViewLink"),
                    "path": path,
                    "parent_id": parent_id,
                    "unsure": unsure,
                    "granted": acts_on in entries,
                    "covered_by": cover[1] if cover else None,
                    "ext_shared": acts_on in shared,
                    "shared_by": share[1] if share else None,
                }
            )
        return {
            "rows": rows,
            # Same-named rows ("Untitled document" three times) show when each changed.
            "dupes": _dupes(rows),
            "crumbs": crumbs,
            "covered_by": covered_by,
            "covered_id": covered_id,
            "shared_by": shared_by,
            "current": current,
            "current_granted": current is not None and str(current["id"]) in entries,
            "is_root": current is not None
            and (
                str(current["id"]) == root_id or (root_id is None and str(current["id"]) == "root")
            ),
            "next_token": next_token,
            "more_matches": more_matches,
            "drive_error": False,
        }

    async def browse(request: Request) -> Response:
        folder = request.query_params.get("folder") or "root"
        q = (request.query_params.get("q") or "").strip()[:200] or None
        page_token = normalize_page_token(request.query_params.get("page"))
        prev = [
            token
            for token in (
                normalize_page_token(item) for item in request.query_params.getlist("prev")
            )
            if token
        ]
        request_id = request.query_params.get("request") or None
        picking = None
        if request_id:
            picking = await blocking(ctx.requests.get, request_id)
            if picking is None or picking.status != PENDING:
                picking = None
        try:
            data = await blocking(browse_data, folder, q, page_token)
        except (InvalidInputError, OwnerNotConnectedError):
            raise
        except Exception as exc:
            # The picker has to stay on the page. A Drive failure used to replace the
            # whole screen, which also removed the only way to approve a file.
            report_exception(exc, where="browse")
            if page_token:
                # Most often a page link that went stale (Back, or a bookmark). Show the
                # folder's first page instead of an error.
                first = {"folder": folder}
                if q:
                    first["q"] = q
                if picking:
                    first["request"] = picking.id
                return RedirectResponse(f"/files?{urlencode(first)}", status_code=303)
            data = {
                "rows": [],
                "crumbs": [{"id": "root", "name": "My Drive"}],
                "covered_by": None,
                "covered_id": None,
                "shared_by": None,
                "current": {"id": "root", "name": "My Drive", "mimeType": FOLDER_MIME},
                "current_granted": False,
                "is_root": True,
                "next_token": None,
                "drive_error": True,
            }
        here = request.url.path + ("?" + request.url.query if request.url.query else "")
        pager = browse_pager(
            folder,
            q=q,
            request_id=picking.id if picking else None,
            page=page_token,
            prev=prev,
            next_token=data.get("next_token"),
        )
        email = str(current_actor.get() or "")
        has_pairing = bool(
            ctx.mailbox is not None
            and ctx.ext_allowlist is not None
            and await blocking(ctx.mailbox.active_peers, email)
        )
        return render(
            request,
            "browse.html",
            has_pairing=has_pairing,
            q=q,
            folder=folder,
            picking=picking,
            here=here,
            picker_ready=settings.picker_configured,
            **pager,
            **data,
        )

    async def picker_session(request: Request) -> Response:
        if not settings.picker_configured:
            return JSONResponse({"error": "picker_not_configured"}, status_code=404)
        record = await blocking(ctx.vault.owner)
        if not record or not record.get("t"):
            return JSONResponse({"error": "sign_in_required"}, status_code=401)
        assert settings.google_oauth_client_id is not None
        assert settings.google_oauth_client_secret is not None
        try:
            token = await blocking(
                refresh_access_token,
                settings.google_oauth_client_id.get_secret_value(),
                settings.google_oauth_client_secret.get_secret_value(),
                record["t"],
            )
        except OAuthError as exc:
            logger.warning("picker token refresh failed")
            return JSONResponse({"error": str(exc)}, status_code=502)
        return JSONResponse(
            {
                "access_token": token,
                "api_key": settings.google_picker_api_key,
                "app_id": settings.google_cloud_project_number,
            }
        )

    async def grant(request: Request, form: dict[str, str]) -> Response:
        file_id = validate_drive_id(form.get("file_id"))
        next_url = safe_next(form.get("next"))
        try:
            entry = await blocking(ctx.grants().grant, file_id)
        except GrantError as exc:
            return action_done(request, "error", str(exc), next_url)
        what = f"\u201c{entry.name}\u201d"
        if entry.id != file_id:
            what += ", the shortcut\u2019s target,"
        return action_done(request, "ok", f"Allowed {what} for the assistant.", next_url)

    async def revoke(request: Request, form: dict[str, str]) -> Response:
        file_id = validate_drive_id(form.get("file_id"))
        next_url = safe_next(form.get("next"))
        grants = ctx.grants()
        entry = await blocking(ctx.allowlist.get, file_id)
        try:
            await blocking(grants.revoke, file_id)
        except GrantError as exc:
            gone = await blocking(lambda: ctx.allowlist.get(file_id) is None)
            return action_done(request, "error", str(exc), next_url, changed=gone)
        root = ctx.visible_root_folder_id()
        extra = {root: "the folder set on the server"} if root else None
        cover = await still_covered(grants, file_id, extra)
        name = (entry.name if entry else "") or "it"
        if cover is None:
            message = f"Removed “{name}”. The assistant can no longer use it."
        elif cover:
            message = (
                f"Removed “{name}”, but the assistant can still use it "
                f"because “{cover}” is allowed."
            )
        else:
            message = (
                f"Removed “{name}”. If a folder above it is allowed, "
                "the assistant can still use it through that folder."
            )
        return action_done(request, "ok", message, next_url)

    async def still_covered(
        grants: GrantService, file_id: str, extra: dict[str, str] | None = None
    ) -> str | None:
        """Name of an allowed folder that still includes `file_id`.

        None means no folder on the list includes it. An empty string means Drive could
        not be asked; only the wording depends on this, so the completed removal is not
        turned into an error, and the message does not claim the item is unreachable.
        """
        try:
            found = await blocking(grants.covering_entry, file_id, extra)
        except Exception as exc:
            report_exception(exc, where="covering_entry")
            return ""
        return found[1] if found else None

    async def share_add(request: Request, form: dict[str, str]) -> Response:
        file_id = validate_drive_id(form.get("file_id"))
        next_url = safe_next(form.get("next") or "/sharing")
        try:
            entry = await blocking(ctx.ext_grants().grant, file_id)
        except GrantError as exc:
            return action_done(request, "error", str(exc), next_url)
        return action_done(
            request,
            "ok",
            f"Shared \u201c{entry.name}\u201d with the assistants of people you are paired with.",
            next_url,
        )

    async def share_audience(request: Request, form: dict[str, str]) -> Response:
        """Who may read one item on the Sharing list, and until when."""
        file_id = validate_drive_id(form.get("file_id"))
        next_url = safe_next(form.get("next") or "/sharing?tab=by-me")
        email = str(request.session.get("owner") or "")
        chosen = [str(v) for v in (await request.form()).getlist("person")]
        try:
            expires_at = _end_of_day(form.get("expires_on") or "")
        except ValueError:
            return action_done(
                request, "error", "Pick a valid end date, or leave it empty.", next_url
            )
        peers = await blocking(ctx.mailbox.active_peers, email) if ctx.mailbox else []
        if form.get("who") == "people":
            # Only people you are paired with now can be named.
            people = tuple(p for p in peers if p in {c.strip().lower() for c in chosen})
            audience: str | tuple[str, ...] = people
        else:
            audience = AUDIENCE_LINKED
        try:
            entry = await blocking(ctx.ext_grants().set_audience, file_id, audience, expires_at)
        except GrantError as exc:
            return action_done(request, "error", str(exc), next_url)
        who = (
            "everyone you are paired with" if entry.for_everyone else ", ".join(entry.audience)  # type: ignore[arg-type]
        )
        until = f" until {entry.expires_at[:10]}" if entry.expires_at else ""
        return action_done(
            request, "ok", f"“{entry.name}” is now shared with {who}{until}.", next_url
        )

    async def share_remove(request: Request, form: dict[str, str]) -> Response:
        file_id = validate_drive_id(form.get("file_id"))
        next_url = safe_next(form.get("next") or "/sharing")
        ext_grants = ctx.ext_grants()
        try:
            await blocking(ext_grants.revoke, file_id)
        except GrantError as exc:
            ext = ctx.ext_allowlist
            gone = ext is not None and await blocking(lambda: ext.get(file_id) is None)
            return action_done(
                request,
                "error",
                str(exc).replace("allowlist", "shared list"),
                next_url,
                changed=gone,
            )
        cover = await still_covered(ext_grants, file_id)
        if cover is None:
            message = "Stopped sharing. Other people's assistants can no longer read it."
        elif cover:
            message = (
                "Stopped sharing it on its own, but other people's assistants can still "
                f"read it because “{cover}” is on your Sharing list."
            )
        else:
            message = (
                "Stopped sharing it on its own. If a folder above it is on your Sharing "
                "list, other people's assistants can still read it through that folder."
            )
        return action_done(request, "ok", message, next_url)

    async def sharing(request: Request) -> Response:
        if ctx.ext_allowlist is None:
            return render(request, "error.html", 404, message="Sharing is not set up.")
        email = str(request.session.get("owner") or "")

        def gather() -> dict[str, Any]:
            peers = ctx.mailbox.active_peers(email) if ctx.mailbox is not None else []
            return {
                "entries": ctx.ext_allowlist.entries(),
                "peers": peers,
                "drive_connected": ctx.drive_connected(),
            }

        data = await blocking(gather)
        rows = sorted(data["entries"].values(), key=lambda e: e.granted_at, reverse=True)
        return render(
            request,
            "sharing.html",
            rows=rows,
            peers=data["peers"],
            describe_mime=describe_mime,
            drive_connected=data["drive_connected"],
        )

    # ---- shared with me ------------------------------------------------
    # The receiving side of Sharing: what paired people let this person read, across
    # every source, browsable to any depth. Every call runs the same guest checks as the
    # MCP tools (pairing active, item on the owner's shared list, read-only), and is
    # recorded on the owner's activity log as "guest:<you> (dashboard)".

    def shared_error(request: Request, exc: SharedAccessError) -> Response:
        status = {
            "invalid_input": 400,
            "owner_unavailable": 503,
            "no_bytes": 404,
        }.get(exc.code, 403)
        message = exc.message
        if exc.code == "own_drive":
            # The MCP wording names tools. A person opens their own files from Browse.
            message = "This is in your own Drive. Open it from Browse."
        elif exc.code == "invalid_input" and ("_shared_" in message or "read_file" in message):
            # Drive's wording for an assistant (it names tools). Say it for a person.
            message = (
                "This item can't be opened that way. If it is a folder, open it from the list."
            )
        return render(request, "shared_error.html", status, message=message, code=exc.code)

    def shared_args(request: Request) -> tuple[Any, str, str | None]:
        """The source, owner and item id from the query string, checked for shape only.
        Whether the caller may see the item is decided by the source on every call."""
        source = ctx.shared_with_me.get(request.query_params.get("source") or "google_drive")
        if source is None:
            raise SharedAccessError("invalid_input", "That source is not available here.")
        owner = normalize_email(request.query_params.get("owner"))
        item = request.query_params.get("id") or None
        if item is not None and not _SHARED_ID.fullmatch(item):
            raise SharedAccessError("invalid_input", "That item id is not valid.")
        return source, owner, item

    async def shared_overview(request: Request) -> Response:
        if ctx.shared_with_me is None:
            return render(request, "error.html", 404, message="Sharing is not set up.")
        email = str(request.session.get("owner") or "")

        def gather() -> dict[str, Any]:
            peers = ctx.mailbox.active_peers(email) if ctx.mailbox is not None else []
            return {"people": ctx.shared_with_me.overview(email), "peers": peers}

        data = await blocking(gather)
        return render(request, "shared.html", **data)

    async def shared_search(request: Request) -> Response:
        if ctx.shared_with_me is None:
            return render(request, "error.html", 404, message="Sharing is not set up.")
        email = str(request.session.get("owner") or "")
        q = (request.query_params.get("q") or "").strip()
        if not q:
            return RedirectResponse("/sharing?tab=with-me", status_code=303)
        allowed = await blocking(
            allow, ctx.store, "shared_search", "user:" + email, SHARED_SEARCH_LIMIT, 60
        )
        if not allowed:
            # Each search reads every sharer's Drive; keep one person from using up theirs.
            return render(
                request,
                "error.html",
                429,
                message="Too many searches. Wait a minute and try again.",
            )
        try:
            results = await blocking(ctx.shared_with_me.search, email, q)
        except SharedAccessError as exc:
            return shared_error(request, exc)
        return render(request, "shared_search.html", q=q, results=results)

    async def shared_browse(request: Request) -> Response:
        if ctx.shared_with_me is None:
            return render(request, "error.html", 404, message="Sharing is not set up.")
        email = str(request.session.get("owner") or "")
        try:
            source, owner, folder = shared_args(request)
            listing = await blocking(source.list, email, owner, folder)
        except SharedAccessError as exc:
            return shared_error(request, exc)
        return render(
            request,
            "shared_browse.html",
            source=source,
            shared_owner=owner,
            listing=listing,
        )

    async def shared_open(request: Request) -> Response:
        if ctx.shared_with_me is None:
            return render(request, "error.html", 404, message="Sharing is not set up.")
        email = str(request.session.get("owner") or "")
        try:
            source, owner, item = shared_args(request)
            if item is None:
                raise SharedAccessError("invalid_input", "Pick an item to open.")
            doc = await blocking(source.open, email, owner, item)
        except SharedAccessError as exc:
            return shared_error(request, exc)
        if doc.node.is_container:
            return RedirectResponse(
                shared_href("browse", source.key, owner, doc.node.id), status_code=303
            )
        return render(request, "shared_item.html", source=source, shared_owner=owner, doc=doc)

    async def shared_download(request: Request) -> Response:
        if ctx.shared_with_me is None:
            return render(request, "error.html", 404, message="Sharing is not set up.")
        email = str(request.session.get("owner") or "")
        try:
            source, owner, item = shared_args(request)
            if item is None:
                raise SharedAccessError("invalid_input", "Pick an item to download.")
            got = await blocking(source.download, email, owner, item)
        except SharedAccessError as exc:
            return shared_error(request, exc)
        # Never served inline: the bytes come from another person and this is our origin.
        # Cache-Control: no-store and nosniff come from the security headers middleware.
        return Response(
            got.data,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": attachment_disposition(got.filename),
                "X-Download-Truncated": "1" if got.truncated else "0",
            },
        )

    async def access(request: Request) -> Response:
        def gather() -> dict[str, Any]:
            return {
                "entries": ctx.allowlist.entries(),
                "bot": ctx.bot_status(),
                "drive_connected": ctx.drive_connected(),
            }

        data = await blocking(gather)
        rows = sorted(data["entries"].values(), key=lambda e: e.granted_at, reverse=True)

        def overlaps() -> dict[str, str]:
            # An entry inside another allowed folder: removing it alone changes nothing,
            # so the list says so. Bounded, since each check walks up the folder tree.
            found: dict[str, str] = {}
            if not data["drive_connected"] or len(rows) < 2:
                return found
            grants = ctx.grants()
            for entry in rows[:COVER_CHECK_LIMIT]:
                try:
                    cover = grants.covering_entry(entry.id)
                except Exception:
                    return found
                if cover and cover[0] != entry.id:
                    found[entry.id] = cover[1]
            return found

        covered = await blocking(overlaps)
        return render(
            request,
            "access.html",
            covered=covered,
            rows=rows,
            root_folder_id=ctx.visible_root_folder_id(),
            describe_mime=describe_mime,
            bot=data["bot"],
            drive_connected=data["drive_connected"],
        )

    def my_app_names() -> dict[str, str]:
        if ctx.mcp_oauth is None:
            return {}
        return app_names(ctx.mcp_oauth.list_grants(current_actor.get()))

    async def requests_page(request: Request) -> Response:
        reqs = await blocking(ctx.requests.recent, 100)
        pending = [r for r in reqs if r.status == PENDING]
        decided = [r for r in reqs if r.status != PENDING]
        apps = await blocking(my_app_names)
        return render(request, "requests.html", pending=pending, decided=decided, apps=apps)

    def request_elsewhere(rid: str, email: str | None) -> bool:
        """Whether this request id belongs to another signed-in person. Ids are 192 random
        bits, so this only ever matches a link someone was sent. It says nothing about whose
        request it is."""
        if ctx.directory is None:
            return False
        for person in ctx.directory.known_users():
            if person == email:
                continue
            if AccessRequests(ctx.directory.store_for(person)).get(rid) is not None:
                return True
        return False

    async def missing_request(request: Request, rid: str) -> Response:
        email = current_actor.get()
        if await blocking(request_elsewhere, rid, email):
            return render(
                request,
                "error.html",
                403,
                title="This request is for a different account",
                message=(
                    f"This request isn\u2019t for {email}. Sign in with the Google account "
                    "that owns this assistant to approve or deny it."
                ),
                actions=[
                    {
                        "label": "Switch account",
                        "logout_next": f"/requests/{rid}",
                        "primary": True,
                    },
                    {"label": "All requests", "href": "/requests"},
                ],
            )
        return render(
            request,
            "error.html",
            404,
            title="Request not found",
            message=(
                "This request doesn\u2019t exist or has expired. Requests expire after 7 days."
            ),
            actions=[
                {"label": "All requests", "href": "/requests", "primary": True},
                {"label": "Back to Overview", "href": "/"},
            ],
        )

    def paired_sharer(file_id: str) -> str | None:
        """A paired person whose Sharing list covers this id (a request filed before
        read_file pointed assistants at read_shared_file). Uses the same guard as a guest
        read, so a file inside a shared folder counts, not only the exact shared id."""
        me = current_actor.get()
        if ctx.sharer_of is not None:
            return ctx.sharer_of(me, file_id) if me else None
        if ctx.mailbox is None or ctx.ext_allowlist is None or ctx.directory is None:
            return None
        for peer in ctx.mailbox.active_peers(me):
            store = ctx.directory.store_for(peer)
            entry = Allowlist(store, EXTERNAL_ALLOWLIST_KEY).get(file_id)
            if entry is not None and entry.readable_by(me):
                return peer
        return None

    async def request_detail(request: Request) -> Response:
        rid = request.path_params["rid"]
        req = await blocking(ctx.requests.get, rid)
        if req is None:
            return await missing_request(request, rid)
        options = []
        owner_meta = None
        drive_error = False
        shared_by = None
        if req.file_id and req.status == PENDING:
            grants = ctx.grants()
            try:
                options = await blocking(grants.approval_options, req)
                owner_meta = await blocking(grants.owner_meta, req.file_id)
            except (InvalidInputError, OwnerNotConnectedError):
                raise
            except Exception as exc:
                report_exception(exc, where="request")
                options = []
                owner_meta = None
                drive_error = True
            if owner_meta is None and not drive_error:
                shared_by = await blocking(paired_sharer, req.file_id)
        return render(
            request,
            "request.html",
            req=req,
            options=options,
            owner_meta=owner_meta,
            drive_error=drive_error,
            shared_by=shared_by,
            apps=await blocking(my_app_names),
            picker_ready=settings.picker_configured,
            describe_mime=describe_mime,
        )

    async def request_approve(request: Request, form: dict[str, str]) -> Response:
        rid = request.path_params["rid"]
        req = await blocking(ctx.requests.get, rid)
        if req is None:
            return await missing_request(request, rid)
        target = form.get("target_id") or req.file_id
        if not target:
            flash(request, "error", "Pick an item to share first.")
            return RedirectResponse(f"/files?request={quote(req.id)}", status_code=303)
        try:
            entry = await blocking(ctx.grants().approve, req, validate_drive_id(target))
            flash(request, "ok", f"Approved: shared \u201c{entry.name}\u201d with the assistant.")
        except GrantError as exc:
            flash(request, "error", str(exc))
        return RedirectResponse(f"/requests/{quote(req.id)}", status_code=303)

    async def request_deny(request: Request, form: dict[str, str]) -> Response:
        rid = request.path_params["rid"]
        req = await blocking(ctx.requests.get, rid)
        if req is None:
            return await missing_request(request, rid)
        try:
            await blocking(ctx.grants().deny, req)
            flash(request, "ok", "Request denied.")
        except GrantError as exc:
            flash(request, "error", str(exc))
        return RedirectResponse(f"/requests/{quote(req.id)}", status_code=303)

    def activity_names(records: list[dict[str, Any]]) -> dict[str, Any]:
        """Names for the ids on this page, from what this person already has: their two
        lists, their requests, and (for a few ids) their own Drive. The log keeps ids only."""
        names: dict[str, str] = {}
        for entry in ctx.allowlist.entries().values():
            if entry.name:
                names[entry.id] = entry.name
        if ctx.ext_allowlist is not None:
            for entry in ctx.ext_allowlist.entries().values():
                if entry.name:
                    names.setdefault(entry.id, entry.name)
        request_names: dict[str, str] = {}
        for req in ctx.requests.recent(300):
            if req.file_id and req.file_name:
                names.setdefault(req.file_id, req.file_name)
            if req.granted_id and req.granted_name:
                names.setdefault(req.granted_id, req.granted_name)
            label = req.granted_name or req.file_name or req.description
            if label:
                request_names[req.id] = str(label)
        unknown = [i for i in item_ids(records) if i not in names][:ACTIVITY_LOOKUPS]
        if unknown and ctx.drive_connected():
            # Under a limited (drive.file) sign-in Google also answers 404 for real files
            # this app never opened, so a 404 proves nothing: don't call them missing.
            limited = ctx.reconsent_needed()
            try:
                drive = ctx.owner_drive()
                for item in unknown:
                    try:
                        meta = drive.get_file(item, fields="id,name")
                    except DriveNotFoundError:
                        if not limited:
                            names[item] = MISSING
                        continue
                    if meta.get("name"):
                        names[item] = str(meta["name"])
            except Exception:
                logger.warning("activity name lookup failed", exc_info=True)
        return {"names": names, "request_names": request_names, "apps": my_app_names()}

    async def activity(request: Request) -> Response:
        view = request.query_params.get("view") or "all"
        if view not in ACTIVITY_FILTERS:
            view = "all"
        show_checks = request.query_params.get("checks") == "1"
        try:
            limit = int(request.query_params.get("show") or ACTIVITY_PAGE)
        except ValueError:
            limit = ACTIVITY_PAGE
        limit = max(ACTIVITY_PAGE, min(limit, 500))
        records = await blocking(ctx.activity.recent)
        rows = [describe(r) for r in records]
        shown_ids = [i for i, row in enumerate(rows) if matches(row, view, show_checks)]
        page = shown_ids[:limit]
        lookup = await blocking(activity_names, [records[i] for i in page])
        page_rows = [
            describe(records[i], lookup["names"], lookup["request_names"], lookup["apps"])
            for i in page
        ]
        counts = {k: sum(1 for r in rows if matches(r, k, show_checks)) for k in ACTIVITY_FILTERS}

        def href(**changes: Any) -> str:
            params = {"view": view, "checks": "1" if show_checks else "", "show": ""}
            params.update({k: str(v) for k, v in changes.items()})
            pairs = [(k, v) for k, v in params.items() if v and not (k == "view" and v == "all")]
            return "/activity" + (f"?{urlencode(pairs)}" if pairs else "")

        return render(
            request,
            "activity.html",
            rows=group_repeats(page_rows),
            total=len(records),
            more_href=href(show=limit + ACTIVITY_PAGE) if len(shown_ids) > limit else None,
            view=view,
            filters=[(k, label, href(view=k), counts[k]) for k, label in ACTIVITY_FILTERS.items()],
            show_checks=show_checks,
            hidden_checks=sum(1 for r in rows if r.polling),
            checks_href=href(checks="" if show_checks else "1"),
        )

    async def not_found(request: Request) -> Response:
        return render(request, "error.html", 404, message="Page not found.")

    async def admin_page(request: Request) -> Response:
        email = session_user(request)
        if email != settings.owner_email:
            return render(request, "error.html", 404, message="Page not found.")
        reset = current_actor.set(email)
        try:
            await remember_pending(request)
            people = await blocking(_directory_rows)
        finally:
            current_actor.reset(reset)
        return render(request, "admin.html", people=people)

    def _directory_rows() -> list[dict[str, Any]]:
        if ctx.directory is None:
            return []
        rows: list[dict[str, Any]] = []
        for person in ctx.directory.known_users():
            grants = ctx.mcp_oauth.list_grants(person) if ctx.mcp_oauth else []
            # The sign-in index is newer than some accounts, so its date can be later
            # than an app the person connected. Show the earliest date we know of.
            known = [ctx.directory.created_at(person), *(g.created_at for g in grants)]
            moments = [(parse_ts(v), v) for v in known if v]
            earliest = min((m for m in moments if m[0] is not None), default=None)
            rows.append(
                {
                    "email": person,
                    "created_at": earliest[1] if earliest else None,
                    "grants": grants,
                }
            )
        return rows

    # ---- MCP OAuth consent (Grok Bot / other remote clients) ------------

    def _oauth_error(request: Request, exc: AuthorizeError, *, from_form: bool = False) -> Response:
        if exc.redirect_uri and ctx.mcp_oauth is not None:
            try:
                target = ctx.mcp_oauth.error_redirect(exc)
            except AuthorizeError:
                target = None
            if target is not None:
                # A form POST's redirect chain is checked against form-action. Stay on
                # this origin and let the next page navigate to the client.
                if from_form:
                    return _parked_redirect(request, target)
                return RedirectResponse(target, status_code=303)
        status = 403 if exc.error == "access_denied" else 400
        return render(request, "error.html", status, message=exc.description)

    def _parked_redirect(request: Request, url: str) -> Response:
        assert ctx.mcp_oauth is not None
        try:
            ticket = ctx.mcp_oauth.park_completion(url, str(request.session.get("owner") or ""))
        except AuthorizeError as exc:
            return render(request, "error.html", 400, message=exc.description)
        return RedirectResponse("/oauth/continue?" + urlencode({"ticket": ticket}), status_code=303)

    def _completion_page(url: str) -> HTMLResponse:
        safe = html.escape(url, quote=True)
        body = (
            "<!doctype html><html><head><meta charset=utf-8>"
            f'<meta http-equiv="refresh" content="0;url={safe}">'
            "<title>Returning to the app</title></head><body>"
            "<p>Returning to the app.</p>"
            f'<p><a href="{safe}">Continue</a></p>'
            "</body></html>"
        )
        return HTMLResponse(body)

    async def oauth_authorize(request: Request) -> Response:
        if ctx.mcp_oauth is None:
            return render(request, "error.html", 404, message="OAuth is not configured.")
        try:
            pending = ctx.mcp_oauth.parse_authorize(request.query_params)
        except AuthorizeError as exc:
            return _oauth_error(request, exc)
        signed_in = session_user(request)
        if request.session.get("owner") and not signed_in:
            return render(
                request,
                "error.html",
                403,
                message="This Google account is not allowed to connect apps.",
            )
        if not signed_in:
            target = request.url.path
            if request.url.query:
                target += "?" + request.url.query
            return RedirectResponse(f"/login?{urlencode({'next': target})}", status_code=303)
        reset = current_actor.set(signed_in)
        try:
            if not await blocking(ctx.drive_connected):
                # An assistant can only be allowed once there is something to reach.
                return connect_redirect(request)
            # The form carries this id back, so Allow only ever approves the request this
            # page describes. A second authorize request in another tab replaces it.
            consent_id = secrets.token_urlsafe(16)
            request.session["mcp_auth"] = {**pending.to_dict(), "consent_id": consent_id}
            await remember_pending(request)
            return_host = urlsplit(pending.redirect_uri).hostname or pending.redirect_uri
            here = request.url.path + ("?" + request.url.query if request.url.query else "")
            return render(
                request,
                "consent.html",
                client_name=pending.client_name,
                scope=SCOPE,
                requested_scope=pending.requested_scope,
                return_host=return_host,
                consent_id=consent_id,
                switch_next=here,
                mailbox_on=ctx.mailbox is not None,
                shared_on=ctx.shared_with_me is not None,
            )
        finally:
            current_actor.reset(reset)

    async def oauth_decide(request: Request, form: dict[str, str]) -> Response:
        if ctx.mcp_oauth is None:
            return render(request, "error.html", 404, message="OAuth is not configured.")
        decision = form.get("decision")
        if decision not in ("allow", "deny"):
            return render(request, "error.html", 400, message="Choose Allow or Deny.")
        raw = request.session.get("mcp_auth")
        if not isinstance(raw, dict):
            return render(
                request,
                "error.html",
                400,
                message="This approval expired. Start the connection again from the app.",
            )
        expected = str(raw.get("consent_id") or "")
        if not expected or not hmac.compare_digest(
            expected.encode(), str(form.get("consent_id") or "").encode()
        ):
            # The newer request stays pending: its own page can still be answered.
            return render(
                request,
                "error.html",
                400,
                message=(
                    "A newer connection request replaced this page, so nothing was approved. "
                    "Use the newest page, or start the connection again from the app."
                ),
            )
        try:
            pending = ctx.mcp_oauth.parse_authorize(QueryMapping(raw))
        except AuthorizeError as exc:
            request.session.pop("mcp_auth", None)
            return _oauth_error(request, exc, from_form=True)
        request.session.pop("mcp_auth", None)
        try:
            if decision == "deny":
                audit_owner("oauth_deny", client=pending.client_name)
                target = ctx.mcp_oauth.deny(pending)
            else:
                audit_owner("oauth_approve", client=pending.client_name)
                target = ctx.mcp_oauth.approve(str(request.session.get("owner")), pending)
        except AuthorizeError as exc:
            return _oauth_error(request, exc, from_form=True)
        return _parked_redirect(request, target)

    async def oauth_continue(request: Request) -> Response:
        if ctx.mcp_oauth is None:
            return render(request, "error.html", 404, message="OAuth is not configured.")
        url = ctx.mcp_oauth.take_completion(
            request.query_params.get("ticket") or "", str(request.session.get("owner") or "")
        )
        if url is None:
            return render(
                request,
                "error.html",
                400,
                message="This return link expired. Start the connection again from the app.",
            )
        return _completion_page(url)

    def assistant_rows(email: str, links: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Connected assistants with their wake-up, for Settings. Two connections can share
        a name (two "Cursor"s), so each row also says which of your assistants it is
        paired with, when it was added and last used, and a short id that never changes."""
        box = ctx.mailbox
        grants = ctx.mcp_oauth.list_grants(email) if ctx.mcp_oauth else []
        if links is None:
            links = box.list_links(email)["links"] if box is not None else []
        # Who each assistant talks to: your own assistants it is paired with (a grant
        # can be in several pairings). Other people's assistants never reach yours.
        names = {g.id: f"{g.client_name} …{g.id[-5:]}" for g in grants}
        mates: dict[str, list[dict[str, Any]]] = {}
        for link in links:
            status = link["status"]
            if not link.get("same_account"):
                continue
            if status not in ("active", "pending_approval"):
                continue
            (grant_a, grant_b), (label_a, label_b) = link["grant_ids"], link["assistants"]
            for me, other, label in ((grant_a, grant_b, label_b), (grant_b, grant_a, label_a)):
                mates.setdefault(str(me), []).append(
                    {
                        "name": names.get(str(other), label),
                        "pending": status == "pending_approval",
                    }
                )
        wake_on = box is not None and bool(box.get_webhook(email, "").get("available"))
        # One row per (pairing, assistant): an assistant in two pairings has two senders.
        missing_rows = box.missing_wakeups(email) if wake_on else []
        rows = []
        for g in grants:
            rows.append(
                {
                    "id": g.id,
                    "short_id": g.id[-5:],
                    "name": g.client_name,
                    "created_at": g.created_at,
                    "last_used": g.last_used,
                    "paired_with": ", ".join(m["name"] for m in mates.get(g.id, [])) or None,
                    "mates": mates.get(g.id, []),
                    "hook": box.get_webhook(email, g.id) if wake_on else None,
                }
            )
        return {
            "assistants": rows,
            "wake_on": wake_on,
            # Left from when mail from other people existed. It is never woken now; the
            # page only offers to move it to an assistant or remove it.
            "account_hook": box.get_webhook(email, "") if wake_on else None,
            "missing_wakeups": missing_rows,
        }

    async def bridge_page(request: Request) -> Response:
        if ctx.mailbox is None:
            return render(request, "error.html", 404, message="Pairing is not configured.")
        email = str(request.session.get("owner") or "")
        data = await blocking(ctx.mailbox.list_links, email)
        data["missing_wakeups"] = await blocking(ctx.mailbox.missing_wakeups, email)
        data["self_pairing"] = await blocking(ctx.mailbox.self_pairing, email)
        # Approving a pairing lets that person's assistant read the Sharing list, so each
        # card that asks for approval says what that list holds right now.
        ext = ctx.ext_allowlist
        data["sharing_on"] = ext is not None
        data["shared_items"] = []
        data["visible_to"] = {}
        if ext is not None:
            entries = await blocking(ext.entries)
            ordered = sorted(entries.values(), key=lambda e: e.granted_at, reverse=True)
            # A new person is never named on an item yet: approving shows them only what
            # is shared with everyone paired.
            data["shared_items"] = [e for e in ordered if e.for_everyone and not e.expired()]
            # Each person you share with: exactly what their assistant can read now.
            for link in data["links"]:
                peer = link.get("peer_email")
                if peer and not link.get("same_account"):
                    data["visible_to"][peer] = [e for e in ordered if e.readable_by(peer)]
        return render(request, "bridge.html", tab="people", **data)

    async def settings_page(request: Request) -> Response:
        email = str(request.session.get("owner") or "")

        def gather() -> dict[str, Any]:
            return {
                "rows": ctx.connection_rows(),
                **assistant_rows(email),
            }

        data = await blocking(gather)
        return render(
            request,
            "settings.html",
            mcp_url=f"{settings.app_base_url}/mcp",
            drive_connected=any(r["connected"] for r in data["rows"]),
            next="/settings",
            missing=settings.missing_settings(),
            store_kind=getattr(ctx.store, "kind", "custom"),
            root_folder_id=ctx.visible_root_folder_id(),
            picker_ready=settings.picker_configured,
            env_token_set=bool(
                settings.env_bot_refresh_token and session_user(request) == settings.owner_email
            ),
            **data,
        )

    async def files_page(request: Request) -> Response:
        request.state.allow_count = len(await blocking(ctx.allowlist.entries))
        if request.query_params.get("tab") == "allowed":
            return await access(request)
        return await browse(request)

    async def sharing_hub(request: Request) -> Response:
        tab = request.query_params.get("tab") or "people"
        if tab == "by-me":
            return await sharing(request)
        if tab == "with-me":
            return await shared_overview(request)
        return await bridge_page(request)

    def moved(path: str, **extra: str) -> Handler:
        """An old address. Keep its query string so bookmarks and links still land."""

        async def go(request: Request) -> Response:
            params = [(k, v) for k, v in request.query_params.multi_items() if k not in extra]
            params = [*extra.items(), *params]
            target = path + (f"?{urlencode(params)}" if params else "")
            return RedirectResponse(target, status_code=308)

        return go

    def _bridge_act(request: Request, link_id: str, action: str, purge: bool = False) -> str:
        email = str(request.session.get("owner") or "")
        if action == "cancel":
            ctx.mailbox.cancel_invite(email, link_id)
            return "Invite cancelled. That code no longer works."
        if action == "dismiss":
            ctx.mailbox.dismiss(email, link_id)
            return "Removed from your list."
        if action == "purge":
            count = ctx.mailbox.delete_messages(email, link_id)["purged_messages"]
            return f"Deleted {count} stored message{'' if count == 1 else 's'} for both of you."
        if action == "revoke":
            peer = next(
                (
                    link["peer_email"]
                    for link in ctx.mailbox.list_links(email)["links"]
                    if link["link_id"] == link_id
                ),
                None,
            )
            same = next(
                (
                    link.get("same_account", False)
                    for link in ctx.mailbox.list_links(email)["links"]
                    if link["link_id"] == link_id
                ),
                False,
            )
            ctx.mailbox.revoke(email, link_id, purge)
            if not same:
                message = (
                    "Pairing turned off. Neither of you can read the other's Sharing list "
                    "through it any more."
                )
                if peer and ctx.mailbox.is_linked(email, peer):
                    message += f" You still have another active pairing with {peer}."
                return message
            message = "Pairing turned off. Your two assistants can no longer message each other."
            if purge:
                return message + " Stored messages were deleted."
            return message + " Messages already delivered stay readable until they expire."
        result = ctx.mailbox.decide(email, link_id, action)
        same = next(
            (
                link.get("same_account", False)
                for link in ctx.mailbox.list_links(email)["links"]
                if link["link_id"] == link_id
            ),
            False,
        )
        if same and result["status"] == "active":
            return "Approved. Your two assistants can message each other now."
        if action == "deny" or result["status"] == "revoked":
            return "Pairing declined. Nothing is shared through it."
        if result["status"] == "active":
            return "You approved. You can now share documents with each other."
        return "You approved. Nothing is shared until the other person approves."

    async def bridge_decide(request: Request, form: dict[str, str]) -> Response:
        if ctx.mailbox is None:
            return render(request, "error.html", 404, message="The mailbox is not configured.")
        link_id = request.path_params["link_id"]
        action = request.path_params["action"]
        if action not in ("approve", "deny", "revoke", "cancel", "dismiss", "purge"):
            return render(request, "error.html", 404, message="That page is not available.")
        purge = form.get("purge") == "on"
        try:
            message = await blocking(_bridge_act, request, link_id, action, purge)
        except MailboxError as exc:
            flash(request, "error", exc.message)
        else:
            flash(request, "ok", message)
        return RedirectResponse("/sharing?tab=people", status_code=303)

    async def bridge_webhook(request: Request, form: dict[str, str]) -> Response:
        if ctx.mailbox is None:
            return render(request, "error.html", 404, message="The mailbox is not configured.")
        email = str(request.session.get("owner") or "")
        back = safe_next(form.get("next") or WAKE_HOME)
        # "account" (or "" from older pages) is the account-wide slot, left from when mail
        # from other people existed; otherwise one of this person's connected apps.
        raw_app = (form.get("app") or "").strip()
        app = "" if raw_app == "account" else raw_app
        from_app = (form.get("from_app") or "").strip()
        from_app = "" if from_app == "account" else from_app
        action = form.get("action")
        grants = await blocking(ctx.mcp_oauth.list_grants, email) if ctx.mcp_oauth else []
        ids = {g.id for g in grants}
        if (app and app not in ids) or (from_app and from_app not in ids):
            return action_done(request, "error", "That app is not connected.", back)
        if action in (None, "", "save") and not app:
            # The account slot never fires: mail only goes between your own assistants,
            # each to its own wake-up. Make the person say which assistant it starts.
            return action_done(
                request, "error", "Choose which assistant this wake-up starts.", back
            )
        if action == "primary":
            return action_done(
                request,
                "error",
                "Mail from other people is turned off, so there is nothing to answer.",
                back,
            )
        # A failed test wake still changes what the page shows (the last wake), so the
        # settings page refreshes those sections even when the test reports an error.
        changed: bool | None = None
        try:
            if action == "remove":
                await blocking(ctx.mailbox.clear_webhook, email, app)
                kind, message = "ok", "Wake-up removed. Mail still waits for check_messages."
            elif action == "test":
                result = await blocking(ctx.mailbox.test_webhook, email, app)
                changed = True
                if result.get("ok"):
                    kind, message = (
                        "ok",
                        f"Test wake sent (HTTP {result.get('http')}). The assistant should "
                        "start in a few seconds and find no new mail.",
                    )
                else:
                    code = f" (HTTP {result['http']})" if result.get("http") else ""
                    kind, message = (
                        "error",
                        f"Test wake failed{code}: {result.get('error')}. Check the URL and "
                        "key in the assistant that gave them to you, then save them again.",
                    )
            elif action == "move":
                await blocking(ctx.mailbox.move_webhook, email, app, from_app)
                kind, message = "ok", "Wake-up moved to that assistant. Its key moved with it."
            else:
                enabled = form.get("enabled", "true") != "false"
                await blocking(
                    ctx.mailbox.set_webhook,
                    email,
                    form.get("url") or "",
                    sender_key=form.get("sender_key") or None,
                    auth_scheme=form.get("auth_scheme") or "bearer",
                    enabled=enabled,
                    app=app,
                )
                kind, message = "ok", "Wake-up saved. Use Send test wake to check it works."
        except MailboxError as exc:
            kind, message, changed = "error", exc.message, False
        return action_done(request, kind, message, back, changed=changed)

    async def revoke_oauth_grant(request: Request, form: dict[str, str]) -> Response:
        grant_id = form.get("grant_id") or ""
        if ctx.mcp_oauth is None or not await blocking(
            ctx.mcp_oauth.revoke, grant_id, email=str(request.session.get("owner") or "")
        ):
            return action_done(
                request, "error", "That connection was not found.", "/settings#assistants"
            )
        audit_owner("oauth_revoke")
        return action_done(
            request,
            "ok",
            "Disconnected the assistant. Its tokens no longer work.",
            "/settings#assistants",
        )

    async def confirm_js(_: Request) -> Response:
        return Response(
            b"document.addEventListener('submit',function(e){"
            b"var f=e.target;if(!f||!f.getAttribute)return;"
            # ui.js asks for confirmation itself on background (data-async) forms.
            b"if(window.__asyncForms&&f.hasAttribute('data-async'))return;"
            b"var m=f.getAttribute('data-confirm');if(!m)return;"
            b"if(f.__confirmed){f.__confirmed=false;return;}"
            b"e.preventDefault();var s=e.submitter;"
            # ui.js's in-page dialog when it loaded, else the browser's own confirm().
            b"var ask=window.__askConfirm||function(x){"
            b"return Promise.resolve(window.confirm(x.getAttribute('data-confirm')));};"
            b"ask(f).then(function(ok){if(!ok)return;f.__confirmed=true;"
            b"if(f.requestSubmit)f.requestSubmit(s||undefined);else f.submit();});});",
            media_type="text/javascript",
            headers={"cache-control": "no-store"},
        )

    routes = [
        Route("/confirm.js", confirm_js, methods=["GET"]),
        Route("/login", safely(login), methods=["GET"]),
        Route("/auth/login", safely(auth_login), methods=["GET"]),
        Route("/auth/callback", safely(auth_callback), methods=["GET"]),
        Route("/connect", owner_only(connect_page), methods=["GET"]),
        Route("/connect/{key}", csrf_protected(connect_start), methods=["POST"]),
        Route("/connect/{key}/disconnect", csrf_protected(connect_remove), methods=["POST"]),
        Route("/logout", csrf_protected(logout), methods=["POST"]),
        Route("/", safely(home), methods=["GET"]),
        Route("/files", owner_only(files_page), methods=["GET"]),
        Route("/browse", moved("/files"), methods=["GET"]),
        Route("/picker/session", owner_only(picker_session), methods=["GET"]),
        Route("/grant", csrf_protected(grant), methods=["POST"]),
        Route("/revoke", csrf_protected(revoke), methods=["POST"]),
        Route("/access", moved("/files", tab="allowed"), methods=["GET"]),
        Route("/sharing", owner_only(sharing_hub), methods=["GET"]),
        Route("/settings", owner_only(settings_page), methods=["GET"]),
        Route("/sharing/add", csrf_protected(share_add), methods=["POST"]),
        Route("/sharing/remove", csrf_protected(share_remove), methods=["POST"]),
        Route("/sharing/audience", csrf_protected(share_audience), methods=["POST"]),
        Route("/shared", moved("/sharing", tab="with-me"), methods=["GET"]),
        Route("/shared/search", owner_only(shared_search), methods=["GET"]),
        Route("/shared/browse", owner_only(shared_browse), methods=["GET"]),
        Route("/shared/open", owner_only(shared_open), methods=["GET"]),
        Route("/shared/download", owner_only(shared_download), methods=["GET"]),
        Route("/requests", owner_only(requests_page), methods=["GET"]),
        Route("/requests/{rid}", owner_only(request_detail), methods=["GET"]),
        Route("/requests/{rid}/approve", csrf_protected(request_approve), methods=["POST"]),
        Route("/requests/{rid}/deny", csrf_protected(request_deny), methods=["POST"]),
        Route("/activity", owner_only(activity), methods=["GET"]),
        Route("/bridge", moved("/sharing", tab="people"), methods=["GET"]),
        Route("/bridge/webhook", csrf_protected(bridge_webhook), methods=["POST"]),
        Route("/bridge/{link_id}/{action}", csrf_protected(bridge_decide), methods=["POST"]),
        Route("/admin", safely(admin_page), methods=["GET"]),
        Route("/oauth/authorize", safely(oauth_authorize), methods=["GET"]),
        Route("/oauth/authorize", csrf_protected(oauth_decide), methods=["POST"]),
        Route("/oauth/continue", owner_only(oauth_continue), methods=["GET"]),
        Route("/oauth/grants/revoke", csrf_protected(revoke_oauth_grant), methods=["POST"]),
        *legal_routes(),
        Route("/{path:path}", owner_only(not_found), methods=["GET"]),
    ]
    app = Starlette(
        routes=routes,
        middleware=[
            Middleware(SecurityHeadersMiddleware, hsts=settings.secure_cookies),
            Middleware(
                SessionMiddleware,
                secret_key=settings.session_secret.get_secret_value(),
                session_cookie=SESSION_COOKIE,
                max_age=SESSION_MAX_AGE,
                same_site="lax",
                https_only=settings.secure_cookies,
            ),
        ],
    )
    app.state.owner_email = settings.owner_email
    # Mount("/") serves this app, so request.app is this app, not the outer one.
    app.state.dashboard = ctx
    return app


def normalize_page_token(value: str | None) -> str | None:
    """Keep an opaque Drive page token.

    Google's tokens are not a fixed alphabet (`~`, `!`, `*`, `|` all show up).
    Drop only blank, huge, or control-character values so a real Next link
    still addresses the same page.
    """
    if not value or len(value) > 1024:
        return None
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in value):
        return None
    return value


def browse_href(
    folder: str,
    *,
    q: str | None,
    request_id: str | None,
    page: str | None,
    prev: list[str],
) -> str:
    pairs: list[tuple[str, str]] = []
    if q:
        pairs.append(("q", q))
    else:
        pairs.append(("folder", folder or "root"))
        if page:
            pairs.append(("page", page))
        for item in prev:
            pairs.append(("prev", item))
    if request_id:
        pairs.append(("request", request_id))
    return "/files?" + urlencode(pairs)


def browse_pager(
    folder: str,
    *,
    q: str | None,
    request_id: str | None,
    page: str | None,
    prev: list[str],
    next_token: str | None,
) -> dict[str, str | None]:
    """Previous/Next links. Drive tokens are not reversible, so the previous stack is in the URL."""
    prev_href = None
    if page and not q:
        if prev:
            prev_href = browse_href(
                folder, q=None, request_id=request_id, page=prev[-1], prev=prev[:-1]
            )
        else:
            prev_href = browse_href(folder, q=None, request_id=request_id, page=None, prev=[])
    next_href = None
    if next_token and not q:
        nxt_prev = [*prev, page] if page else list(prev)
        next_href = browse_href(
            folder, q=None, request_id=request_id, page=next_token, prev=nxt_prev
        )
    return {"prev_href": prev_href, "next_href": next_href}


def shared_href(view: str, source: str, owner: str, item_id: str | None = None) -> str:
    """Link inside "Shared with me". view is "browse", "open" or "download"."""
    pairs = [("source", source), ("owner", owner)]
    if item_id:
        pairs.append(("id", item_id))
    return f"/shared/{view}?" + urlencode(pairs)


def attachment_disposition(filename: str) -> str:
    """Content-Disposition for a download. The name was typed by another person."""
    cleaned = (
        "".join(
            ch for ch in filename if ord(ch) >= 32 and ord(ch) != 127 and ch not in '"\\/;'
        ).strip()[:200]
        or "download"
    )
    ascii_name = cleaned.encode("ascii", "ignore").decode("ascii").strip() or "download"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(cleaned, safe='')}"


def human_size(size: int | None) -> str:
    if size is None:
        return ""
    value = float(size)
    for unit in ("bytes", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{int(value)} {unit}" if unit == "bytes" else f"{value:.1f} {unit}"
        value /= 1024
    return ""


def request_headline(
    req: Any, owner_meta: dict[str, Any] | None = None, apps: dict[str, str] | None = None
) -> str:
    """Plain-language summary of an access request. Technical fields stay out of this sentence."""
    who = assistant_label(getattr(req, "token_name", None), apps)
    name = None
    if owner_meta and owner_meta.get("name"):
        name = str(owner_meta["name"])
    elif getattr(req, "file_name", None):
        name = str(req.file_name)
    elif getattr(req, "description", None):
        name = str(req.description)
    item = name or "something in your Drive"
    tool = str(getattr(req, "tool", "") or "")
    actions = {
        "read_file": f"read {item}",
        "get_metadata": f"see the details of {item}",
        "list_folder": f"list {item}",
        "search_files": "search your Drive",
        "create_folder": f"create a folder in {item}",
        "create_doc": f"create a document in {item}",
        "upload_file": f"upload a file in {item}",
        "update_file_content": f"edit {item}",
        "rename_file": f"rename {item}",
        "trash_file": f"move {item} to trash",
        "request_access": f"use {item}",
    }
    action = actions.get(tool, f"use {item}")
    if str(getattr(req, "status", "pending") or "pending") != "pending":
        # Decided requests are history: "Grok asked to read notes.txt."
        return f"{who} asked to {action}."
    if tool == "request_access":
        return f"{who} is asking to {action}."
    return f"{who} wants to {action}."


def status_label(status: str | None) -> str:
    if not status:
        return ""
    labels = {
        "pending": "Waiting for you",
        "approved": "Approved",
        "denied": "Denied",
        "allow": "Allowed",
        "deny": "Denied",
        "error": "Error",
    }
    return labels.get(status, status.replace("_", " "))


def tool_label(tool: str) -> str:
    return {
        "read_file": "Read a file",
        "get_metadata": "See file details",
        "list_folder": "List a folder",
        "search_files": "Search",
        "create_folder": "Create a folder",
        "create_doc": "Create a document",
        "upload_file": "Upload a file",
        "update_file_content": "Edit a file",
        "rename_file": "Rename a file",
        "trash_file": "Move to trash",
        "request_access": "Ask for access",
    }.get(tool, "Use a file")


def describe_mime(mime: str) -> str:
    known = {
        FOLDER_MIME: "Folder",
        SHORTCUT_MIME: "Shortcut",
        "application/vnd.google-apps.document": "Google Doc",
        "application/vnd.google-apps.spreadsheet": "Google Sheet",
        "application/vnd.google-apps.presentation": "Google Slides",
        "application/vnd.google-apps.form": "Google Form",
        "application/vnd.google-apps.drawing": "Google Drawing",
        "application/pdf": "PDF",
        "application/msword": "Word",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "Word",
        "application/vnd.ms-excel": "Excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "Excel",
        "application/vnd.ms-powerpoint": "PowerPoint",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation": "PowerPoint",
        "application/rtf": "Rich text",
        "application/zip": "ZIP",
        "application/json": "JSON",
        "text/csv": "CSV",
    }
    if mime in known:
        return known[mime]
    if mime.startswith("image/"):
        return "Image"
    if mime.startswith("text/"):
        return "Text"
    if mime.startswith("video/"):
        return "Video"
    if mime.startswith("audio/"):
        return "Audio"
    sub = mime.rsplit("/", 1)[-1]
    # Vendor types like "vnd.foo.bar-baz" mean nothing to a person and break narrow layouts.
    return sub if sub and len(sub) <= 16 and not sub.startswith(("vnd.", "x-")) else "File"


_env.globals["request_headline"] = request_headline
_env.globals["status_label"] = status_label
_env.globals["tool_label"] = tool_label
_env.globals["describe_mime"] = describe_mime
_env.globals["shared_href"] = shared_href
_env.globals["human_size"] = human_size
_env.globals["assistant_label"] = assistant_label
_env.filters["when"] = when
_env.globals["icon_kind"] = icon_kind
