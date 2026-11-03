"""Owner web dashboard: Google sign-in, Drive browser, allowlist, access requests, activity.

Authentication is a signed, httponly, SameSite=Lax session cookie set only after a Google
sign-in as OWNER_EMAIL. MCP bearer tokens are never consulted here, and the MCP endpoint
never reads this cookie (it is a separate ASGI app behind BearerAuthMiddleware).
Every POST requires the per-session CSRF token, and a cross-origin `Origin` is refused.
"""

import hmac
import logging
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

import anyio.to_thread
from itsdangerous import BadSignature, URLSafeTimedSerializer
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .access import PENDING, AccessRequests
from .audit import audit_owner
from .config import Settings
from .drive_client import (
    DRIVE_SCOPE,
    FOLDER_MIME,
    SHORTCUT_MIME,
    DriveNotFoundError,
    LazyBotDriveClient,
    OwnerDriveClient,
)
from .grants import OWNER_FIELDS, GrantError, GrantService
from .oauth import OAuthClient, OAuthError
from .scope import InvalidInputError, clean_search_text, validate_drive_id
from .store import ActivityLog, Allowlist, TokenVault

logger = logging.getLogger(__name__)

SESSION_COOKIE = "sdm_session"
SESSION_MAX_AGE = 8 * 3600
STATE_MAX_AGE = 600
STATE_SALT = "sdm-oauth-state"
BROWSE_PAGE_SIZE = 200
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
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store"),
    (
        b"content-security-policy",
        b"default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        b"form-action 'self' https://accounts.google.com; frame-ancestors 'none'; "
        b"base-uri 'none'",
    ),
]


class OwnerNotConnectedError(Exception):
    """No stored refresh token for the owner (sign in again)."""


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
    _owner_client: tuple[str, OwnerDriveClient] | None = field(default=None, repr=False)

    def owner_drive(self) -> OwnerDriveClient:
        record = self.vault.owner()
        if not record or not record.get("t"):
            raise OwnerNotConnectedError
        token = record["t"]
        if self._owner_client is None or self._owner_client[0] != token:
            self._owner_client = (token, self.owner_drive_factory(token))
        return self._owner_client[1]

    def grants(self) -> GrantService:
        assert self.settings.bot_email is not None
        return GrantService(
            self.owner_drive,
            self.allowlist,
            self.requests,
            self.settings.bot_email,
            on_change=self.on_allowlist_change,
        )

    def bot_status(self) -> dict[str, Any]:
        if self.settings.env_bot_refresh_token:
            return {"connected": True, "source": "env", "email": self.settings.bot_email}
        record = self.vault.bot() if self.vault.enabled else None
        if record and record.get("t"):
            return {"connected": True, "source": "dashboard", "email": record.get("email")}
        return {"connected": False, "source": None, "email": None}

    def owner_connected(self) -> bool:
        return bool(self.vault.enabled and self.vault.owner())


async def blocking[T](fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    return await anyio.to_thread.run_sync(partial(fn, *args, **kwargs))


def safe_next(value: str | None) -> str:
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    return value


def origin_of(url: str) -> str:
    scheme, _, rest = url.partition("://")
    return f"{scheme}://{rest.split('/', 1)[0]}"


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                message.setdefault("headers", [])
                message["headers"] = list(message["headers"]) + SECURITY_HEADERS
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


def render(request: Request, template: str, status_code: int = 200, **ctx: Any) -> HTMLResponse:
    owner = request.session.get("owner")
    html = _env.get_template(template).render(
        request=request,
        owner=owner,
        csrf=_csrf_token(request) if owner else None,
        flashes=request.session.pop("flash", []) if owner else [],
        nav=request.url.path,
        **ctx,
    )
    return HTMLResponse(html, status_code=status_code)


def render_plain(template: str, status_code: int = 200, **ctx: Any) -> HTMLResponse:
    html = _env.get_template(template).render(owner=None, csrf=None, flashes=[], nav="", **ctx)
    return HTMLResponse(html, status_code=status_code)


def is_owner(request: Request, settings: Settings) -> bool:
    owner = request.session.get("owner")
    return bool(owner) and owner == settings.owner_email


Handler = Callable[[Request], Awaitable[Response]]


def build_dashboard(ctx: DashboardContext) -> Starlette:
    settings = ctx.settings
    missing = settings.dashboard_missing()
    if missing or ctx.oauth is None:

        async def not_configured(request: Request) -> Response:
            return render_plain("setup.html", status_code=503, missing=missing)

        return Starlette(
            routes=[Route("/{path:path}", not_configured, methods=["GET", "POST"])],
            middleware=[Middleware(SecurityHeadersMiddleware)],
        )

    assert settings.session_secret is not None and settings.app_base_url is not None
    oauth = ctx.oauth
    serializer = URLSafeTimedSerializer(settings.session_secret.get_secret_value(), STATE_SALT)
    app_origin = origin_of(settings.app_base_url)

    def owner_only(handler: Handler) -> Handler:
        async def wrapped(request: Request) -> Response:
            if not is_owner(request, settings):
                if request.method != "GET":
                    return Response("Sign in first.", status_code=403)
                target = request.url.path
                if request.url.query:
                    target += "?" + request.url.query
                return RedirectResponse(f"/login?{urlencode({'next': target})}", status_code=303)
            try:
                return await handler(request)
            except OwnerNotConnectedError:
                request.session.clear()
                return RedirectResponse("/login", status_code=303)
            except InvalidInputError as exc:
                return render(request, "error.html", 400, message=str(exc))
            except Exception:
                logger.exception("dashboard request failed")
                return render(
                    request, "error.html", 502, message="A Google Drive request failed. Try again."
                )

        return wrapped

    async def check_csrf(request: Request) -> dict[str, str] | None:
        origin = request.headers.get("origin")
        if origin is not None and origin != app_origin:
            return None
        form = await request.form()
        sent = form.get("csrf")
        expected = request.session.get("csrf")
        if not isinstance(sent, str) or not expected or not hmac.compare_digest(sent, expected):
            return None
        return {k: v for k, v in form.items() if isinstance(v, str)}

    def csrf_protected(
        handler: Callable[[Request, dict[str, str]], Awaitable[Response]],
    ) -> Handler:
        async def wrapped(request: Request) -> Response:
            form = await check_csrf(request)
            if form is None:
                audit_owner("csrf", "deny", path=request.url.path)
                return Response("CSRF check failed.", status_code=403)
            return await handler(request, form)

        return owner_only(wrapped)

    # ---- sign-in -------------------------------------------------------

    def start_oauth(request: Request, flow: str, login_hint: str | None) -> RedirectResponse:
        nonce = secrets.token_urlsafe(24)
        request.session["oauth_nonce"] = nonce
        state = serializer.dumps({"flow": flow, "nonce": nonce})
        return RedirectResponse(oauth.authorization_url(state, login_hint), status_code=303)

    async def login(request: Request) -> Response:
        if is_owner(request, settings):
            return RedirectResponse(safe_next(request.query_params.get("next")), status_code=303)
        return render(request, "login.html", next=safe_next(request.query_params.get("next")))

    async def auth_login(request: Request) -> Response:
        request.session["oauth_next"] = safe_next(request.query_params.get("next"))
        return start_oauth(request, "owner", settings.owner_email)

    async def auth_callback(request: Request) -> Response:
        params = request.query_params
        if params.get("error"):
            return render(request, "error.html", 400, message="Google sign-in was cancelled.")
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
        if flow not in ("owner", "bot"):
            return render(request, "error.html", 400, message="Invalid sign-in state.")
        if flow == "bot" and not is_owner(request, settings):
            return render(request, "error.html", 403, message="Sign in as the owner first.")
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
        expected = settings.owner_email if flow == "owner" else settings.bot_email
        action = "login" if flow == "owner" else "connect_bot"
        if not verified or email != expected:
            await blocking(oauth.revoke, tokens.refresh_token or tokens.access_token)
            audit_owner(action, "deny", reason="wrong_account")
            if flow == "owner":
                msg = "This Google account is not allowed to use this dashboard."
            else:
                msg = (
                    f"You signed in as {email or 'an unknown account'}, but the bot account is "
                    f"{settings.bot_email}. Sign in as the bot and try again."
                )
            return render(request, "error.html", 403, message=msg)
        if DRIVE_SCOPE not in tokens.scopes:
            await blocking(oauth.revoke, tokens.refresh_token or tokens.access_token)
            return render(
                request,
                "error.html",
                400,
                message="Google Drive access was not granted. Sign in again and tick the "
                "Drive checkbox on Google's consent screen.",
            )
        if not tokens.refresh_token:
            return render(
                request,
                "error.html",
                400,
                message="Google did not return a refresh token. Remove the app at "
                "myaccount.google.com/permissions and try again.",
            )

        if flow == "owner":
            await blocking(ctx.vault.set_owner, tokens.refresh_token, email)
            next_url = safe_next(request.session.get("oauth_next"))
            request.session.clear()
            request.session["owner"] = email
            request.session["csrf"] = secrets.token_urlsafe(32)
            audit_owner("login")
            return RedirectResponse(next_url, status_code=303)

        await blocking(ctx.vault.set_bot, tokens.refresh_token, email)
        if isinstance(ctx.bot_drive, LazyBotDriveClient):
            ctx.bot_drive.invalidate()
        audit_owner("connect_bot")
        note = ""
        if settings.env_bot_refresh_token:
            note = " (GOOGLE_OAUTH_REFRESH_TOKEN is also set and takes precedence.)"
        flash(request, "ok", f"Bot account {email} connected.{note}")
        return RedirectResponse("/", status_code=303)

    async def logout(request: Request, form: dict[str, str]) -> Response:
        audit_owner("logout")
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    async def connect_bot_page(request: Request) -> Response:
        status = await blocking(ctx.bot_status)
        return render(request, "connect_bot.html", bot=status, bot_email=settings.bot_email)

    async def connect_bot_start(request: Request, form: dict[str, str]) -> Response:
        return start_oauth(request, "bot", settings.bot_email)

    async def bot_disconnect(request: Request, form: dict[str, str]) -> Response:
        await blocking(ctx.vault.clear_bot)
        if isinstance(ctx.bot_drive, LazyBotDriveClient):
            ctx.bot_drive.invalidate()
        audit_owner("disconnect_bot")
        flash(request, "ok", "Stored bot connection removed.")
        return RedirectResponse("/connect-bot", status_code=303)

    # ---- pages -----------------------------------------------------------

    async def overview(request: Request) -> Response:
        def gather() -> dict[str, Any]:
            entries = ctx.allowlist.entries()
            reqs = ctx.requests.recent(100)
            return {
                "bot": ctx.bot_status(),
                "owner_connected": ctx.owner_connected(),
                "allow_count": len(entries),
                "pending_count": sum(1 for r in reqs if r.status == PENDING),
            }

        data = await blocking(gather)
        return render(
            request,
            "overview.html",
            missing=settings.missing_settings(),
            store_kind=getattr(ctx.store, "kind", "custom"),
            root_folder_id=settings.root_folder_id,
            mcp_url=f"{settings.app_base_url}/mcp",
            **data,
        )

    def browse_data(folder: str, q: str | None, page_token: str | None) -> dict[str, Any]:
        drive = ctx.owner_drive()
        root_id = str(drive.get_file("root", fields="id")["id"])
        entries = ctx.allowlist.entries()
        crumbs: list[dict[str, str]] = []
        covered_by: str | None = None
        next_token: str | None = None
        current: dict[str, Any] | None = None
        if q:
            term = clean_search_text(q)
            query = f"trashed=false and name contains '{term}'"
            resp = drive.list_files(query, fields=OWNER_FIELDS, page_size=100)
            items = resp.get("files", [])
        else:
            folder_id = root_id if folder == "root" else validate_drive_id(folder, "folder")
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
                name = "My Drive" if nid == root_id else str(node.get("name", ""))
                crumbs.insert(0, {"id": nid, "name": name})
                if covered_by is None and nid in entries:
                    covered_by = name
                parents = node.get("parents") or []
                if nid == root_id or not parents:
                    break
                try:
                    node = drive.get_file(str(parents[0]), fields=OWNER_FIELDS)
                except DriveNotFoundError:
                    node = None
            query = f"'{folder_id}' in parents and trashed=false"
            resp = drive.list_files(
                query, fields=OWNER_FIELDS, page_size=BROWSE_PAGE_SIZE, page_token=page_token
            )
            items = [i for i in resp.get("files", []) if folder_id in (i.get("parents") or [])]
            next_token = resp.get("nextPageToken")
        items.sort(key=lambda i: (i.get("mimeType") != FOLDER_MIME, str(i.get("name", "")).lower()))
        rows = []
        for item in items:
            iid = str(item["id"])
            mime = str(item.get("mimeType", ""))
            rows.append(
                {
                    "id": iid,
                    "name": str(item.get("name", "")),
                    "is_folder": mime == FOLDER_MIME,
                    "is_shortcut": mime == SHORTCUT_MIME,
                    "kind": describe_mime(mime),
                    "link": item.get("webViewLink"),
                    "granted": iid in entries,
                    "covered": covered_by is not None and iid not in entries,
                }
            )
        return {
            "rows": rows,
            "crumbs": crumbs,
            "covered_by": covered_by,
            "current": current,
            "current_granted": current is not None and str(current["id"]) in entries,
            "is_root": current is not None and str(current["id"]) == root_id,
            "next_token": next_token,
        }

    async def browse(request: Request) -> Response:
        folder = request.query_params.get("folder") or "root"
        q = (request.query_params.get("q") or "").strip()[:200] or None
        page_token = request.query_params.get("page") or None
        request_id = request.query_params.get("request") or None
        picking = None
        if request_id:
            picking = await blocking(ctx.requests.get, request_id)
            if picking is None or picking.status != PENDING:
                picking = None
        data = await blocking(browse_data, folder, q, page_token)
        here = request.url.path + ("?" + request.url.query if request.url.query else "")
        return render(
            request, "browse.html", q=q, folder=folder, picking=picking, here=here, **data
        )

    async def grant(request: Request, form: dict[str, str]) -> Response:
        file_id = validate_drive_id(form.get("file_id"))
        try:
            entry = await blocking(ctx.grants().grant, file_id)
            flash(request, "ok", f"Shared \u201c{entry.name}\u201d with the assistant.")
        except GrantError as exc:
            flash(request, "error", str(exc))
        return RedirectResponse(safe_next(form.get("next")), status_code=303)

    async def revoke(request: Request, form: dict[str, str]) -> Response:
        file_id = validate_drive_id(form.get("file_id"))
        try:
            await blocking(ctx.grants().revoke, file_id)
            flash(request, "ok", "Access revoked.")
        except GrantError as exc:
            flash(request, "error", str(exc))
        return RedirectResponse(safe_next(form.get("next")), status_code=303)

    async def access(request: Request) -> Response:
        entries = await blocking(ctx.allowlist.entries)
        rows = sorted(entries.values(), key=lambda e: e.granted_at, reverse=True)
        return render(
            request,
            "access.html",
            rows=rows,
            root_folder_id=settings.root_folder_id,
            describe_mime=describe_mime,
        )

    async def requests_page(request: Request) -> Response:
        reqs = await blocking(ctx.requests.recent, 100)
        pending = [r for r in reqs if r.status == PENDING]
        decided = [r for r in reqs if r.status != PENDING]
        return render(request, "requests.html", pending=pending, decided=decided)

    async def request_detail(request: Request) -> Response:
        rid = request.path_params["rid"]
        req = await blocking(ctx.requests.get, rid)
        if req is None:
            return render(request, "error.html", 404, message="Request not found or expired.")
        options = []
        owner_meta = None
        if req.file_id and req.status == PENDING:
            grants = ctx.grants()
            options = await blocking(grants.approval_options, req)
            owner_meta = await blocking(grants.owner_meta, req.file_id)
        return render(
            request,
            "request.html",
            req=req,
            options=options,
            owner_meta=owner_meta,
            describe_mime=describe_mime,
        )

    async def request_approve(request: Request, form: dict[str, str]) -> Response:
        rid = request.path_params["rid"]
        req = await blocking(ctx.requests.get, rid)
        if req is None:
            return render(request, "error.html", 404, message="Request not found or expired.")
        target = form.get("target_id") or req.file_id
        if not target:
            flash(request, "error", "Pick an item to share first.")
            return RedirectResponse(f"/browse?request={quote(req.id)}", status_code=303)
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
            return render(request, "error.html", 404, message="Request not found or expired.")
        try:
            await blocking(ctx.grants().deny, req)
            flash(request, "ok", "Request denied.")
        except GrantError as exc:
            flash(request, "error", str(exc))
        return RedirectResponse(f"/requests/{quote(req.id)}", status_code=303)

    async def activity(request: Request) -> Response:
        records = await blocking(ctx.activity.recent)
        return render(request, "activity.html", records=records)

    async def not_found(request: Request) -> Response:
        return render(request, "error.html", 404, message="Page not found.")

    routes = [
        Route("/login", login, methods=["GET"]),
        Route("/auth/login", auth_login, methods=["GET"]),
        Route("/auth/callback", auth_callback, methods=["GET"]),
        Route("/logout", csrf_protected(logout), methods=["POST"]),
        Route("/", owner_only(overview), methods=["GET"]),
        Route("/connect-bot", owner_only(connect_bot_page), methods=["GET"]),
        Route("/connect-bot", csrf_protected(connect_bot_start), methods=["POST"]),
        Route("/bot/disconnect", csrf_protected(bot_disconnect), methods=["POST"]),
        Route("/browse", owner_only(browse), methods=["GET"]),
        Route("/grant", csrf_protected(grant), methods=["POST"]),
        Route("/revoke", csrf_protected(revoke), methods=["POST"]),
        Route("/access", owner_only(access), methods=["GET"]),
        Route("/requests", owner_only(requests_page), methods=["GET"]),
        Route("/requests/{rid}", owner_only(request_detail), methods=["GET"]),
        Route("/requests/{rid}/approve", csrf_protected(request_approve), methods=["POST"]),
        Route("/requests/{rid}/deny", csrf_protected(request_deny), methods=["POST"]),
        Route("/activity", owner_only(activity), methods=["GET"]),
        Route("/{path:path}", owner_only(not_found), methods=["GET"]),
    ]
    return Starlette(
        routes=routes,
        middleware=[
            Middleware(SecurityHeadersMiddleware),
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


def describe_mime(mime: str) -> str:
    known = {
        FOLDER_MIME: "Folder",
        SHORTCUT_MIME: "Shortcut",
        "application/vnd.google-apps.document": "Google Doc",
        "application/vnd.google-apps.spreadsheet": "Google Sheet",
        "application/vnd.google-apps.presentation": "Google Slides",
        "application/pdf": "PDF",
    }
    if mime in known:
        return known[mime]
    if mime.startswith("image/"):
        return "Image"
    if mime.startswith("text/"):
        return "Text"
    return mime.rsplit("/", 1)[-1] or "File"
