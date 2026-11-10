"""Owner dashboard: sign-in, bot connection, CSRF, separation from /mcp, browse/grant/revoke."""

import re

import pytest

from scoped_drive_mcp.dashboard import SESSION_COOKIE
from scoped_drive_mcp.server import build_app
from scoped_drive_mcp.store import BOT_TOKEN_KEY, KEY_PREFIX, OWNER_TOKEN_KEY, MemoryStore
from tests.conftest import BASE_URL, BOT_EMAIL, OWNER_EMAIL, TOKENS, make_settings
from tests.dash import MCP_HEADERS, client, csrf, login, mcp_call, post, start_oauth

OWNER_PAGES = [
    "/browse",
    "/browse?folder=proj",
    "/access",
    "/requests",
    "/activity",
    "/connect-bot",
    "/requests/" + "A" * 32,
]
OWNER_POSTS = [
    "/grant",
    "/revoke",
    "/logout",
    "/connect-bot",
    "/bot/disconnect",
    "/requests/" + "A" * 32 + "/approve",
    "/requests/" + "A" * 32 + "/deny",
    "/oauth/grants/revoke",
]


@pytest.fixture
def c(p2_app):
    return client(p2_app)


@pytest.fixture
def owner_c(c):
    r = login(c)
    assert r.status_code == 303 and r.headers["location"] == "/"
    return c


# ---- logged out ----------------------------------------------------------------


@pytest.mark.parametrize("page", OWNER_PAGES)
def test_logged_out_pages_redirect_to_login(c, page: str) -> None:
    r = c.get(page)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login?next=")


@pytest.mark.parametrize("path", OWNER_POSTS)
def test_logged_out_posts_are_refused(c, world, path: str) -> None:
    r = c.post(path, data={"file_id": "proj", "csrf": "x"})
    assert r.status_code == 403
    assert world.files["proj"].permissions == []


def test_login_page_is_public(c) -> None:
    r = c.get("/login")
    assert r.status_code == 200 and "Sign in with Google" in r.text
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert 'href="/terms"' in r.text and 'href="/privacy"' in r.text
    # Google requires the data disclosure immediately before the consent button.
    assert r.text.index("Full access to Google Drive") < r.text.index("Sign in with Google")


def test_public_home_is_the_consent_screen_page(c) -> None:
    r = c.get("/")
    assert r.status_code == 200
    assert "gateway that sits in front of Google Drive" in r.text
    assert 'href="/privacy"' in r.text and 'href="/terms"' in r.text
    assert ">Privacy policy</a>" in r.text and ">Terms of service</a>" in r.text
    assert "set-cookie" not in {name.lower() for name in r.headers}


@pytest.mark.parametrize(
    ("path", "needle"),
    [
        ("/terms", "gateway that sits in front of Google Drive"),
        ("/privacy", "Google API Services User Data Policy"),
    ],
)
def test_legal_pages_are_public(c, path: str, needle: str) -> None:
    r = c.get(path)
    assert r.status_code == 200
    assert needle in r.text
    assert "set-cookie" not in {name.lower() for name in r.headers}
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


# ---- owner sign-in ---------------------------------------------------------------


def test_owner_login(c, oauth, memstore, p2_app) -> None:
    r = login(c)
    assert r.status_code == 303
    cookie = r.headers["set-cookie"].lower()
    assert SESSION_COOKIE in cookie
    assert "httponly" in cookie and "secure" in cookie and "samesite=lax" in cookie
    assert oauth.hints[-1] == OWNER_EMAIL
    assert c.get("/").status_code == 200
    # the refresh token is stored encrypted
    raw = memstore.get(KEY_PREFIX + OWNER_TOKEN_KEY)
    assert raw and "rt-owner" not in raw
    vault = p2_app.state.dashboard.vault
    assert vault.owner()["t"] == f"rt-{OWNER_EMAIL}"
    # and used for the owner's Drive
    assert c.get("/browse").status_code == 200
    assert p2_app.state.owner_tokens[-1] == f"rt-{OWNER_EMAIL}"


def test_login_redirects_back_to_next(c) -> None:
    r = c.get("/requests")
    assert r.headers["location"] == "/login?next=%2Frequests"
    state = start_oauth(c, "/auth/login?next=/requests")
    r = c.get("/auth/callback", params={"code": "owner-code", "state": state})
    assert r.headers["location"] == "/requests"


def test_login_next_cannot_redirect_offsite(c) -> None:
    state = start_oauth(c, "/auth/login?next=//evil.example.com/x")
    r = c.get("/auth/callback", params={"code": "owner-code", "state": state})
    assert r.headers["location"] == "/"


def test_unverified_account_cannot_sign_in(c, oauth, memstore) -> None:
    r = login(c, "unverified-owner-code")
    assert r.status_code == 403
    assert "not allowed" in r.text
    assert c.get("/browse").status_code == 303  # still logged out
    assert memstore.get(KEY_PREFIX + OWNER_TOKEN_KEY) is None
    assert oauth.revoked  # the unwanted token was revoked


def test_second_verified_account_can_sign_in(c, memstore, p2_app) -> None:
    r = login(c, "eve-code")
    assert r.status_code == 303
    assert c.get("/browse").status_code == 200
    # The admin's legacy key stays empty; eve's token is under her prefix.
    assert memstore.get(KEY_PREFIX + OWNER_TOKEN_KEY) is None
    raw = memstore.get(KEY_PREFIX + "u:eve@example.com:" + OWNER_TOKEN_KEY)
    assert raw and "rt-eve" not in raw
    assert p2_app.state.dashboard.directory.has_owner_refresh("eve@example.com")
    assert c.get("/admin").status_code == 404
    assert 'href="/admin"' not in c.get("/").text


def test_state_is_checked(c) -> None:
    state = start_oauth(c)
    r = c.get("/auth/callback", params={"code": "owner-code", "state": state + "x"})
    assert r.status_code == 400
    # a valid state from another browser (no matching nonce in this session) is refused
    other = client(c.app)
    other_state = start_oauth(other)
    r = c.get("/auth/callback", params={"code": "owner-code", "state": other_state})
    assert r.status_code == 400
    # a state is single-use
    r = other.get("/auth/callback", params={"code": "owner-code", "state": other_state})
    assert r.status_code == 303
    r = other.get("/auth/callback", params={"code": "owner-code", "state": other_state})
    assert r.status_code == 400


def test_google_error_param(c) -> None:
    assert c.get("/auth/callback", params={"error": "access_denied"}).status_code == 400


def test_drive_scope_required(c, oauth) -> None:
    oauth.scopes = frozenset({"openid", "email"})
    r = login(c)
    assert r.status_code == 400 and "Drive access was not granted" in r.text


def test_logout(owner_c) -> None:
    r = post(owner_c, "/logout")
    assert r.status_code == 303
    assert owner_c.get("/browse").status_code == 303


# HTML form POST is a non-cors navigation. These policies leave Origin as the
# document origin; `no-referrer` replaces it with the literal "null", which
# check_csrf rejects even when the session token is present.
_FORM_POST_KEEPS_ORIGIN = frozenset(
    {
        "same-origin",
        "origin",
        "origin-when-cross-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "no-referrer-when-downgrade",
    }
)
_LOGOUT_FORM = re.compile(
    r'<form class="inline" method="post" action="/logout">\s*'
    r'<input type="hidden" name="csrf" value="([^"]+)">'
)


def _browser_form_origin(policy: str) -> str:
    """Origin header a browser attaches to a same-origin HTML form POST under `policy`."""
    if policy in _FORM_POST_KEEPS_ORIGIN:
        return BASE_URL
    return "null"


def test_logout_form_post_as_the_browser(owner_c) -> None:
    """Sign out via the dashboard form, with the Origin a browser would send."""
    page = owner_c.get("/")
    assert page.status_code == 200
    match = _LOGOUT_FORM.search(page.text)
    assert match, "signed-in page has no logout form"
    origin = _browser_form_origin(page.headers["referrer-policy"])

    logged_out = owner_c.post("/logout", data={"csrf": match.group(1)}, headers={"Origin": origin})
    assert logged_out.status_code == 303, logged_out.text
    assert logged_out.headers["location"] == "/login"
    home = owner_c.get("/")
    assert home.status_code == 200 and "Privacy policy" in home.text
    assert "Sign out" not in home.text
    assert owner_c.get("/browse").headers["location"].startswith("/login")

    login(owner_c)
    denied = owner_c.post("/logout", headers={"Origin": origin})
    assert denied.status_code == 403
    assert denied.text == "CSRF check failed."
    assert owner_c.get("/").status_code == 200


def test_session_for_other_owner_is_ignored(p2_app, world, memstore, oauth) -> None:
    c = client(p2_app)
    login(c)
    cookie = c.cookies.get(SESSION_COOKIE)
    other = build_app(
        make_settings(root_folder_id=None, owner_email="someone-else@example.com"),
        world.as_user(BOT_EMAIL),
        store=memstore,
        owner_drive_factory=lambda t: world.as_user(OWNER_EMAIL),
        oauth=oauth,
    )
    c2 = client(other)
    c2.cookies.set(SESSION_COOKIE, cookie)
    assert c2.get("/browse").status_code == 303


# ---- bot connection ----------------------------------------------------------------


@pytest.fixture
def no_env_bot_app(world, memstore, oauth):
    built: list[str] = []

    def bot_factory(token: str):
        built.append(token)
        return world.as_user(BOT_EMAIL)

    app = build_app(
        make_settings(root_folder_id=None, google_oauth_refresh_token=None, allowlist_cache_ttl=0),
        store=memstore,
        owner_drive_factory=lambda t: world.as_user(OWNER_EMAIL),
        oauth=oauth,
        bot_drive_factory=bot_factory,
    )
    app.state.bot_tokens = built
    return app


def test_connect_bot_requires_owner(c) -> None:
    assert c.post("/connect-bot", data={"csrf": "x"}).status_code == 403


def test_connect_bot_requires_bot_email(no_env_bot_app, memstore, oauth) -> None:
    c = client(no_env_bot_app)
    login(c)
    for code in ("owner-code", "eve-code"):
        state = start_oauth(c, "/connect-bot", csrf=csrf(c, "/connect-bot"))
        assert oauth.hints[-1] == BOT_EMAIL
        r = c.get("/auth/callback", params={"code": code, "state": state})
        assert r.status_code == 403
        assert BOT_EMAIL in r.text
    assert memstore.get(KEY_PREFIX + BOT_TOKEN_KEY) is None
    assert c.get("/").status_code == 200  # the owner session survives


def test_connect_bot_flow_and_mcp_uses_stored_token(no_env_bot_app, memstore, world) -> None:
    c = client(no_env_bot_app)
    login(c)
    health = c.get("/health").json()
    assert health["bot_connected"] is False and health["owner_connected"] is True
    # before connecting, tools explain that the bot is missing
    result = mcp_call(c, "read_file", file_id="loose-doc")
    text = result["content"][0]["text"]
    assert result["isError"] and "not connected" in text and "Connect bot" in text

    state = start_oauth(c, "/connect-bot", csrf=csrf(c, "/connect-bot"))
    r = c.get("/auth/callback", params={"code": "bot-code", "state": state})
    assert r.status_code == 303
    raw = memstore.get(KEY_PREFIX + BOT_TOKEN_KEY)
    assert raw and "rt-bot" not in raw
    health = c.get("/health").json()
    assert health["bot_connected"] is True and health["bot_source"] == "dashboard"

    no_env_bot_app.state.dashboard.bot_drive.invalidate()
    post(c, "/grant", file_id="loose-doc")
    result = mcp_call(c, "read_file", file_id="loose-doc")
    assert result["isError"] is False
    assert result["structuredContent"]["content"] == "memo beta"
    assert no_env_bot_app.state.bot_tokens == [f"rt-{BOT_EMAIL}"]

    r = post(c, "/bot/disconnect")
    assert r.status_code == 303
    assert memstore.get(KEY_PREFIX + BOT_TOKEN_KEY) is None


def test_bot_session_does_not_become_owner(no_env_bot_app) -> None:
    c = client(no_env_bot_app)
    login(c)
    state = start_oauth(c, "/connect-bot", csrf=csrf(c, "/connect-bot"))
    c.get("/auth/callback", params={"code": "bot-code", "state": state})
    page = c.get("/")
    assert page.status_code == 200 and OWNER_EMAIL in page.text


# ---- CSRF -------------------------------------------------------------------------------


def test_csrf_required_on_every_post(owner_c, world) -> None:
    for path in (
        "/grant",
        "/revoke",
        "/logout",
        "/connect-bot",
        "/bot/disconnect",
        "/oauth/authorize",
        "/oauth/grants/revoke",
    ):
        assert owner_c.post(path, data={"file_id": "proj"}).status_code == 403
        assert owner_c.post(path, data={"file_id": "proj", "csrf": "wrong"}).status_code == 403
    assert world.files["proj"].permissions == []
    assert owner_c.get("/").status_code == 200  # logout without csrf did nothing


def test_cross_origin_post_refused(owner_c, world) -> None:
    token = csrf(owner_c)
    r = owner_c.post(
        "/grant",
        data={"csrf": token, "file_id": "proj"},
        headers={"Origin": "https://evil.example.com"},
    )
    assert r.status_code == 403
    assert world.files["proj"].permissions == []
    r = owner_c.post(
        "/grant", data={"csrf": token, "file_id": "proj"}, headers={"Origin": BASE_URL}
    )
    assert r.status_code == 303
    assert len(world.files["proj"].permissions) == 1


def test_csrf_token_rotates_on_login(c) -> None:
    login(c)
    first = csrf(c)
    post(c, "/logout")
    login(c)
    assert csrf(c) != first


# ---- separation of dashboard and /mcp --------------------------------------------------


@pytest.mark.parametrize("role", ["viewer", "admin"])
def test_bearer_tokens_do_not_open_the_dashboard(c, world, role: str) -> None:
    headers = {"Authorization": f"Bearer {TOKENS[role]}"}
    for page in OWNER_PAGES:
        r = c.get(page, headers=headers)
        assert r.status_code == 303 and r.headers["location"].startswith("/login")
    r = c.post("/grant", data={"file_id": "proj"}, headers=headers)
    assert r.status_code == 403
    assert world.files["proj"].permissions == []


def test_dashboard_cookie_does_not_open_mcp(owner_c) -> None:
    assert owner_c.cookies.get(SESSION_COOKIE)
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"},
        },
    }
    r = owner_c.post("/mcp", json=init, headers=MCP_HEADERS)
    assert r.status_code == 401
    r = owner_c.get("/mcp")
    assert r.status_code == 401


# ---- browse, grant, revoke ---------------------------------------------------------


def test_browse_my_drive(owner_c) -> None:
    r = owner_c.get("/browse")
    assert r.status_code == 200
    for name in ("Projects", "Private", "Loose memo"):
        assert name in r.text
    assert "secret from eve" not in r.text  # not in the owner's Drive
    r = owner_c.get("/browse?folder=proj-sub")
    assert "Deep roadmap" in r.text
    assert 'href="/browse?folder=proj"' in r.text  # breadcrumb
    r = owner_c.get("/browse?q=memo")
    assert "Loose memo" in r.text and "Second memo" in r.text and "Projects" not in r.text
    assert owner_c.get("/browse?folder=bad id").status_code == 400
    assert owner_c.get("/browse?folder=proj-notes").status_code == 400


def test_grant_and_revoke_from_dashboard(owner_c, world, p2_app) -> None:
    assert mcp_call(owner_c, "read_file", file_id="proj-notes")["isError"] is True
    r = post(owner_c, "/grant", file_id="proj", next="/browse")
    assert r.status_code == 303 and r.headers["location"] == "/browse"
    assert [p["emailAddress"] for p in world.files["proj"].permissions] == [BOT_EMAIL]
    page = owner_c.get("/browse").text
    assert "Remove" in page and 'data-confirm="Remove this from the assistant?"' in page
    page = owner_c.get("/browse?folder=proj").text
    assert "via folder" in page and "Everything in this folder is available" in page
    assert "Projects" in owner_c.get("/access").text

    result = mcp_call(owner_c, "read_file", file_id="proj-notes")
    assert result["isError"] is False

    r = post(owner_c, "/revoke", file_id="proj", next="/access")
    assert r.status_code == 303
    assert world.files["proj"].permissions == []
    result = mcp_call(owner_c, "read_file", file_id="proj-notes")
    assert result["structuredContent"]["error"] == "access_required"


def test_grant_errors_are_shown(owner_c) -> None:
    post(owner_c, "/grant", file_id="does-not-exist", next="/browse")
    assert "not found" in owner_c.get("/browse").text
    r = post(owner_c, "/grant", file_id="bad id")
    assert r.status_code == 400


def test_grant_shortcut_from_browse(owner_c, world) -> None:
    post(owner_c, "/grant", file_id="proj-shortcut")
    assert [p["emailAddress"] for p in world.files["priv-secret"].permissions] == [BOT_EMAIL]
    assert world.files["proj-shortcut"].permissions == []


def test_activity_page(owner_c) -> None:
    post(owner_c, "/grant", file_id="loose-doc")
    mcp_call(owner_c, "read_file", file_id="priv-secret")
    page = owner_c.get("/activity").text
    assert "grant" in page and "read_file" in page and "priv-secret" in page
    assert "Drive id, not a file name" in page
    assert "TOP SECRET" not in page and "payroll" not in page


def test_activity_is_capped(p2_app) -> None:
    log = p2_app.state.dashboard.activity
    for i in range(520):
        log({"ts": str(i), "event": "x"})
    recent = log.recent()
    assert len(recent) == 500 and recent[0]["ts"] == "519"


def test_overview_and_health_report_status(owner_c) -> None:
    page = owner_c.get("/").text
    assert "UPSTASH_REDIS_REST_URL" in page
    assert f"{BASE_URL}/mcp" in page
    assert "Connect a second Gmail" in page
    assert "make_token.py" in page  # admin-only operator note


def test_non_admin_overview_hides_operator_notes(c) -> None:
    login(c, "eve-code")
    page = c.get("/").text
    assert "Connect a second Gmail" in page
    assert f"{BASE_URL}/mcp" in page
    assert "make_token.py" not in page
    assert "UPSTASH_REDIS_REST_URL" not in page
    assert "Vercel" not in page
    assert "BOT_EMAIL" not in page


def test_allowed_emails_rejects_other_accounts(world, memstore, oauth) -> None:
    app = build_app(
        make_settings(
            root_folder_id=None,
            allowlist_cache_ttl=0,
            allowed_emails="owner@example.com",
        ),
        world.as_user(BOT_EMAIL),
        store=memstore,
        oauth=oauth,
        owner_drive_factory=lambda t: world.as_user(OWNER_EMAIL),
    )
    c = client(app)
    refused = login(c, "eve-code")
    assert refused.status_code == 403
    assert "not allowed" in refused.text
    assert oauth.revoked
    assert c.get("/browse").status_code == 303
    assert login(c).status_code == 303
    assert c.get("/browse").status_code == 200


def test_requests_nav_counts_pending(owner_c) -> None:
    mcp_call(owner_c, "read_file", file_id="priv-secret")
    page = owner_c.get("/browse").text
    start = page.index("Requests")
    assert 'class="pill pending">1<' in page[start : start + 160]


def test_confirm_script_is_served(c) -> None:
    r = c.get("/confirm.js")
    assert r.status_code == 200
    assert "data-confirm" in r.text
    assert r.headers["content-type"].startswith("text/javascript")


def test_mailbox_empty_state_is_plain_language(owner_c) -> None:
    page = owner_c.get("/bridge").text
    assert "request_link" not in page
    assert "Ask your assistant to start a pairing" in page


def test_public_pages_do_not_say_only_the_owner(c) -> None:
    for path in ("/", "/login", "/privacy", "/terms"):
        text = c.get(path).text
        assert "Only the" not in text
        assert "only the owner" not in text.lower()
    assert "your own Google account" in c.get("/").text
    assert "14 days" in c.get("/privacy").text
    assert "Postgres" in c.get("/privacy").text


def test_dashboard_not_configured(world) -> None:
    app = build_app(
        make_settings(session_secret=None, owner_email=None),
        world.as_user(BOT_EMAIL),
        store=MemoryStore(),
    )
    c = client(app)
    r = c.get("/")
    assert r.status_code == 503
    assert "SESSION_SECRET" in r.text and "OWNER_EMAIL" in r.text
    assert c.get("/terms").status_code == 200
    assert c.get("/privacy").status_code == 200
    health = c.get("/health").json()
    assert {"SESSION_SECRET", "OWNER_EMAIL"} <= set(health["missing"])
