"""Same-account mode: no separate bot, the MCP tools act as the owner, and the allowlist is
the only boundary. Also the switch to a separate bot and "share all allowed items"."""

import pytest
from itsdangerous import URLSafeTimedSerializer

from scoped_drive_mcp.dashboard import STATE_SALT
from scoped_drive_mcp.grants import GrantError
from scoped_drive_mcp.server import build_app
from scoped_drive_mcp.store import AllowEntry
from tests.conftest import BASE_URL, BOT_EMAIL, OWNER_EMAIL, SESSION_SECRET, make_settings
from tests.dash import client, csrf, login, mcp_call, post, start_oauth

NO_BOT = pytest.mark.parametrize("bot_email", [None, OWNER_EMAIL, OWNER_EMAIL.upper()])


def same_settings(**overrides):
    values = {
        "root_folder_id": None,
        "bot_email": None,
        "google_oauth_refresh_token": None,
        "allowlist_cache_ttl": 0,
    }
    values.update(overrides)
    return make_settings(**values)


def make_app(world, memstore, oauth, settings):
    tool_tokens: list[str] = []

    def tools_factory(token: str):
        tool_tokens.append(token)
        return world.as_user(OWNER_EMAIL)

    app = build_app(
        settings,
        store=memstore,
        owner_drive_factory=lambda t: world.as_user(OWNER_EMAIL),
        oauth=oauth,
        bot_drive_factory=tools_factory,
    )
    app.state.tool_tokens = tool_tokens
    return app


@pytest.fixture
def same_app(world, memstore, oauth):
    return make_app(world, memstore, oauth, same_settings())


@pytest.fixture
def c(same_app):
    c = client(same_app)
    login(c)
    return c


def permission_changes(world) -> list:
    return [f.permissions for f in world.files.values() if f.id != "stray-shared"]


@NO_BOT
def test_mode_detection(bot_email) -> None:
    s = make_settings(bot_email=bot_email)
    assert s.same_account and s.mode == "same_account"
    assert "BOT_EMAIL" not in s.missing_settings()
    assert make_settings(bot_email=BOT_EMAIL).mode == "separate_bot"


def test_tools_use_the_owner_token(c, same_app) -> None:
    post(c, "/grant", file_id="loose-doc")
    result = mcp_call(c, "read_file", file_id="loose-doc")
    assert result["isError"] is False
    assert result["structuredContent"]["content"] == "memo beta"
    assert same_app.state.tool_tokens == [f"rt-{OWNER_EMAIL}"]
    health = c.get("/health").json()
    assert health["mode"] == "same_account"
    assert health["bot_connected"] is True and health["bot_source"] == "owner"


def test_tools_need_the_owner_signed_in_once(same_app) -> None:
    c = client(same_app)
    result = mcp_call(c, "read_file", file_id="loose-doc")
    text = result["content"][0]["text"]
    assert result["isError"] and "owner has not signed in" in text
    assert "Connect bot" not in text

    login(c)
    post(c, "/grant", file_id="loose-doc")
    assert mcp_call(c, "read_file", file_id="loose-doc")["isError"] is False


def test_env_refresh_token_still_wins(world, memstore, oauth) -> None:
    app = make_app(world, memstore, oauth, same_settings(google_oauth_refresh_token="env-rt"))
    c = client(app)
    login(c)
    post(c, "/grant", file_id="loose-doc")
    assert mcp_call(c, "read_file", file_id="loose-doc")["isError"] is False
    assert app.state.tool_tokens == ["env-rt"]
    assert c.get("/health").json()["bot_source"] == "env"


def test_grant_and_revoke_make_no_permission_calls(c, same_app, world) -> None:
    before = permission_changes(world)
    r = post(c, "/grant", file_id="proj")
    assert r.status_code == 303
    entry = same_app.state.dashboard.allowlist.get("proj")
    assert entry is not None and entry.permission_id is None and entry.shared_with is None
    assert mcp_call(c, "read_file", file_id="proj-notes")["isError"] is False
    post(c, "/revoke", file_id="proj")
    assert same_app.state.dashboard.allowlist.get("proj") is None
    assert permission_changes(world) == before
    assert mcp_call(c, "read_file", file_id="proj-notes")["isError"] is True


def test_owner_sees_everything_but_scope_still_needs_a_ticked_item(c, world) -> None:
    """The tools' credentials can read the whole Drive; only the allowlist stops them."""
    post(c, "/grant", file_id="proj")
    assert mcp_call(c, "read_file", file_id="proj-deep-doc")["isError"] is False
    for file_id in ("priv-secret", "loose-two", "owner-root", "stray-shared"):
        result = mcp_call(c, "read_file", file_id=file_id)
        assert result["isError"] is True, file_id
        assert "TOP SECRET" not in str(result) and "memo gamma" not in str(result)
    # a shortcut inside the ticked folder is not followed to its target
    result = mcp_call(c, "read_file", file_id="proj-shortcut")
    assert result["structuredContent"]["content"] is None
    # search only returns ticked content, although the owner's view matches more
    found = mcp_call(c, "search_files", query="secret")["structuredContent"]["files"]
    assert {f["id"] for f in found} <= {"proj", "proj-sub", "proj-deep-doc", "proj-notes"}
    # writes cannot leave the ticked folder
    result = mcp_call(c, "create_folder", "editor", name="x", parent_id="owner-root")
    assert result["isError"] is True
    assert mcp_call(c, "trash_file", "admin", file_id="proj")["isError"] is True
    assert world.files["proj"].trashed is False


def test_access_required_approve_retry_revoke(c, same_app, world) -> None:
    before = permission_changes(world)
    payload = mcp_call(c, "read_file", file_id="priv-secret")["structuredContent"]
    assert payload["error"] == "access_required"
    path = payload["approval_url"].removeprefix(BASE_URL)
    page = c.get(path)
    assert page.status_code == 200 and "payroll.txt" in page.text

    r = post(c, f"{path}/approve", target_id="priv-secret")
    assert r.status_code == 303
    assert same_app.state.dashboard.allowlist.get("priv-secret").permission_id is None
    result = mcp_call(c, "read_file", file_id="priv-secret")
    assert result["structuredContent"]["content"] == "TOP SECRET payroll"
    status = mcp_call(c, "check_access_request", request_id=payload["request_id"])
    assert status["structuredContent"]["status"] == "approved"
    assert mcp_call(c, "read_file", file_id="priv-other")["isError"] is True

    post(c, "/revoke", file_id="priv-secret")
    again = mcp_call(c, "read_file", file_id="priv-secret")["structuredContent"]
    assert again["error"] == "access_required" and again["request_id"] != payload["request_id"]
    assert permission_changes(world) == before


def test_my_drive_root_cannot_be_granted(c, same_app) -> None:
    grants = same_app.state.dashboard.grants()
    with pytest.raises(GrantError):
        grants.grant("owner-root")
    assert same_app.state.dashboard.allowlist.entries() == {}


def test_pages_show_the_mode_warning(c) -> None:
    for page in ("/", "/access"):
        html = c.get(page).text
        assert 'id="mode-warning"' in html and "Same-account mode" in html, page
        assert "separate Google account" in html
    html = c.get("/connect-bot").text
    assert "optional" in html and 'action="/connect-bot"' not in html


def test_connect_bot_is_refused(c, oauth, same_app) -> None:
    r = post(c, "/connect-bot")
    assert r.status_code == 303 and r.headers["location"] == "/connect-bot"
    assert "BOT_EMAIL" in c.get("/connect-bot").text
    # a validly signed bot-flow state is refused at the callback as well
    serializer = URLSafeTimedSerializer(SESSION_SECRET, STATE_SALT)
    nonce = serializer.loads(start_oauth(c))["nonce"]
    bot_state = serializer.dumps({"flow": "bot", "nonce": nonce})
    r = c.get("/auth/callback", params={"code": "owner-code", "state": bot_state})
    assert r.status_code == 400 and "BOT_EMAIL" in r.text
    assert same_app.state.dashboard.vault.bot() is None
    r = post(c, "/access/share-bot")
    assert r.status_code == 303 and same_app.state.dashboard.allowlist.entries() == {}


def test_separate_bot_pages_have_no_warning(p2_app) -> None:
    c = client(p2_app)
    login(c)
    for page in ("/", "/access"):
        html = c.get(page).text
        assert 'id="mode-warning"' not in html and 'id="mode-note"' in html
    assert c.get("/health").json()["mode"] == "separate_bot"


# ---- switching to a separate bot -----------------------------------------------------


def switch_to_bot(world, memstore, oauth):
    """Same store, now with BOT_EMAIL set and the bot connected from the dashboard."""
    app = build_app(
        make_settings(root_folder_id=None, google_oauth_refresh_token=None, allowlist_cache_ttl=0),
        store=memstore,
        owner_drive_factory=lambda t: world.as_user(OWNER_EMAIL),
        oauth=oauth,
        bot_drive_factory=lambda t: world.as_user(BOT_EMAIL),
    )
    c = client(app)
    login(c)
    state = start_oauth(c, "/connect-bot", csrf=csrf(c, "/connect-bot"))
    assert c.get("/auth/callback", params={"code": "bot-code", "state": state}).status_code == 303
    return app, c


def test_share_all_after_switching_to_a_bot(c, world, memstore, oauth) -> None:
    post(c, "/grant", file_id="proj")
    post(c, "/grant", file_id="loose-doc")

    app, bc = switch_to_bot(world, memstore, oauth)
    # ticked items are on the allowlist, but Google does not let the bot in yet
    assert mcp_call(bc, "read_file", file_id="loose-doc")["isError"] is True
    html = bc.get("/access").text
    assert "Share all allowed items with the bot" in html and "not shared with bot" in html
    assert "2 allowed item(s)" in bc.get("/").text

    r = post(bc, "/access/share-bot")
    assert r.status_code == 303
    for fid in ("proj", "loose-doc"):
        entry = app.state.dashboard.allowlist.get(fid)
        assert entry.shared_with == BOT_EMAIL and entry.permission_id
        assert [p["emailAddress"] for p in world.files[fid].permissions] == [BOT_EMAIL]
    assert mcp_call(bc, "read_file", file_id="loose-doc")["structuredContent"]["content"] == (
        "memo beta"
    )
    assert mcp_call(bc, "read_file", file_id="proj-notes")["isError"] is False
    assert "Share all allowed items" not in bc.get("/access").text

    # idempotent: a second run shares nothing new
    calls = len(world.permission_calls)
    assert app.state.dashboard.grants().share_all() == {"shared": [], "failed": []}
    post(bc, "/access/share-bot")
    assert len(world.permission_calls) == calls
    assert all(len(world.files[f].permissions) == 1 for f in ("proj", "loose-doc"))

    # revoking now removes the bot's Drive share too
    post(bc, "/revoke", file_id="loose-doc")
    assert world.files["loose-doc"].permissions == []


def test_share_all_requires_a_connected_bot(c, world, memstore, oauth) -> None:
    post(c, "/grant", file_id="loose-doc")
    app = build_app(
        make_settings(root_folder_id=None, google_oauth_refresh_token=None, allowlist_cache_ttl=0),
        store=memstore,
        owner_drive_factory=lambda t: world.as_user(OWNER_EMAIL),
        oauth=oauth,
    )
    bc = client(app)
    login(bc)
    assert "Share all allowed items" not in bc.get("/access").text
    r = post(bc, "/access/share-bot")
    assert r.status_code == 303 and r.headers["location"] == "/connect-bot"
    assert world.files["loose-doc"].permissions == []


def test_share_all_moves_shares_to_a_new_bot_address(world, memstore) -> None:
    from scoped_drive_mcp.access import AccessRequests
    from scoped_drive_mcp.grants import GrantService
    from scoped_drive_mcp.store import Allowlist, PrefixedStore

    kv = PrefixedStore(memstore)
    allowlist = Allowlist(kv)
    owner = world.as_user(OWNER_EMAIL)
    old = GrantService(lambda: owner, allowlist, AccessRequests(kv), "old-bot@example.com")
    old.grant("loose-doc")
    new = GrantService(lambda: owner, allowlist, AccessRequests(kv), BOT_EMAIL)
    assert [e.id for e in new.unshared()] == ["loose-doc"]
    assert new.share_all()["shared"] == ["loose-doc"]
    assert [p["emailAddress"] for p in world.files["loose-doc"].permissions] == [BOT_EMAIL]


def test_share_all_reports_failures_and_keeps_the_entry(world, memstore) -> None:
    from scoped_drive_mcp.access import AccessRequests
    from scoped_drive_mcp.grants import GrantService
    from scoped_drive_mcp.store import Allowlist, PrefixedStore

    kv = PrefixedStore(memstore)
    allowlist = Allowlist(kv)
    allowlist.add(AllowEntry("stray-shared", "eve's", "text/plain", None))  # not the owner's
    allowlist.add(AllowEntry("loose-doc", "Loose memo", "application/x", None))
    owner = world.as_user(OWNER_EMAIL)
    grants = GrantService(lambda: owner, allowlist, AccessRequests(kv), BOT_EMAIL)
    result = grants.share_all()
    assert result["shared"] == ["loose-doc"]
    assert [f["id"] for f in result["failed"]] == ["stray-shared"]
    assert allowlist.get("stray-shared").shared_with is None
