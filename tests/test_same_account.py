"""The assistant uses the signed-in account, and the allowlist is the only boundary."""

import pytest

from scoped_drive_mcp.grants import GrantError
from scoped_drive_mcp.server import build_app
from tests.conftest import BASE_URL, OWNER_EMAIL, make_settings
from tests.dash import client, login, mcp_call, post

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
    assert make_settings(bot_email="bot@example.com").mode == "same_account"


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


def test_pages_describe_the_allowlist(c) -> None:
    for page in ("/", "/access"):
        html = c.get(page).text
        assert 'id="mode-note"' in html and "your Google account" in html, page
        assert "connect-bot" not in html and "BOT_EMAIL" not in html
    assert c.get("/health").json()["mode"] == "same_account"


def test_bot_oauth_flow_is_rejected(c, same_app) -> None:
    from itsdangerous import URLSafeTimedSerializer

    from scoped_drive_mcp.dashboard import STATE_SALT
    from tests.conftest import SESSION_SECRET
    from tests.dash import start_oauth

    serializer = URLSafeTimedSerializer(SESSION_SECRET, STATE_SALT)
    nonce = serializer.loads(start_oauth(c))["nonce"]
    bot_state = serializer.dumps({"flow": "bot", "nonce": nonce})
    r = c.get("/auth/callback", params={"code": "owner-code", "state": bot_state})
    assert r.status_code == 400
    assert same_app.state.dashboard.vault.bot() is None
    assert c.get("/connect-bot").status_code == 404
