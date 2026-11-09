"""Two people, two bots: Grok Bot for one cannot read the other's files."""

import json

from scoped_drive_mcp.auth import current_actor
from scoped_drive_mcp.drive_client import FOLDER_MIME
from scoped_drive_mcp.scope import ScopeGuard
from scoped_drive_mcp.server import build_app
from scoped_drive_mcp.store import KEY_PREFIX
from tests.conftest import BOT_EMAIL, EVE, OWNER_EMAIL, make_settings
from tests.dash import MCP_HEADERS, client, csrf, login, post, start_oauth
from tests.fake_drive import FakeDrive
from tests.test_mcp_oauth import GROK, auth_params, code_from, exchange, posted_redirect, register

EVE_BOT = "eve-bot@example.com"
EVE_BOT_2 = "eve-bot-2@example.com"
CAROL = "carol@example.com"
EVE_DOC = "eve-doc"
EVE_DOC_NAME = "Eve private memo"


def _accounts(oauth) -> None:
    oauth.accounts["eve-bot-code"] = (EVE_BOT, True)
    oauth.accounts["eve-bot-2-code"] = (EVE_BOT_2, True)
    oauth.accounts["carol-code"] = (CAROL, True)


def _extend(world: FakeDrive) -> None:
    world.roots[EVE_BOT] = "eve-bot-root"
    world.roots[EVE_BOT_2] = "eve-bot-2-root"
    world.roots[CAROL] = "carol-root"
    world.add("eve-bot-root", "My Drive", FOLDER_MIME, [], owner=EVE_BOT)
    world.add("eve-bot-2-root", "My Drive", FOLDER_MIME, [], owner=EVE_BOT_2)
    world.add("carol-root", "My Drive", FOLDER_MIME, [], owner=CAROL)
    world.add(EVE_DOC, EVE_DOC_NAME, "text/plain", ["eve-root"], b"eve only text", owner=EVE)


def _app(world, memstore, oauth):
    _accounts(oauth)
    _extend(world)

    def drive_for(token: str) -> FakeDrive:
        return world.as_user(token.removeprefix("rt-"))

    app = build_app(
        make_settings(
            root_folder_id=None,
            google_oauth_refresh_token=None,
            allowlist_cache_ttl=0,
        ),
        store=memstore,
        owner_drive_factory=drive_for,
        oauth=oauth,
        bot_drive_factory=drive_for,
    )
    return app


def _mcp(c, token: str, tool: str, **arguments) -> dict:
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }
    headers = {**MCP_HEADERS, "Authorization": f"Bearer {token}"}
    response = c.post("/mcp", json=body, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["result"]


def _grok(c, name: str) -> str:
    created = register(c, GROK, name=name)
    assert created.status_code == 201, created.text
    client_id = created.json()["client_id"]
    verifier, params = auth_params(client_id, GROK)
    page = c.get("/oauth/authorize", params=params)
    assert page.status_code == 200, page.text
    decided = post(c, "/oauth/authorize", decision="allow")
    target = posted_redirect(c, decided)
    token = exchange(c, client_id, code_from(target), verifier, GROK)
    assert token.status_code == 200, token.text
    return token.json()["access_token"]


def _connect_bot(c, code: str):
    state = start_oauth(c, "/connect-bot", csrf=csrf(c, "/connect-bot"))
    return c.get("/auth/callback", params={"code": code, "state": state})


def test_each_grok_bot_sees_only_that_users_files(world, memstore, oauth) -> None:
    app = _app(world, memstore, oauth)
    admin = client(app)
    eve = client(app)
    assert login(admin).status_code == 303
    assert login(eve, "eve-code").status_code == 303
    assert _connect_bot(admin, "bot-code").status_code == 303
    assert _connect_bot(eve, "eve-bot-code").status_code == 303
    assert post(admin, "/grant", file_id="loose-doc").status_code == 303
    assert post(eve, "/grant", file_id=EVE_DOC).status_code == 303

    admin_token = _grok(admin, "Grok Ada")
    eve_token = _grok(eve, "Grok Eve")

    admin_read = _mcp(admin, admin_token, "read_file", file_id="loose-doc")
    assert admin_read["isError"] is False
    assert admin_read["structuredContent"]["content"] == "memo beta"
    admin_denied = _mcp(admin, admin_token, "read_file", file_id=EVE_DOC)
    assert admin_denied["isError"] is True
    assert admin_denied["structuredContent"]["error"] == "access_required"
    assert admin_denied["structuredContent"]["file_id"] == EVE_DOC

    eve_read = _mcp(eve, eve_token, "read_file", file_id=EVE_DOC)
    assert eve_read["isError"] is False
    assert eve_read["structuredContent"]["content"] == "eve only text"
    eve_denied = _mcp(eve, eve_token, "read_file", file_id="loose-doc")
    assert eve_denied["isError"] is True
    assert eve_denied["structuredContent"]["error"] == "access_required"
    assert eve_denied["structuredContent"]["file_id"] == "loose-doc"

    allow = memstore.hgetall(KEY_PREFIX + "allowlist")
    eve_allow = memstore.hgetall(KEY_PREFIX + f"u:{EVE}:allowlist")
    assert "loose-doc" in allow and EVE_DOC not in allow
    assert EVE_DOC in eve_allow and "loose-doc" not in eve_allow
    assert json.loads(allow["loose-doc"])["shared_with"] == BOT_EMAIL
    assert json.loads(eve_allow[EVE_DOC])["shared_with"] == EVE_BOT

    admin.get("/")  # drop the grant flash before the directory page
    page = admin.get("/admin")
    assert page.status_code == 200
    text = page.text
    assert OWNER_EMAIL in text and EVE in text
    assert BOT_EMAIL in text and EVE_BOT in text
    assert "Grok Ada" in text and "Grok Eve" in text
    assert "connected" in text
    for secret in ("loose-doc", EVE_DOC, "Loose memo", EVE_DOC_NAME, "proj-notes"):
        assert secret not in text
    assert eve.get("/admin").status_code == 404
    assert 'href="/admin"' in admin.get("/").text
    assert 'href="/admin"' not in eve.get("/").text


def test_bot_address_rules(world, memstore, oauth) -> None:
    app = _app(world, memstore, oauth)
    eve = client(app)
    carol = client(app)
    assert login(eve, "eve-code").status_code == 303
    assert _connect_bot(eve, "eve-bot-code").status_code == 303
    assert login(carol, "carol-code").status_code == 303

    stolen = _connect_bot(carol, "eve-bot-code")
    assert stolen.status_code == 403
    assert "already used" in stolen.text
    assert app.state.dashboard.directory.stored_bot_email(CAROL) is None

    own = _connect_bot(eve, "eve-code")
    assert own.status_code == 403
    assert "different Google account" in own.text
    assert app.state.dashboard.directory.stored_bot_email(EVE) == EVE_BOT

    switched = _connect_bot(eve, "eve-bot-2-code")
    assert switched.status_code == 403
    assert "Disconnect" in switched.text
    assert app.state.dashboard.directory.stored_bot_email(EVE) == EVE_BOT

    assert post(eve, "/bot/disconnect").status_code == 303
    assert app.state.dashboard.directory.stored_bot_email(EVE) is None
    assert _connect_bot(eve, "eve-bot-2-code").status_code == 303
    assert app.state.dashboard.directory.stored_bot_email(EVE) == EVE_BOT_2

    post(eve, "/grant", file_id=EVE_DOC)
    assert post(eve, "/access/share-bot").status_code == 303
    emails = [p["emailAddress"] for p in world.files[EVE_DOC].permissions]
    assert emails == [EVE_BOT_2]


def test_scope_cache_is_partitioned_by_actor() -> None:
    def source() -> dict[str, str]:
        actor = current_actor.get()
        if actor == "a@example.com":
            return {"a-file": "text/plain"}
        if actor == "b@example.com":
            return {"b-file": "text/plain"}
        return {"shared-file": "text/plain"}

    guard = ScopeGuard(FakeDrive(), None, allowlist=source, allowlist_ttl=60)
    first = current_actor.set("a@example.com")
    try:
        assert set(guard.allowed()) == {"a-file"}
    finally:
        current_actor.reset(first)
    second = current_actor.set("b@example.com")
    try:
        assert set(guard.allowed()) == {"b-file"}
    finally:
        current_actor.reset(second)
    assert set(guard.allowed()) == {"shared-file"}
