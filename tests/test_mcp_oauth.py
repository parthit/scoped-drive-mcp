"""MCP OAuth (no network): discovery, registration, consent, PKCE, and revocation."""

import base64
import hashlib
import html
import json
import re
import secrets
from urllib.parse import parse_qs, urlparse

import itsdangerous
import pytest

from scoped_drive_mcp.dashboard import SESSION_COOKIE
from scoped_drive_mcp.mcp_oauth import ALLOWED_REDIRECT_URIS, GRANTS_KEY, OAuthGrant, done_redirect
from scoped_drive_mcp.server import build_app
from scoped_drive_mcp.store import MemoryStore
from tests.conftest import BASE_URL, SESSION_SECRET, TOKENS
from tests.dash import MCP_HEADERS, client, login, post

RESOURCE = f"{BASE_URL}/mcp"
METADATA = f"{BASE_URL}/.well-known/oauth-protected-resource/mcp"
DONE = done_redirect(BASE_URL)
GROK = "https://grok.com/connectors-oauth-exchange-code/"
CURSOR = "cursor://anysphere.cursor-mcp/oauth/callback"
MUSE = (
    "https://muse.ai/api/hatch/oauth/callback",
    "https://agent.meta.ai/api/hatch/oauth/callback",
)

INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "0"},
    },
}
LIST = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
_GRANT_ID = re.compile(r'name="grant_id" value="([^"]+)"')


def s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def register(c, uris: str | list[str], name: str = "Grok Bot", **extra):
    payload = {
        "client_name": name,
        "redirect_uris": [uris] if isinstance(uris, str) else uris,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    }
    payload.update(extra)
    return c.post("/oauth/register", json=payload)


def auth_params(client_id: str, redirect: str, **extra) -> tuple[str, dict[str, str]]:
    verifier = secrets.token_urlsafe(32)
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect,
        "code_challenge": s256(verifier),
        "code_challenge_method": "S256",
        "state": "state-1",
        "resource": RESOURCE,
    }
    params.update(extra)
    return verifier, params


def exchange(c, client_id: str, code: str, verifier: str, redirect: str, **extra):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect,
        "client_id": client_id,
        "code_verifier": verifier,
        "resource": RESOURCE,
    }
    data.update(extra)
    return c.post("/oauth/token", data=data)


def tool_names(c, token: str) -> set[str]:
    headers = {**MCP_HEADERS, "Authorization": f"Bearer {token}"}
    init = c.post("/mcp", json=INIT, headers=headers)
    assert init.status_code == 200, init.text
    listed = c.post("/mcp", json=LIST, headers=headers)
    assert listed.status_code == 200, listed.text
    return {item["name"] for item in listed.json()["result"]["tools"]}


def code_from(location: str) -> str:
    query = parse_qs(urlparse(location).query)
    return query["code"][0]


def posted_redirect(c, response) -> str:
    """Follow the same-origin handoff that a consent POST returns."""
    assert response.status_code == 303, response.text
    location = response.headers["location"]
    assert location.startswith("/oauth/continue?"), location
    assert "code=" not in location
    assert "error=" not in location
    assert location.startswith("/") and not location.startswith("//")
    page = c.get(location)
    assert page.status_code == 200, page.text
    policy = page.headers["content-security-policy"]
    assert "form-action 'self' https://accounts.google.com" in policy
    assert "grok.com" not in policy
    assert "cursor.com" not in policy
    match = re.search(r'http-equiv="refresh" content="0;url=([^"]+)"', page.text)
    assert match, page.text
    target = html.unescape(match.group(1))
    assert "evil.example" not in target
    expired = c.get(location)
    assert expired.status_code == 400
    assert "http-equiv" not in expired.text
    return target


def forge_session(owner: str) -> str:
    signer = itsdangerous.TimestampSigner(SESSION_SECRET)
    payload = base64.b64encode(json.dumps({"owner": owner, "csrf": "tok"}).encode())
    return signer.sign(payload).decode()


@pytest.fixture
def c(p2_app):
    return client(p2_app)


@pytest.fixture
def owner_c(c):
    assert login(c).status_code == 303
    return c


class SpyStore(MemoryStore):
    def __init__(self) -> None:
        super().__init__()
        self.oauth_ops = 0

    def _watch(self, key: str) -> None:
        if "oauth:" in key:
            self.oauth_ops += 1

    def get(self, key: str) -> str | None:
        self._watch(key)
        return super().get(key)

    def hget(self, key: str, field: str) -> str | None:
        self._watch(key)
        return super().hget(key, field)

    def hgetall(self, key: str) -> dict[str, str]:
        self._watch(key)
        return super().hgetall(key)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._watch(key)
        return super().set(key, value, ex)

    def hset(self, key: str, field: str, value: str) -> None:
        self._watch(key)
        return super().hset(key, field, value)


def test_metadata_is_public(c) -> None:
    root = c.get("/.well-known/oauth-protected-resource")
    scoped = c.get("/.well-known/oauth-protected-resource/mcp")
    suffixed = c.get("/mcp/.well-known/oauth-protected-resource")
    assert root.status_code == scoped.status_code == suffixed.status_code == 200
    assert root.json() == scoped.json() == suffixed.json()
    body = root.json()
    assert body["resource"] == RESOURCE
    assert body["authorization_servers"] == [BASE_URL]
    assert "authorization" not in {k.lower() for k in root.request.headers}

    meta = c.get("/.well-known/oauth-authorization-server")
    alias = c.get("/.well-known/oauth-authorization-server/mcp")
    assert meta.status_code == alias.status_code == 200
    assert meta.json() == alias.json()
    document = meta.json()
    assert document["issuer"] == BASE_URL
    assert document["authorization_endpoint"] == f"{BASE_URL}/oauth/authorize"
    assert document["token_endpoint"] == f"{BASE_URL}/oauth/token"
    assert document["registration_endpoint"] == f"{BASE_URL}/oauth/register"
    assert document["response_types_supported"] == ["code"]
    assert document["grant_types_supported"] == ["authorization_code", "refresh_token"]
    assert document["code_challenge_methods_supported"] == ["S256"]
    assert document["token_endpoint_auth_methods_supported"] == ["none"]


def test_mcp_without_token_advertises_metadata(c) -> None:
    missing = c.post("/mcp", json=INIT, headers=MCP_HEADERS)
    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == f'Bearer resource_metadata="{METADATA}"'
    bad = c.post(
        "/mcp",
        json=INIT,
        headers={**MCP_HEADERS, "Authorization": f"Bearer {secrets.token_urlsafe(32)}"},
    )
    assert bad.status_code == 401
    assert bad.headers["www-authenticate"] == (
        f'Bearer resource_metadata="{METADATA}", error="invalid_token"'
    )


def test_preshared_api_token_is_not_an_oauth_lookup(world, p2_settings, oauth) -> None:
    spy = SpyStore()
    app = build_app(
        p2_settings,
        world.as_user(p2_settings.bot_email or p2_settings.owner_email or ""),
        store=spy,
        oauth=oauth,
        owner_drive_factory=lambda _token: world.as_user(p2_settings.owner_email or ""),
    )
    c = client(app)
    names = tool_names(c, TOKENS["viewer"])
    assert names == {
        "search_files",
        "list_folder",
        "get_metadata",
        "read_file",
        "request_access",
        "check_access_request",
        "request_link",
        "list_links",
        "send_message",
        "list_inbox",
        "check_messages",
        "reply",
        "mark_read",
    }
    assert "trash_file" not in names
    assert spy.oauth_ops == 0
    rejected = c.post(
        "/mcp",
        json=INIT,
        headers={**MCP_HEADERS, "Authorization": "Bearer not-a-real-token"},
    )
    assert rejected.status_code == 401
    assert spy.oauth_ops > 0


@pytest.mark.parametrize(
    "uri",
    [
        "https://evil.example/callback",
        "https://www.cursor.com.evil.example/agents/mcp/oauth/callback",
        "https://evil.cursor.com/agents/mcp/oauth/callback",
        "https://cursor.com/agents/mcp/oauth/callback/extra",
        "https://cursor.com/agents/mcp/oauth/callback.evil",
        "https://user@cursor.com/agents/mcp/oauth/callback",
        "https://cursor.com/agents/mcp/oauth/callback?next=https://evil.example",
        "https://grok.com/connectors-oauth-exchange-code",
        "https://grok.com/connectors-oauth-exchange-code/extra",
        "https://muse.ai/api/hatch/oauth/callback/",
        "https://www.muse.ai/api/hatch/oauth/callback",
        "https://muse.ai.evil.example/api/hatch/oauth/callback",
        "https://evil.muse.ai/api/hatch/oauth/callback",
        "https://agent.meta.ai/api/hatch/oauth/callback/extra",
        "https://platform.muse.ai/oauth/credential-test/callback/extra",
        "http://muse.ai/api/hatch/oauth/callback",
        "http://localhost:8787/callback/extra",
        "http://localhost:8788/callback",
        "https://localhost:8787/callback",
        "http://127.0.0.1:8787/callback?x=1",
        CURSOR + "/extra",
        "javascript:alert(1)",
    ],
)
def test_registration_rejects_foreign_redirects(c, uri: str) -> None:
    alone = register(c, uri)
    assert alone.status_code == 400
    assert alone.json()["error"] == "invalid_redirect_uri"
    assert "client_id" not in alone.json()
    mixed = register(c, [DONE, uri])
    assert mixed.status_code == 400
    assert mixed.json()["error"] == "invalid_redirect_uri"


def test_muse_can_register_its_callbacks(c) -> None:
    response = register(c, list(MUSE), name="Muse")
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["redirect_uris"] == list(MUSE)
    assert body["token_endpoint_auth_method"] == "none"
    assert "client_secret" not in body
    platform = register(c, "https://platform.muse.ai/oauth/credential-test/callback", name="Muse")
    assert platform.status_code == 201, platform.text


def test_registration_accepts_allowed_redirects(c) -> None:
    uris = sorted(ALLOWED_REDIRECT_URIS | {DONE})
    response = register(c, uris, name="Cursor")
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["redirect_uris"] == uris
    assert body["token_endpoint_auth_method"] == "none"
    assert "client_secret" not in body
    assert body["client_id"]
    confidential = register(c, DONE, token_endpoint_auth_method="client_secret_basic")
    assert confidential.status_code == 400
    assert confidential.json()["error"] == "invalid_client_metadata"


def test_authorize_without_session_redirects_to_login(c) -> None:
    created = register(c, DONE)
    _verifier, params = auth_params(created.json()["client_id"], DONE)
    response = c.get("/oauth/authorize", params=params)
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("/login?next=")
    assert "oauth" in location
    assert DONE not in location


def test_non_owner_session_is_refused(c) -> None:
    created = register(c, GROK)
    _verifier, params = auth_params(created.json()["client_id"], GROK)
    c.cookies.set(SESSION_COOKIE, forge_session("eve@example.com"))
    response = c.get("/oauth/authorize", params=params)
    assert response.status_code == 403
    assert "not allowed" in response.text
    assert "location" not in response.headers


def test_open_redirect_is_rejected(owner_c) -> None:
    created = register(owner_c, GROK)
    client_id = created.json()["client_id"]
    _verifier, params = auth_params(client_id, "https://evil.example/phish")
    response = owner_c.get("/oauth/authorize", params=params)
    assert response.status_code == 400
    assert "location" not in response.headers
    assert "evil.example" not in response.headers.get("location", "")
    _verifier, params = auth_params(client_id, "https://cursor.com/agents/mcp/oauth/callback")
    response = owner_c.get("/oauth/authorize", params=params)
    assert response.status_code == 400
    assert "location" not in response.headers


def test_invalid_resource_redirects_with_error_not_a_code(owner_c) -> None:
    created = register(owner_c, GROK)
    _verifier, params = auth_params(
        created.json()["client_id"], GROK, resource="https://evil.example/mcp"
    )
    response = owner_c.get("/oauth/authorize", params=params)
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith(GROK)
    query = parse_qs(urlparse(location).query)
    assert query["error"] == ["invalid_target"]
    assert query["state"] == ["state-1"]
    assert "code" not in query


def test_approve_issues_a_code_and_deny_does_not(owner_c) -> None:
    created = register(owner_c, CURSOR, name="Cursor")
    client_id = created.json()["client_id"]
    _verifier, params = auth_params(client_id, CURSOR, scope="something-else")
    page = owner_c.get("/oauth/authorize", params=params)
    assert page.status_code == 200
    assert "Cursor" in page.text
    assert "Drive trash" in page.text
    assert "trash_file" not in page.text
    assert "something-else" in page.text
    denied = post(owner_c, "/oauth/authorize", decision="deny")
    target = posted_redirect(owner_c, denied)
    query = parse_qs(urlparse(target).query)
    assert target.startswith(CURSOR)
    assert query["error"] == ["access_denied"]
    assert query["state"] == ["state-1"]
    assert "code" not in query

    verifier, params = auth_params(client_id, CURSOR, state="returned-state")
    assert owner_c.get("/oauth/authorize", params=params).status_code == 200
    blocked = owner_c.post("/oauth/authorize", data={"decision": "allow", "csrf": "nope"})
    assert blocked.status_code == 403
    assert "location" not in blocked.headers
    allowed = post(owner_c, "/oauth/authorize", decision="allow")
    location = posted_redirect(owner_c, allowed)
    assert location.startswith(CURSOR + "?")
    query = parse_qs(urlparse(location).query)
    assert query["state"] == ["returned-state"]
    assert query["code"][0]
    assert query.get("iss") == [BASE_URL]


def test_pkce_and_redirect_mismatch_fail_and_code_is_single_use(owner_c, memstore) -> None:
    created = register(owner_c, DONE, name="Local test")
    client_id = created.json()["client_id"]
    verifier, params = auth_params(client_id, DONE)
    assert owner_c.get("/oauth/authorize", params=params).status_code == 200
    allowed = post(owner_c, "/oauth/authorize", decision="allow")
    code = code_from(posted_redirect(owner_c, allowed))
    mismatch = exchange(owner_c, client_id, code, verifier, "http://127.0.0.1:8787/callback")
    assert mismatch.status_code == 400
    assert mismatch.json()["error"] == "invalid_grant"
    replay = exchange(owner_c, client_id, code, verifier, DONE)
    assert replay.status_code == 400

    verifier, params = auth_params(client_id, DONE)
    assert owner_c.get("/oauth/authorize", params=params).status_code == 200
    code = code_from(posted_redirect(owner_c, post(owner_c, "/oauth/authorize", decision="allow")))
    bad_pkce = exchange(owner_c, client_id, code, secrets.token_urlsafe(32), DONE)
    assert bad_pkce.status_code == 400
    assert bad_pkce.json()["error"] == "invalid_grant"
    assert exchange(owner_c, client_id, code, verifier, DONE).status_code == 400

    verifier, params = auth_params(client_id, DONE)
    assert owner_c.get("/oauth/authorize", params=params).status_code == 200
    code = code_from(posted_redirect(owner_c, post(owner_c, "/oauth/authorize", decision="allow")))
    token = exchange(owner_c, client_id, code, verifier, DONE)
    assert token.status_code == 200, token.text
    body = token.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 3600
    assert body["scope"] == "drive"
    assert "client_secret" not in body
    access = body["access_token"]
    refresh = body["refresh_token"]
    assert access != refresh
    stored = repr(memstore._values)
    assert access not in stored
    assert refresh not in stored
    assert code not in stored
    assert hash_in(access) in stored

    names = tool_names(owner_c, access)
    assert len(names) == 19
    assert "trash_file" in names
    dashboard = owner_c.get("/", headers={"Authorization": f"Bearer {access}"})
    assert dashboard.status_code == 200
    assert "Local test" in dashboard.text
    logged_out = client(owner_c.app)
    opened = logged_out.get("/browse", headers={"Authorization": f"Bearer {access}"})
    assert opened.status_code == 303
    assert opened.headers["location"].startswith("/login")

    rotated = owner_c.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": client_id,
            "resource": RESOURCE,
        },
    )
    assert rotated.status_code == 200, rotated.text
    new_refresh = rotated.json()["refresh_token"]
    assert new_refresh != refresh
    assert tool_names(owner_c, rotated.json()["access_token"])
    reused = owner_c.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": client_id,
            "resource": RESOURCE,
        },
    )
    assert reused.status_code == 400
    assert reused.json()["error"] == "invalid_grant"
    killed = owner_c.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": new_refresh,
            "client_id": client_id,
            "resource": RESOURCE,
        },
    )
    assert killed.status_code == 400


def hash_in(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def test_revoked_grant_cannot_call_mcp(owner_c) -> None:
    created = register(owner_c, GROK, name="Grok Bot")
    client_id = created.json()["client_id"]
    verifier, params = auth_params(client_id, GROK)
    assert owner_c.get("/oauth/authorize", params=params).status_code == 200
    code = code_from(posted_redirect(owner_c, post(owner_c, "/oauth/authorize", decision="allow")))
    token = exchange(owner_c, client_id, code, verifier, GROK)
    access = token.json()["access_token"]
    refresh = token.json()["refresh_token"]
    assert "list_folder" in tool_names(owner_c, access)
    page = owner_c.get("/")
    assert "Grok Bot" in page.text
    grant_id = _GRANT_ID.search(page.text)
    assert grant_id
    blocked = owner_c.post(
        "/oauth/grants/revoke", data={"grant_id": grant_id.group(1), "csrf": "nope"}
    )
    assert blocked.status_code == 403
    assert "list_folder" in tool_names(owner_c, access)
    revoked = post(owner_c, "/oauth/grants/revoke", grant_id=grant_id.group(1))
    assert revoked.status_code == 303
    page = owner_c.get("/").text
    assert "No apps connected" in page
    assert grant_id.group(1) not in page
    denied = owner_c.post(
        "/mcp", json=LIST, headers={**MCP_HEADERS, "Authorization": f"Bearer {access}"}
    )
    assert denied.status_code == 401
    assert f'resource_metadata="{METADATA}"' in denied.headers["www-authenticate"]
    refresh_denied = owner_c.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": client_id,
            "resource": RESOURCE,
        },
    )
    assert refresh_denied.status_code == 400


def test_dashboard_cookie_cannot_call_mcp(owner_c) -> None:
    assert owner_c.cookies.get(SESSION_COOKIE)
    response = owner_c.post("/mcp", json=INIT, headers=MCP_HEADERS)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == f'Bearer resource_metadata="{METADATA}"'


def test_continue_ignores_an_external_url_query(owner_c) -> None:
    response = owner_c.get(
        "/oauth/continue",
        params={"url": "https://evil.example/phish", "ticket": "nope"},
    )
    assert response.status_code == 400
    assert "evil.example" not in response.text
    assert "http-equiv" not in response.text
    assert "location" not in response.headers


def test_non_owner_cannot_post_consent(c) -> None:
    c.cookies.set(SESSION_COOKIE, forge_session("eve@example.com"))
    response = c.post("/oauth/authorize", data={"decision": "allow", "csrf": "tok"})
    assert response.status_code == 403
    assert "location" not in response.headers


def test_oauth_bearer_cannot_post_to_dashboard(owner_c) -> None:
    created = register(owner_c, GROK, name="Grok Bot")
    client_id = created.json()["client_id"]
    verifier, params = auth_params(client_id, GROK)
    assert owner_c.get("/oauth/authorize", params=params).status_code == 200
    code = code_from(posted_redirect(owner_c, post(owner_c, "/oauth/authorize", decision="allow")))
    access = exchange(owner_c, client_id, code, verifier, GROK).json()["access_token"]
    grant_id = next(iter(owner_c.app.state.dashboard.store.hgetall(GRANTS_KEY)))
    stranger = client(owner_c.app)
    denied = stranger.post(
        "/oauth/grants/revoke",
        data={"grant_id": grant_id, "csrf": "tok"},
        headers={"Authorization": f"Bearer {access}"},
    )
    assert denied.status_code == 403
    assert "list_folder" in tool_names(owner_c, access)


def test_access_check_does_not_clobber_rotated_grant(owner_c) -> None:
    created = register(owner_c, DONE, name="Local test")
    client_id = created.json()["client_id"]
    verifier, params = auth_params(client_id, DONE)
    assert owner_c.get("/oauth/authorize", params=params).status_code == 200
    code = code_from(posted_redirect(owner_c, post(owner_c, "/oauth/authorize", decision="allow")))
    access = exchange(owner_c, client_id, code, verifier, DONE).json()["access_token"]
    oauth = owner_c.app.state.dashboard.mcp_oauth
    store = owner_c.app.state.dashboard.store
    grant_id = next(iter(store.hgetall(GRANTS_KEY)))
    before = store.hget(GRANTS_KEY, grant_id)
    assert oauth.resolve_access(access) is not None
    after = store.hget(GRANTS_KEY, grant_id)
    assert json.loads(after)["access_hashes"] == json.loads(before)["access_hashes"]
    assert json.loads(after)["refresh_hash"] == json.loads(before)["refresh_hash"]
    store.set(f"oauth:seen:{grant_id}", "2099-01-01T00:00:00+00:00", ex=3600)
    assert "2099-01-01T00:00:00+00:00" in owner_c.get("/").text

    original = oauth._grant
    issued: dict[str, str] = {}
    state = {"done": False}

    def hooked(gid: str):
        grant = original(gid)
        if grant is not None and not state["done"]:
            state["done"] = True
            fresh = OAuthGrant.from_json(grant.to_json())
            oauth._issue_tokens(fresh)
            assert fresh.refresh_hash is not None
            issued["hash"] = fresh.refresh_hash
        return grant

    oauth._grant = hooked
    try:
        assert oauth.resolve_access(access) is not None
    finally:
        oauth._grant = original
    assert original(grant_id) is not None
    assert original(grant_id).refresh_hash == issued["hash"]
    assert issued["hash"] != json.loads(before)["refresh_hash"]
