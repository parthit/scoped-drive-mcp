"""In-process smoke tests of the ASGI app (no lifespan, like a serverless runtime)."""

import json
import secrets

import anyio
import httpx
import pytest

from scoped_drive_mcp.server import build_app
from tests.conftest import CLIENT_SECRET, REFRESH_TOKEN, TOKENS, make_settings

MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}

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


def rpc(method: str, params: dict | None = None, id_: int = 2) -> dict:
    msg: dict = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def auth(role: str) -> dict:
    return {**MCP_HEADERS, "Authorization": f"Bearer {TOKENS[role]}"}


@pytest.fixture
async def client(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://example.vercel.app") as c:
        yield c


@pytest.mark.anyio
async def test_health_needs_no_auth(client, drive) -> None:
    r = await client.get("/health")
    assert r.status_code == 200
    body = r.json()
    # only Redis is missing in the test settings (an in-memory store is injected)
    assert body["status"] == "incomplete"
    assert body["missing"] == ["UPSTASH_REDIS_REST_URL", "UPSTASH_REDIS_REST_TOKEN"]
    assert body["bot_connected"] is True and body["bot_source"] == "env"
    assert body["owner_connected"] is False
    assert REFRESH_TOKEN not in r.text and CLIENT_SECRET not in r.text
    assert drive.get_calls == [] and drive.queries == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    "headers",
    [
        MCP_HEADERS,
        {**MCP_HEADERS, "Authorization": f"Bearer {secrets.token_urlsafe(32)}"},
        {**MCP_HEADERS, "Authorization": f"Basic {secrets.token_urlsafe(12)}"},
        {**MCP_HEADERS, "Authorization": ""},
    ],
)
async def test_mcp_rejects_missing_or_invalid_token(client, headers) -> None:
    r = await client.post("/mcp", json=INIT, headers=headers)
    assert r.status_code == 401
    assert r.headers["www-authenticate"].startswith("Bearer")
    r = await client.get("/mcp", headers=headers)
    assert r.status_code == 401


async def _initialize(client, role: str) -> None:
    r = await client.post("/mcp", json=INIT, headers=auth(role))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"]["serverInfo"]["name"] == "scoped-drive"


@pytest.mark.anyio
@pytest.mark.parametrize(("role", "count"), [("viewer", 6), ("editor", 11), ("admin", 12)])
async def test_initialize_and_list_tools(client, role: str, count: int) -> None:
    await _initialize(client, role)
    r = await client.post("/mcp", json=rpc("tools/list"), headers=auth(role))
    assert r.status_code == 200, r.text
    tools = {t["name"] for t in r.json()["result"]["tools"]}
    assert len(tools) == count
    assert "read_file" in tools
    assert ("trash_file" in tools) == (role == "admin")


@pytest.mark.anyio
async def test_tool_calls_over_http(client) -> None:
    await _initialize(client, "viewer")
    call = rpc("tools/call", {"name": "read_file", "arguments": {"file_id": "notes-txt"}})
    r = await client.post("/mcp", json=call, headers=auth("viewer"))
    result = r.json()["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["content"] == "plan notes inside"

    call = rpc("tools/call", {"name": "read_file", "arguments": {"file_id": "outside-file"}})
    result = (await client.post("/mcp", json=call, headers=auth("viewer"))).json()["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["error"] == "access_required"
    assert json.loads(result["content"][0]["text"])["error"] == "access_required"
    assert "outside plan" not in json.dumps(result)

    call = rpc("tools/call", {"name": "trash_file", "arguments": {"file_id": "notes-txt"}})
    result = (await client.post("/mcp", json=call, headers=auth("viewer"))).json()["result"]
    assert result["isError"] is True
    assert "Permission denied" in result["content"][0]["text"]


@pytest.mark.anyio
async def test_principal_does_not_leak_between_requests(client) -> None:
    await _initialize(client, "admin")
    r = await client.post("/mcp", json=rpc("tools/list"), headers=auth("viewer"))
    assert len(r.json()["result"]["tools"]) == 6


def test_starlette_testclient_with_lifespan(app) -> None:
    from starlette.testclient import TestClient

    with TestClient(app, base_url="https://example.vercel.app") as tc:
        assert tc.get("/health").status_code == 200
        assert tc.post("/mcp", json=INIT, headers=MCP_HEADERS).status_code == 401
        r = tc.post("/mcp", json=INIT, headers=auth("editor"))
        assert r.status_code == 200
        r = tc.post("/mcp", json=rpc("tools/list"), headers=auth("editor"))
        assert len(r.json()["result"]["tools"]) == 11


@pytest.mark.anyio
async def test_misconfigured_app_health(monkeypatch) -> None:
    for name in (
        "ROOT_FOLDER_ID",
        "API_TOKENS",
        "GOOGLE_OAUTH_CLIENT_ID",
        "GOOGLE_OAUTH_CLIENT_SECRET",
        "GOOGLE_OAUTH_REFRESH_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "do-not-leak-this")
    app = build_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get("/health")
        assert r.status_code == 503
        assert r.json()["status"] == "misconfigured"
        assert "do-not-leak-this" not in r.text
        settings = {p["setting"] for p in r.json()["problems"]}
        assert settings == {"API_TOKENS"}
        assert (await c.post("/mcp", json=INIT)).status_code == 503
        assert (await c.get("/browse")).status_code == 503


@pytest.mark.anyio
@pytest.mark.parametrize("method", ["GET", "DELETE"])
async def test_authenticated_get_and_delete_return_405_promptly(client, method: str) -> None:
    headers = {"Authorization": f"Bearer {TOKENS['viewer']}", "Accept": "text/event-stream"}
    with anyio.fail_after(5):
        r = await client.request(method, "/mcp", headers=headers)
    assert r.status_code == 405
    assert r.headers["allow"] == "POST"
    # authentication still runs first
    r = await client.request(method, "/mcp", headers={"Accept": "text/event-stream"})
    assert r.status_code == 401


# ---- no silent in-memory store on Vercel -------------------------------------------------


@pytest.fixture
def no_redis_env(monkeypatch):
    for name in (
        "UPSTASH_REDIS_REST_URL",
        "UPSTASH_REDIS_REST_TOKEN",
        "KV_REST_API_URL",
        "KV_REST_API_TOKEN",
        "REDIS_REST_URL",
        "REDIS_REST_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.anyio
async def test_vercel_without_redis_refuses_to_serve(monkeypatch, no_redis_env, drive) -> None:
    monkeypatch.setenv("VERCEL", "1")
    app = build_app(make_settings(), drive)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://x.vercel.app") as c:
        r = await c.get("/health")
        assert r.status_code == 503
        body = r.json()
        assert body["status"] == "misconfigured"
        assert body["store_error"] == "redis_not_configured"
        assert "UPSTASH_REDIS_REST_URL" in body["missing"] and "Redis" in body["detail"]
        assert REFRESH_TOKEN not in r.text and CLIENT_SECRET not in r.text
        r = await c.post("/mcp", json=INIT, headers=auth("admin"))
        assert r.status_code == 503 and "storage" in r.json()["error"]
        for path in ("/", "/browse", "/login"):
            page = await c.get(path)
            assert page.status_code == 503 and "Redis is not configured" in page.text
    assert drive.get_calls == [] and drive.queries == []


def test_local_without_redis_uses_memory(monkeypatch, no_redis_env, drive) -> None:
    monkeypatch.delenv("VERCEL", raising=False)
    app = build_app(make_settings(), drive)
    assert app.state.dashboard.store.kind == "memory"
    monkeypatch.setenv("VERCEL", "")
    assert build_app(make_settings(), drive).state.dashboard.store.kind == "memory"


def test_vercel_with_redis_builds_normally(monkeypatch, drive) -> None:
    monkeypatch.setenv("VERCEL", "1")
    settings = make_settings(
        redis_rest_url="https://example.upstash.io", redis_rest_token=secrets.token_urlsafe(16)
    )
    assert build_app(settings, drive).state.dashboard.store.kind == "redis"
