"""access_required errors, request dedupe, approve/deny flows and the two request tools."""

import json
import re

import pytest

from scoped_drive_mcp.access import REQUEST_TTL, AccessRequests
from scoped_drive_mcp.store import AllowEntry, MemoryStore, PrefixedStore
from tests.conftest import BASE_URL, BOT_EMAIL, FakeClock
from tests.dash import client, login, mcp_call, post


@pytest.fixture
def c(p2_app):
    c = client(p2_app)
    login(c)
    return c


def requests_of(app) -> AccessRequests:
    return app.state.dashboard.requests


def test_access_required_shape(c) -> None:
    result = mcp_call(c, "read_file", file_id="priv-secret")
    assert result["isError"] is True
    payload = result["structuredContent"]
    assert payload["error"] == "access_required"
    assert re.fullmatch(r"[A-Za-z0-9_-]{32}", payload["request_id"])  # 192 random bits
    assert payload["approval_url"] == f"{BASE_URL}/requests/{payload['request_id']}"
    assert payload["file_id"] == "priv-secret"
    assert "approval" in payload["message"] and payload["approval_url"] in payload["message"]
    assert json.loads(result["content"][0]["text"]) == payload
    assert "TOP SECRET" not in json.dumps(result) and "payroll" not in json.dumps(result)


def test_request_record_contents(c, p2_app, world) -> None:
    world.share("stray-shared", BOT_EMAIL)
    payload = mcp_call(c, "get_metadata", file_id="stray-shared")["structuredContent"]
    req = requests_of(p2_app).get(payload["request_id"])
    assert req.status == "pending"
    assert req.tool == "get_metadata" and req.token_name == "viewer-tok"
    assert req.file_id == "stray-shared"
    assert req.file_name == "secret from eve.txt"  # the bot can see it, so the owner sees a name
    assert req.reason and req.created_at
    # a file the bot cannot see has no name
    payload = mcp_call(c, "read_file", file_id="priv-secret")["structuredContent"]
    assert requests_of(p2_app).get(payload["request_id"]).file_name is None


def test_pending_requests_are_deduped(c, p2_app) -> None:
    first = mcp_call(c, "read_file", file_id="priv-secret")["structuredContent"]
    again = mcp_call(c, "get_metadata", file_id="priv-secret")["structuredContent"]
    assert first["request_id"] == again["request_id"]
    other = mcp_call(c, "read_file", file_id="priv-other")["structuredContent"]
    assert other["request_id"] != first["request_id"]
    assert len(requests_of(p2_app).recent()) == 2


def test_every_denying_tool_creates_a_request(c) -> None:
    calls = [
        ("list_folder", "viewer", {"folder_id": "priv"}),
        ("create_folder", "editor", {"name": "x", "parent_id": "priv"}),
        ("update_file_content", "editor", {"file_id": "priv-other", "content": "x"}),
        ("rename_file", "editor", {"file_id": "loose-two", "new_name": "x"}),
        ("trash_file", "admin", {"file_id": "loose-doc"}),
    ]
    for tool, role, args in calls:
        result = mcp_call(c, tool, role, **args)
        assert result["structuredContent"]["error"] == "access_required", tool


def test_role_denial_does_not_create_a_request(c, p2_app) -> None:
    result = mcp_call(c, "trash_file", "viewer", file_id="priv-secret")
    assert result["isError"] and "Permission denied" in result["content"][0]["text"]
    result = mcp_call(c, "read_file", file_id="bad id!")
    assert "Invalid input" in result["content"][0]["text"]
    assert requests_of(p2_app).recent() == []


def test_protected_item_is_not_an_access_request(c, p2_app) -> None:
    post(c, "/grant", file_id="proj")
    result = mcp_call(c, "rename_file", "editor", file_id="proj", new_name="x")
    assert "Forbidden" in result["content"][0]["text"]
    assert requests_of(p2_app).recent() == []


def test_approve_item_then_retry_then_revoke(c, p2_app, world) -> None:
    payload = mcp_call(c, "read_file", file_id="priv-secret")["structuredContent"]
    path = payload["approval_url"].removeprefix(BASE_URL)
    page = c.get(path)
    assert page.status_code == 200
    assert "payroll.txt" in page.text and "viewer-tok" in page.text and "read_file" in page.text
    assert "Share just this item" in page.text and "Share its whole parent folder" in page.text

    r = post(c, f"{path}/approve", target_id="priv-secret")
    assert r.status_code == 303
    assert [p["emailAddress"] for p in world.files["priv-secret"].permissions] == [BOT_EMAIL]
    assert world.files["priv"].permissions == []

    result = mcp_call(c, "read_file", file_id="priv-secret")
    assert result["isError"] is False
    assert result["structuredContent"]["content"] == "TOP SECRET payroll"
    status = mcp_call(c, "check_access_request", request_id=payload["request_id"])
    assert status["structuredContent"]["status"] == "approved"
    assert status["structuredContent"]["granted_id"] == "priv-secret"
    # the sibling was not shared
    assert mcp_call(c, "read_file", file_id="priv-other")["isError"] is True

    entry = p2_app.state.dashboard.allowlist.get("priv-secret")
    assert entry.request_id == payload["request_id"]
    post(c, "/revoke", file_id="priv-secret")
    result = mcp_call(c, "read_file", file_id="priv-secret")
    new = result["structuredContent"]
    assert new["error"] == "access_required"
    assert new["request_id"] != payload["request_id"]  # the old one is no longer pending


def test_approve_parent_folder(c, world) -> None:
    payload = mcp_call(c, "read_file", file_id="priv-secret")["structuredContent"]
    path = payload["approval_url"].removeprefix(BASE_URL)
    post(c, f"{path}/approve", target_id="priv")
    assert [p["emailAddress"] for p in world.files["priv"].permissions] == [BOT_EMAIL]
    assert mcp_call(c, "read_file", file_id="priv-secret")["isError"] is False
    assert mcp_call(c, "read_file", file_id="priv-other")["isError"] is False


def test_approve_rejects_other_targets(c, world, p2_app) -> None:
    payload = mcp_call(c, "read_file", file_id="priv-secret")["structuredContent"]
    path = payload["approval_url"].removeprefix(BASE_URL)
    post(c, f"{path}/approve", target_id="proj")
    assert world.files["proj"].permissions == []
    assert requests_of(p2_app).get(payload["request_id"]).status == "pending"
    assert "Pick the requested item" in c.get(path).text


def test_drive_alias_does_not_open_an_access_request(c, p2_app) -> None:
    for file_id in ("root", "appDataFolder"):
        result = mcp_call(c, "read_file", file_id=file_id)
        assert result["isError"] and "Invalid input" in result["content"][0]["text"]
    assert requests_of(p2_app).recent() == []


def test_substitute_item_when_the_requested_file_is_not_in_the_owners_drive(c, world) -> None:
    payload = mcp_call(c, "get_metadata", file_id="stray-shared")["structuredContent"]
    path = payload["approval_url"].removeprefix(BASE_URL)
    page = c.get(path).text
    assert "pick a different item" in page and "Share just this item" not in page
    post(c, f"{path}/approve", target_id="loose-two")
    assert [p["emailAddress"] for p in world.files["loose-two"].permissions] == [BOT_EMAIL]
    status = mcp_call(c, "check_access_request", request_id=payload["request_id"])
    assert status["structuredContent"]["granted_id"] == "loose-two"


def test_my_drive_root_itself_cannot_be_approved(c, world, p2_app) -> None:
    payload = mcp_call(c, "read_file", file_id="owner-root")["structuredContent"]
    path = payload["approval_url"].removeprefix(BASE_URL)
    page = c.get(path).text
    assert "Share just this item" not in page and "pick a different item" in page
    post(c, f"{path}/approve", target_id="owner-root")
    assert p2_app.state.dashboard.allowlist.entries() == {}
    assert requests_of(p2_app).get(payload["request_id"]).status == "pending"
    assert "whole My Drive" in c.get(path).text
    post(c, f"{path}/approve", target_id="proj")
    assert [p["emailAddress"] for p in world.files["proj"].permissions] == [BOT_EMAIL]


def test_share_all_failure_does_not_flash_success(c, p2_app) -> None:
    p2_app.state.dashboard.allowlist.add(
        AllowEntry("stray-shared", "eve secret", "text/plain", None)
    )
    assert post(c, "/access/share-bot").status_code == 303
    page = c.get("/access").text
    assert "Could not share 1 item" in page
    assert "Shared 0 item" not in page
    assert 'class="flash ok"' not in page


def test_my_drive_root_is_not_offered(c) -> None:
    payload = mcp_call(c, "read_file", file_id="loose-doc")["structuredContent"]
    page = c.get(payload["approval_url"].removeprefix(BASE_URL)).text
    assert "Share just this item" in page and "parent folder" not in page


def test_deny_flow(c, world, p2_app) -> None:
    payload = mcp_call(c, "read_file", file_id="priv-secret")["structuredContent"]
    path = payload["approval_url"].removeprefix(BASE_URL)
    assert post(c, f"{path}/deny").status_code == 303
    assert world.files["priv-secret"].permissions == []
    status = mcp_call(c, "check_access_request", request_id=payload["request_id"])
    assert status["structuredContent"]["status"] == "denied"
    assert mcp_call(c, "read_file", file_id="priv-secret")["isError"] is True
    # a decided request cannot be approved afterwards
    post(c, f"{path}/approve", target_id="priv-secret")
    assert world.files["priv-secret"].permissions == []
    assert requests_of(p2_app).get(payload["request_id"]).status == "denied"


def test_approval_needs_owner_and_csrf(p2_app, world) -> None:
    owner = client(p2_app)
    login(owner)
    payload = mcp_call(owner, "read_file", file_id="priv-secret")["structuredContent"]
    path = payload["approval_url"].removeprefix(BASE_URL)
    stranger = client(p2_app)
    assert stranger.get(path).status_code == 303
    assert stranger.post(f"{path}/approve", data={"target_id": "priv-secret"}).status_code == 403
    assert owner.post(f"{path}/approve", data={"target_id": "priv-secret"}).status_code == 403
    assert world.files["priv-secret"].permissions == []


def test_request_access_tool_without_file_id(c, p2_app, world) -> None:
    result = mcp_call(
        c, "request_access", description="the Q3 memo", reason="the user asked for a summary"
    )
    assert result["isError"] is False
    out = result["structuredContent"]
    assert out["status"] == "pending" and out["approval_url"].endswith(out["request_id"])
    req = requests_of(p2_app).get(out["request_id"])
    assert req.description == "the Q3 memo" and req.file_id is None
    assert req.tool == "request_access" and req.token_name == "viewer-tok"

    path = out["approval_url"].removeprefix(BASE_URL)
    page = c.get(path).text
    assert "the Q3 memo" in page and "Pick an item" in page
    picker = c.get(f"/browse?request={out['request_id']}").text
    assert "Share for this request" in picker
    post(c, f"{path}/approve", target_id="loose-two")
    assert [p["emailAddress"] for p in world.files["loose-two"].permissions] == [BOT_EMAIL]
    status = mcp_call(c, "check_access_request", request_id=out["request_id"])
    assert status["structuredContent"]["granted_id"] == "loose-two"
    assert mcp_call(c, "read_file", file_id="loose-two")["isError"] is False


def test_request_access_tool_with_file_id(c, p2_app) -> None:
    auto = mcp_call(c, "read_file", file_id="priv-secret")["structuredContent"]
    out = mcp_call(c, "request_access", description="payroll", reason="r", file_id="priv-secret")[
        "structuredContent"
    ]
    assert out["request_id"] == auto["request_id"]  # deduped with the automatic request
    post(c, "/grant", file_id="loose-doc")
    out = mcp_call(c, "request_access", description="memo", reason="r", file_id="loose-doc")
    assert out["structuredContent"]["status"] == "already_allowed"


@pytest.mark.parametrize(
    "args",
    [
        {"description": "", "reason": "r"},
        {"description": "d", "reason": "  "},
        {"description": "x" * 501, "reason": "r"},
        {"description": "d", "reason": "r", "file_id": "bad id"},
    ],
)
def test_request_access_validation(c, args) -> None:
    result = mcp_call(c, "request_access", **args)
    assert result["isError"] and "Invalid input" in result["content"][0]["text"]


def test_check_access_request_tool(c) -> None:
    out = mcp_call(c, "check_access_request", request_id="A" * 32)["structuredContent"]
    assert out["status"] == "not_found"
    result = mcp_call(c, "check_access_request", request_id="../../etc")
    assert result["isError"] and "Invalid input" in result["content"][0]["text"]
    pending = mcp_call(c, "read_file", file_id="priv-secret")["structuredContent"]
    out = mcp_call(c, "check_access_request", request_id=pending["request_id"])
    assert out["structuredContent"]["status"] == "pending"
    assert out["structuredContent"]["approval_url"] == pending["approval_url"]


def test_requests_page_lists_pending_and_decided(c) -> None:
    a = mcp_call(c, "read_file", file_id="priv-secret")["structuredContent"]
    mcp_call(c, "read_file", file_id="priv-other")
    post(c, f"/requests/{a['request_id']}/deny")
    page = c.get("/requests").text
    assert page.count('class="pill pending"') == 1 and page.count('class="pill bad"') == 1


def test_requests_expire_after_7_days() -> None:
    clock = FakeClock()
    reqs = AccessRequests(PrefixedStore(MemoryStore(clock=clock)))
    req, created = reqs.create(tool="read_file", token_name="t", reason="r", file_id="f1")
    assert created and reqs.get(req.id) is not None
    clock.advance(REQUEST_TTL - 10)
    assert reqs.create(tool="read_file", token_name="t", reason="r", file_id="f1")[0].id == req.id
    clock.advance(20)
    assert reqs.get(req.id) is None
    assert reqs.recent() == []
    again, created = reqs.create(tool="read_file", token_name="t", reason="r", file_id="f1")
    assert created and again.id != req.id


def test_no_access_service_without_base_url(world) -> None:
    from scoped_drive_mcp.server import build_app
    from tests.conftest import make_settings

    app = build_app(
        make_settings(root_folder_id=None, app_base_url=None),
        world.as_user(BOT_EMAIL),
        store=MemoryStore(),
    )
    c = client(app)
    result = mcp_call(c, "read_file", file_id="priv-secret")
    assert result["isError"] and "Forbidden" in result["content"][0]["text"]
    result = mcp_call(c, "request_access", description="d", reason="r")
    assert result["isError"] and "not configured" in result["content"][0]["text"]
