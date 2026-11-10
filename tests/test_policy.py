import json

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from scoped_drive_mcp.auth import Principal, current_principal
from scoped_drive_mcp.config import Role
from scoped_drive_mcp.policy import (
    ADMIN_TOOLS,
    EDITOR_TOOLS,
    ROLE_TOOLS,
    VIEWER_TOOLS,
    is_allowed,
    require,
)
from scoped_drive_mcp.server import create_mcp

VALID_ARGS = {
    "search_files": {"query": "plan"},
    "list_folder": {},
    "get_metadata": {"file_id": "notes-txt"},
    "read_file": {"file_id": "notes-txt"},
    "create_folder": {"name": "New folder"},
    "create_doc": {"title": "New doc", "content": "hello"},
    "upload_file": {"name": "a.txt", "mime_type": "text/plain", "content_text": "x"},
    "update_file_content": {"file_id": "notes-txt", "content": "replaced"},
    "rename_file": {"file_id": "notes-txt", "new_name": "renamed.txt"},
    "trash_file": {"file_id": "notes-txt"},
    "request_access": {"description": "the budget sheet", "reason": "to answer a question"},
    "check_access_request": {"request_id": "A" * 32},
}

MAILBOX_TOOLS = {
    "request_link",
    "list_links",
    "send_message",
    "list_inbox",
    "check_messages",
    "reply",
    "mark_read",
}
VIEWER_EXPECTED = {
    "search_files",
    "list_folder",
    "get_metadata",
    "read_file",
    "request_access",
    "check_access_request",
} | MAILBOX_TOOLS
EXPECTED = {
    Role.VIEWER: VIEWER_EXPECTED,
    Role.EDITOR: VIEWER_EXPECTED
    | {
        "create_folder",
        "create_doc",
        "upload_file",
        "update_file_content",
        "rename_file",
    },
    Role.ADMIN: set(VALID_ARGS) | MAILBOX_TOOLS,
}

FORBIDDEN_TOOL_WORDS = ("move", "share", "permission", "delete", "parent")


def test_role_map_matches_spec() -> None:
    assert VIEWER_TOOLS == EXPECTED[Role.VIEWER]
    assert EDITOR_TOOLS == EXPECTED[Role.EDITOR]
    assert ADMIN_TOOLS == EXPECTED[Role.ADMIN]
    assert set(ROLE_TOOLS) == set(Role)


def test_unknown_role_and_tool() -> None:
    assert not is_allowed(None, "read_file")
    assert not is_allowed("superuser", "read_file")
    assert not is_allowed(Role.ADMIN, "delete_file")
    with pytest.raises(ValueError):
        require("move_file")


@pytest.mark.anyio
async def test_registered_tools_are_exactly_the_role_map(service) -> None:
    mcp = create_mcp(service)
    names = {t.name for t in mcp._tool_manager.list_tools()}
    assert names == set(ADMIN_TOOLS)
    for name in names:
        assert not any(word in name for word in FORBIDDEN_TOOL_WORDS)


@pytest.mark.anyio
@pytest.mark.parametrize("role", list(Role))
@pytest.mark.parametrize("tool", sorted(VALID_ARGS))
async def test_role_matrix(service, access, capsys, role: Role, tool: str) -> None:
    mcp = create_mcp(service, access)
    token = current_principal.set(Principal(token_name=f"{role}-tok", role=role))
    try:
        if tool in EXPECTED[role]:
            await mcp.call_tool(tool, VALID_ARGS[tool])
            decision = "allow"
        else:
            with pytest.raises(ToolError, match="Permission denied"):
                await mcp.call_tool(tool, VALID_ARGS[tool])
            decision = "deny"
    finally:
        current_principal.reset(token)

    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.strip()]
    assert lines[-1]["tool"] == tool
    assert lines[-1]["decision"] == decision
    assert lines[-1]["token_name"] == f"{role}-tok"
    assert lines[-1]["role"] == str(role)


@pytest.mark.anyio
async def test_list_tools_filtered_by_role(service) -> None:
    mcp = create_mcp(service)
    for role in Role:
        token = current_principal.set(Principal(token_name="t", role=role))
        try:
            names = {t.name for t in await mcp.list_tools()}
        finally:
            current_principal.reset(token)
        assert names == EXPECTED[role]
    assert await mcp.list_tools() == []


@pytest.mark.anyio
async def test_no_principal_is_denied(service) -> None:
    mcp = create_mcp(service)
    with pytest.raises(ToolError, match="Permission denied"):
        await mcp.call_tool("read_file", {"file_id": "notes-txt"})


@pytest.mark.anyio
async def test_scope_denial_is_audited(service, capsys) -> None:
    # without an AccessService (no APP_BASE_URL) scope denials stay plain "Forbidden" errors
    mcp = create_mcp(service)
    token = current_principal.set(Principal(token_name="admin-tok", role=Role.ADMIN))
    try:
        with pytest.raises(ToolError, match="Forbidden"):
            await mcp.call_tool("read_file", {"file_id": "outside-file"})
        with pytest.raises(ToolError, match="Forbidden"):
            await mcp.call_tool("create_folder", {"name": "x", "parent_id": "outside-folder"})
        with pytest.raises(ToolError, match="Invalid input"):
            await mcp.call_tool("read_file", {"file_id": "bad id"})
    finally:
        current_principal.reset(token)
    out = capsys.readouterr().out
    lines = [json.loads(line) for line in out.splitlines()]
    assert [ln["decision"] for ln in lines] == ["deny", "deny", "error"]
    assert lines[0]["file_id"] == "outside-file"
    assert lines[1]["parent_id"] == "outside-folder"
    assert "outside plan" not in out


@pytest.mark.anyio
async def test_audit_never_contains_content(service, capsys) -> None:
    mcp = create_mcp(service)
    token = current_principal.set(Principal(token_name="admin-tok", role=Role.ADMIN))
    try:
        await mcp.call_tool("read_file", {"file_id": "doc-deep"})
        await mcp.call_tool("create_doc", {"title": "Secret title", "content": "SECRET BODY"})
    finally:
        current_principal.reset(token)
    out = capsys.readouterr().out
    assert "deep secret plan" not in out
    assert "SECRET BODY" not in out and "Secret title" not in out
    for line in out.splitlines():
        record = json.loads(line)
        assert {"ts", "token_name", "role", "tool", "decision", "reason"} <= record.keys()
