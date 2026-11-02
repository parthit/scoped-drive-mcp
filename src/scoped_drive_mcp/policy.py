"""Role-to-tool map and the `require(tool)` decorator that enforces it and writes the audit log."""

import functools
import logging
from collections.abc import Awaitable, Callable
from typing import Any, ParamSpec, TypeVar

from mcp.server.fastmcp.exceptions import ToolError

from .audit import audit
from .auth import Principal, current_principal
from .config import Role
from .scope import ForbiddenError, InvalidInputError

logger = logging.getLogger(__name__)

VIEWER_TOOLS: frozenset[str] = frozenset(
    {"search_files", "list_folder", "get_metadata", "read_file"}
)
EDITOR_TOOLS: frozenset[str] = VIEWER_TOOLS | {
    "create_folder",
    "create_doc",
    "upload_file",
    "update_file_content",
    "rename_file",
}
ADMIN_TOOLS: frozenset[str] = EDITOR_TOOLS | {"trash_file"}

ROLE_TOOLS: dict[Role, frozenset[str]] = {
    Role.VIEWER: VIEWER_TOOLS,
    Role.EDITOR: EDITOR_TOOLS,
    Role.ADMIN: ADMIN_TOOLS,
}

ALL_TOOLS = ADMIN_TOOLS

_AUDITED_ID_ARGS = ("file_id", "folder_id", "parent_id")

P = ParamSpec("P")
R = TypeVar("R")


class PermissionDeniedError(Exception):
    """The caller's role does not include this tool."""


def is_allowed(role: Role | str | None, tool: str) -> bool:
    if role is None:
        return False
    try:
        return tool in ROLE_TOOLS[Role(role)]
    except ValueError:
        return False


def check_permission(principal: Principal | None, tool: str) -> Principal:
    if principal is None:
        raise PermissionDeniedError("not authenticated")
    if not is_allowed(principal.role, tool):
        raise PermissionDeniedError(f"role '{principal.role}' may not call '{tool}'")
    return principal


def require(tool: str) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
    """Wrap an async tool: check the caller's role, audit the call, and map errors.

    The wrapper keeps the original signature (via functools.wraps) so FastMCP still
    generates the right input schema.
    """
    if tool not in ALL_TOOLS:
        raise ValueError(f"tool {tool!r} is not in the role map")

    def decorator(fn: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
        @functools.wraps(fn)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            principal = current_principal.get()
            ids: dict[str, Any] = {
                k: kwargs.get(k) if isinstance(kwargs.get(k), str) else None
                for k in _AUDITED_ID_ARGS
            }
            who = {
                "token_name": principal.token_name if principal else None,
                "role": str(principal.role) if principal else None,
            }
            try:
                check_permission(principal, tool)
            except PermissionDeniedError as exc:
                audit(tool=tool, decision="deny", reason=str(exc), **who, **ids)
                raise ToolError(f"Permission denied: {exc}") from None

            try:
                result = await fn(*args, **kwargs)
            except ForbiddenError as exc:
                audit(tool=tool, decision="deny", reason=str(exc), **who, **ids)
                raise ToolError(f"Forbidden: {exc}") from None
            except InvalidInputError as exc:
                audit(tool=tool, decision="error", reason=str(exc), **who, **ids)
                raise ToolError(f"Invalid input: {exc}") from None
            except Exception as exc:
                audit(tool=tool, decision="error", reason=type(exc).__name__, **who, **ids)
                logger.exception("tool %s failed", tool)
                raise ToolError("Drive request failed; see server logs") from None
            audit(tool=tool, decision="allow", reason="ok", **who, **ids)
            return result

        return wrapper

    return decorator
