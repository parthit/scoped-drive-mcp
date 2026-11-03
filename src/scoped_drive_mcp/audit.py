"""JSON-lines audit log on stdout (shows up in Vercel runtime logs), optionally mirrored to
extra sinks such as the capped Redis activity list shown on the dashboard.

Only identifiers and decisions are logged: never file contents, names, queries or secrets.
"""

import json
import logging
import sys
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any, Literal

logger = logging.getLogger(__name__)

Decision = Literal["allow", "deny", "error"]
Sink = Callable[[dict[str, Any]], None]

_sinks: list[Sink] = []


def set_sinks(sinks: Iterable[Sink]) -> None:
    """Replace the extra sinks (stdout is always written)."""
    _sinks[:] = list(sinks)


def _emit(record: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(record, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    for sink in list(_sinks):
        try:
            sink(record)
        except Exception:
            logger.warning("audit sink failed", exc_info=True)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def audit(
    *,
    tool: str,
    decision: Decision,
    reason: str,
    token_name: str | None,
    role: str | None,
    **ids: str | None,
) -> None:
    record: dict[str, Any] = {
        "ts": _now(),
        "event": "tool_call",
        "token_name": token_name,
        "role": role,
        "tool": tool,
    }
    record.update({k: v for k, v in ids.items() if v is not None})
    record["decision"] = decision
    record["reason"] = reason
    _emit(record)


def audit_auth_failure(reason: str, path: str) -> None:
    _emit({"ts": _now(), "event": "auth", "path": path, "decision": "deny", "reason": reason})


def audit_owner(action: str, decision: Decision = "allow", **fields: str | None) -> None:
    """Dashboard actions: sign-in, grant, revoke, request decisions."""
    record: dict[str, Any] = {"ts": _now(), "event": "owner", "action": action}
    record.update({k: v for k, v in fields.items() if v is not None})
    record["decision"] = decision
    _emit(record)
