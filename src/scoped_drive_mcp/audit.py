"""JSON-lines audit log on stdout (shows up in Vercel runtime logs).

Only identifiers and decisions are logged: never file contents, names, queries or secrets.
"""

import json
import sys
from datetime import UTC, datetime
from typing import Any, Literal

Decision = Literal["allow", "deny", "error"]


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
        "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
        "event": "tool_call",
        "token_name": token_name,
        "role": role,
        "tool": tool,
    }
    record.update({k: v for k, v in ids.items() if v is not None})
    record["decision"] = decision
    record["reason"] = reason
    sys.stdout.write(json.dumps(record, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def audit_auth_failure(reason: str, path: str) -> None:
    record = {
        "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
        "event": "auth",
        "path": path,
        "decision": "deny",
        "reason": reason,
    }
    sys.stdout.write(json.dumps(record, separators=(",", ":")) + "\n")
    sys.stdout.flush()
