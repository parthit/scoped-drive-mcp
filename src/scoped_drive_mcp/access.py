"""Access requests: created when a tool is denied because of scope (never because of role),
or explicitly through the `request_access` tool. The owner approves or denies them on the
dashboard at APP_BASE_URL/requests/<id>.

Storage (all keys expire after 7 days):
- `req:<id>`           the request as JSON
- `req:pending:<file>` id of the pending request for that file (dedupe)
- `requests:index`     newest-first list of request ids (capped)
- `requests:pending`   ids that are still pending, so the nav count is not a scan of the history
"""

import json
import re
import secrets
from dataclasses import asdict, dataclass, field
from typing import Any

from .scope import InvalidInputError, validate_drive_id
from .store import KeyValueStore, utc_now

REQUEST_TTL = 7 * 24 * 3600
INDEX_KEY = "requests:index"
PENDING_INDEX = "requests:pending"
PENDING_READY = "requests:pending_ready"
INDEX_MAX = 300
MAX_TEXT = 500

PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"

_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{22,64}$")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def new_request_id() -> str:
    return secrets.token_urlsafe(24)  # 192 bits


def validate_request_id(value: Any) -> str:
    if not isinstance(value, str) or not _REQUEST_ID.fullmatch(value):
        raise InvalidInputError("request_id is not a valid access request id")
    return value


def clean_text(value: Any, what: str, *, required: bool) -> str | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            raise InvalidInputError(f"{what} must not be empty")
        return None
    if not isinstance(value, str):
        raise InvalidInputError(f"{what} must be a string")
    value = _CONTROL_CHARS.sub(" ", value).strip()
    if len(value) > MAX_TEXT:
        raise InvalidInputError(f"{what} must be at most {MAX_TEXT} characters")
    return value


@dataclass
class AccessRequest:
    id: str
    file_id: str | None
    file_name: str | None
    description: str | None
    tool: str
    token_name: str | None
    reason: str | None
    status: str = PENDING
    created_at: str = field(default_factory=utc_now)
    decided_at: str | None = None
    granted_id: str | None = None
    granted_name: str | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> "AccessRequest":
        data = json.loads(raw)
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


class AccessRequests:
    def __init__(self, store: KeyValueStore):
        self.store = store

    def get(self, request_id: str) -> AccessRequest | None:
        try:
            validate_request_id(request_id)
        except InvalidInputError:
            return None
        raw = self.store.get(f"req:{request_id}")
        if not raw:
            return None
        try:
            return AccessRequest.from_json(raw)
        except (ValueError, TypeError):
            return None

    def save(self, req: AccessRequest) -> None:
        self.store.set(f"req:{req.id}", req.to_json(), ex=REQUEST_TTL)

    def pending_for(self, file_id: str) -> AccessRequest | None:
        rid = self.store.get(f"req:pending:{file_id}")
        if not rid:
            return None
        req = self.get(rid)
        if req is None or req.status != PENDING:
            return None
        return req

    def create(
        self,
        *,
        tool: str,
        token_name: str | None,
        reason: str | None,
        file_id: str | None = None,
        file_name: str | None = None,
        description: str | None = None,
    ) -> tuple[AccessRequest, bool]:
        """Create a pending request, or return the existing pending one for `file_id`.
        Returns (request, created)."""
        if file_id is not None:
            existing = self.pending_for(file_id)
            if existing is not None:
                return existing, False
        req = AccessRequest(
            id=new_request_id(),
            file_id=file_id,
            file_name=file_name,
            description=description,
            tool=tool,
            token_name=token_name,
            reason=reason,
        )
        self.save(req)
        if file_id is not None:
            self.store.set(f"req:pending:{file_id}", req.id, ex=REQUEST_TTL)
        self.store.lpush(INDEX_KEY, req.id)
        self.store.ltrim(INDEX_KEY, 0, INDEX_MAX - 1)
        self.store.lpush(PENDING_INDEX, req.id)
        return req, True

    def decide(
        self,
        req: AccessRequest,
        status: str,
        *,
        granted_id: str | None = None,
        granted_name: str | None = None,
    ) -> AccessRequest:
        req.status = status
        req.decided_at = utc_now()
        req.granted_id = granted_id
        req.granted_name = granted_name
        self.save(req)
        if req.file_id is not None and self.store.get(f"req:pending:{req.file_id}") == req.id:
            self.store.delete(f"req:pending:{req.file_id}")
        if status != PENDING:
            self.store.lrem(PENDING_INDEX, req.id)
        return req

    def pending_count(self) -> int:
        """How many requests are still waiting. One list read, then one read per waiting id.

        The whole history list (up to INDEX_MAX) is walked once per tenant, the first time
        this is asked, so a waiting request saved before that list existed is still counted.
        Later calls do not walk it.
        """
        if self.store.get(PENDING_READY) is None:
            seen = set(self.store.lrange(PENDING_INDEX, 0, -1))
            for rid in self.store.lrange(INDEX_KEY, 0, INDEX_MAX - 1):
                if rid in seen:
                    continue
                req = self.get(rid)
                if req is not None and req.status == PENDING:
                    self.store.lpush(PENDING_INDEX, rid)
                    seen.add(rid)
            self.store.set(PENDING_READY, "1")
        count = 0
        seen_ids: set[str] = set()
        for rid in self.store.lrange(PENDING_INDEX, 0, -1):
            if rid in seen_ids:
                continue
            seen_ids.add(rid)
            req = self.get(rid)
            if req is None or req.status != PENDING:
                self.store.lrem(PENDING_INDEX, rid)
                continue
            count += 1
        return count

    def recent(self, limit: int = 100) -> list[AccessRequest]:
        out: list[AccessRequest] = []
        seen: set[str] = set()
        for rid in self.store.lrange(INDEX_KEY, 0, INDEX_MAX - 1):
            if rid in seen:
                continue
            seen.add(rid)
            req = self.get(rid)
            if req is not None:
                out.append(req)
            if len(out) >= limit:
                break
        return out


class AccessService:
    """What the MCP tools see: build `access_required` payloads and the two request tools."""

    def __init__(self, requests: AccessRequests, app_base_url: str, guard: Any, peek_name: Any):
        self.requests = requests
        self.app_base_url = app_base_url.rstrip("/")
        self.guard = guard
        self.peek_name = peek_name

    def approval_url(self, request_id: str) -> str:
        return f"{self.app_base_url}/requests/{request_id}"

    def _payload(self, req: AccessRequest) -> dict[str, Any]:
        return {
            "error": "access_required",
            "request_id": req.id,
            "approval_url": self.approval_url(req.id),
            "file_id": req.file_id,
            "message": (
                "This item has not been shared with you. Show the user this approval link "
                f"and ask them to approve access: {self.approval_url(req.id)} . After they "
                "approve, retry the same call (or check with check_access_request using "
                "request_id)."
            ),
        }

    def handle_denial(self, file_id: str, tool: str, token_name: str | None) -> dict[str, Any]:
        """Called by the policy wrapper when a tool is denied because of scope."""
        req, _created = self.requests.create(
            tool=tool,
            token_name=token_name,
            reason=f"{tool} was refused because the item is not shared with the assistant",
            file_id=file_id,
            file_name=self.peek_name(file_id),
        )
        return self._payload(req)

    def request_access(
        self,
        description: str,
        reason: str,
        file_id: str | None,
        *,
        token_name: str | None,
    ) -> dict[str, Any]:
        description_clean = clean_text(description, "description", required=True)
        reason_clean = clean_text(reason, "reason", required=True)
        if file_id is not None and file_id != "":
            validate_drive_id(file_id)
            if self.guard.is_in_scope(file_id):
                return {
                    "status": "already_allowed",
                    "file_id": file_id,
                    "message": "You already have access to this item.",
                }
        else:
            file_id = None
        req, _created = self.requests.create(
            tool="request_access",
            token_name=token_name,
            reason=reason_clean,
            file_id=file_id,
            file_name=self.peek_name(file_id) if file_id else None,
            description=description_clean,
        )
        return {
            "status": req.status,
            "request_id": req.id,
            "approval_url": self.approval_url(req.id),
            "message": (
                "Show the user this link so they can approve or deny the request: "
                f"{self.approval_url(req.id)} . Then call check_access_request with request_id."
            ),
        }

    def check_access_request(self, request_id: str) -> dict[str, Any]:
        validate_request_id(request_id)
        req = self.requests.get(request_id)
        if req is None:
            return {"request_id": request_id, "status": "not_found"}
        out: dict[str, Any] = {"request_id": req.id, "status": req.status, "file_id": req.file_id}
        if req.status == APPROVED:
            out["granted_id"] = req.granted_id
            out["message"] = "Approved. Retry your call" + (
                f"; the owner shared item {req.granted_id}." if req.granted_id else "."
            )
        elif req.status == DENIED:
            out["message"] = "The owner denied this request. Do not retry it."
        else:
            out["message"] = "Still waiting for the owner. Remind the user of the approval link."
            out["approval_url"] = self.approval_url(req.id)
        return out
