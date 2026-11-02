"""Bearer-token authentication as a pure ASGI middleware."""

import hashlib
import hmac
import json
from collections.abc import Iterable
from contextvars import ContextVar
from dataclasses import dataclass

from starlette.types import ASGIApp, Receive, Scope, Send

from .audit import audit_auth_failure
from .config import Role, TokenEntry


@dataclass(frozen=True)
class Principal:
    token_name: str
    role: Role


current_principal: ContextVar[Principal | None] = ContextVar("current_principal", default=None)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_token(token: str, entries: Iterable[TokenEntry]) -> Principal | None:
    """Compare against every configured hash (no early exit) with a timing-safe check."""
    digest = hash_token(token)
    match: TokenEntry | None = None
    for entry in entries:
        if hmac.compare_digest(digest, entry.sha256) and match is None:
            match = entry
    if match is None:
        return None
    return Principal(token_name=match.name, role=match.role)


def extract_token(authorization: str | None) -> str | None:
    """Accept `Bearer <token>`. A bare token (no scheme, no spaces) is also accepted,
    because some MCP clients put the configured value into the header verbatim."""
    if not authorization:
        return None
    value = authorization.strip()
    if value.lower() == "bearer":
        return None
    scheme, _, rest = value.partition(" ")
    if rest:
        if scheme.lower() != "bearer":
            return None
        token = rest.strip()
    else:
        token = value
    if not token or " " in token:
        return None
    return token


class BearerAuthMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        tokens: Iterable[TokenEntry],
        exempt_paths: Iterable[str] = ("/health",),
    ):
        self.app = app
        self.tokens = tuple(tokens)
        self.exempt_paths = frozenset(exempt_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") in self.exempt_paths:
            await self.app(scope, receive, send)
            return

        header: str | None = None
        for key, value in scope.get("headers", []):
            if key.lower() == b"authorization":
                header = value.decode("latin-1")
                break

        token = extract_token(header)
        principal = verify_token(token, self.tokens) if token else None
        if principal is None:
            reason = "missing_token" if header is None else "invalid_token"
            audit_auth_failure(reason, scope.get("path", ""))
            await _unauthorized(send, reason)
            return

        reset = current_principal.set(principal)
        try:
            await self.app(scope, receive, send)
        finally:
            current_principal.reset(reset)


async def _unauthorized(send: Send, reason: str) -> None:
    body = json.dumps({"error": "unauthorized", "reason": reason}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"www-authenticate", b'Bearer realm="scoped-drive-mcp"'),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
