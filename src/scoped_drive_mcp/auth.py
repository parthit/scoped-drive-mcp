"""Bearer-token authentication as a pure ASGI middleware.

`/mcp` accepts two kinds of bearer, checked in this order:

1. A pre-shared `API_TOKENS` entry (constant-time hash compare). These are never
   looked up as OAuth tokens.
2. An opaque OAuth access token issued by this server's authorization server.

Anything else is 401. The `WWW-Authenticate` header points at the protected-resource
metadata (RFC 9728) so an OAuth client can discover the authorization server.
The dashboard session cookie is not read here.
"""

import hashlib
import hmac
import json
from collections.abc import Callable, Iterable
from contextvars import ContextVar
from dataclasses import dataclass

from starlette.types import ASGIApp, Receive, Scope, Send

from .audit import audit_auth_failure
from .config import Role, TokenEntry


@dataclass(frozen=True)
class Principal:
    token_name: str
    role: Role
    # The dashboard user this caller acts for. API tokens leave this empty; the
    # middleware fills in the admin. OAuth grants set the user who approved them.
    email: str | None = None


current_principal: ContextVar[Principal | None] = ContextVar("current_principal", default=None)
# Which tenant's allowlist, vault and Drive client the current call uses.
# Unset means the admin's legacy keys (single-tenant tests and /health).
current_actor: ContextVar[str | None] = ContextVar("current_actor", default=None)

OAuthResolver = Callable[[str], Principal | None]


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
        oauth_resolve: OAuthResolver | None = None,
        resource_metadata: str | None = None,
        owner_email: str | None = None,
    ):
        self.app = app
        self.tokens = tuple(tokens)
        self.exempt_paths = frozenset(exempt_paths)
        self.oauth_resolve = oauth_resolve
        self.resource_metadata = resource_metadata
        self.owner_email = owner_email

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
        if principal is None and token and self.oauth_resolve is not None:
            principal = self.oauth_resolve(token)
        if principal is None:
            reason = "missing_token" if header is None else "invalid_token"
            audit_auth_failure(reason, scope.get("path", ""))
            await _unauthorized(send, reason, self.resource_metadata)
            return
        # Pre-shared API tokens are the admin's legacy bearer. OAuth already set email.
        if principal.email is None and self.owner_email:
            principal = Principal(
                token_name=principal.token_name, role=principal.role, email=self.owner_email
            )

        reset = current_principal.set(principal)
        reset_actor = current_actor.set(principal.email)
        try:
            await self.app(scope, receive, send)
        finally:
            current_actor.reset(reset_actor)
            current_principal.reset(reset)


def www_authenticate(reason: str, resource_metadata: str | None) -> bytes:
    """RFC 9728 discovery header. `resource_metadata` is the protected-resource URL.

    A missing token carries only that parameter. A presented but rejected token also
    carries `error="invalid_token"` (RFC 6750). Pre-shared API tokens never reach here.
    """
    params: list[str] = []
    if resource_metadata:
        params.append(f'resource_metadata="{resource_metadata}"')
    if reason != "missing_token":
        params.append('error="invalid_token"')
    if not params:
        return b'Bearer realm="scoped-drive-mcp"'
    return ("Bearer " + ", ".join(params)).encode("ascii")


async def _unauthorized(send: Send, reason: str, resource_metadata: str | None = None) -> None:
    body = json.dumps({"error": "unauthorized", "reason": reason}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"www-authenticate", www_authenticate(reason, resource_metadata)),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
