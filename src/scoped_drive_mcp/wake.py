"""Wake a paired assistant with a small HTTPS ping. The message text stays in the mailbox."""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from http.client import HTTPSConnection
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

SCHEMES = ("bearer", "bearer_and_x_automation_key")
Lookup = Callable[[str], list[str]]
Poster = Callable[[dict[str, str]], int]


@dataclass(frozen=True)
class WakeSettings:
    enabled: bool = False
    kek: bytes | None = None
    allowlist: tuple[str, ...] = ("api2.cursor.sh",)
    timeout: float = 4.0
    lookup: Lookup | None = None
    poster: Poster | None = None

    @property
    def ready(self) -> bool:
        return self.enabled and self.kek is not None


def decode_kek(value: str | None) -> bytes | None:
    if value is None or not value.strip():
        return None
    try:
        raw = base64.b64decode(value.strip(), validate=True)
    except Exception:
        return None
    return raw if len(raw) == 32 else None


def seal(secret: str, kek: bytes) -> tuple[str, str]:
    nonce = os.urandom(12)
    ciphertext = AESGCM(kek).encrypt(nonce, secret.encode(), None)
    return base64.b64encode(ciphertext).decode(), base64.b64encode(nonce).decode()


def open_secret(ciphertext: str, nonce: str, kek: bytes) -> str:
    return AESGCM(kek).decrypt(base64.b64decode(nonce), base64.b64decode(ciphertext), None).decode()


def hint(secret: str) -> str:
    return secret[-4:]


def inspect_url(raw: str, allowlist: tuple[str, ...]) -> tuple[str, str]:
    parts = urlsplit(raw.strip())
    host = parts.hostname.lower().rstrip(".") if parts.hostname else ""
    if (
        parts.scheme != "https"
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or (parts.port not in (None, 443))
        or not host
        or _is_ip(host)
    ):
        raise ValueError("invalid_webhook_url")
    allowed = {item.lower() for item in allowlist}
    if host not in allowed:
        raise ValueError("webhook_host_not_allowed")
    return host, parts.path or "/"


def approve_url(
    raw: str, allowlist: tuple[str, ...], lookup: Lookup | None = None
) -> tuple[str, str, str]:
    host, path = inspect_url(raw, allowlist)
    addresses = (lookup or _lookup)(host)
    if not addresses or any(not _public(address) for address in addresses):
        raise ValueError("invalid_webhook_url")
    return host, path, addresses[0]


def payload(message: dict[str, Any]) -> dict[str, Any]:
    return {
        "v": 1,
        "type": "bot_bridge.message_available",
        "link_id": message["link_id"],
        "thread_id": message["thread_id"],
        "msg_id": message["msg_id"],
        "created_at": message["created_at"],
    }


def headers_for(scheme: str, secret: str) -> dict[str, str]:
    headers = {
        "content-type": "application/json",
        "accept": "application/json",
        "user-agent": "scoped-drive-mailbox/1",
    }
    if scheme == "bearer":
        headers["authorization"] = f"Bearer {secret}"
    elif scheme == "bearer_and_x_automation_key":
        headers["authorization"] = f"Bearer {secret}"
        headers["x-automation-key"] = secret
    else:
        raise ValueError("invalid_input")
    return headers


def deliver(settings: WakeSettings, record: dict[str, Any], message: dict[str, Any]) -> int:
    if not settings.kek:
        raise ValueError("webhook_disabled")
    host, path, address = approve_url(str(record["url"]), settings.allowlist, settings.lookup)
    secret = open_secret(str(record["ciphertext"]), str(record["nonce"]), settings.kek)
    body = json.dumps(payload(message), separators=(",", ":"))
    request = {
        "hostname": host,
        "path": path,
        "address": address,
        "body": body,
        **headers_for(str(record.get("scheme") or "bearer"), secret),
    }
    poster = settings.poster or _post
    status = poster(request)
    if status != 200:
        raise ValueError(f"http_{status}")
    return status


def _post(request: dict[str, str]) -> int:
    class Pinned(HTTPSConnection):
        def connect(self) -> None:
            raw = socket.create_connection((request["address"], 443), self.timeout)
            context = self._context or ssl.create_default_context()
            self.sock = context.wrap_socket(raw, server_hostname=self.host)

    conn = Pinned(request["hostname"], timeout=4)
    try:
        conn.request(
            "POST",
            request["path"],
            body=request["body"],
            headers={
                key: value
                for key, value in request.items()
                if key not in {"hostname", "path", "address", "body"}
            },
        )
        response = conn.getresponse()
        response.read(512)
        return response.status
    finally:
        conn.close()


def _lookup(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _public(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    if parsed.version == 6 and getattr(parsed, "ipv4_mapped", None) is not None:
        parsed = parsed.ipv4_mapped
    if any(
        (
            parsed.is_private,
            parsed.is_loopback,
            parsed.is_link_local,
            parsed.is_multicast,
            parsed.is_reserved,
            parsed.is_unspecified,
        )
    ):
        return False
    carrier = ipaddress.ip_network("100.64.0.0/10")
    return not (isinstance(parsed, ipaddress.IPv4Address) and parsed in carrier)
