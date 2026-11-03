"""Persistent state: the allowlist, access requests' storage, encrypted OAuth tokens and the
activity log.

Everything sits behind the small `KeyValueStore` protocol so tests (and local development
without Redis) can use `MemoryStore`. In production `RedisStore` talks to Upstash Redis over
its REST API. All keys are prefixed with `sdm:`.
"""

import json
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

KEY_PREFIX = "sdm:"
ALLOWLIST_KEY = "allowlist"
ACTIVITY_KEY = "activity"
ACTIVITY_MAX = 500
OWNER_TOKEN_KEY = "vault:owner_refresh_token"  # noqa: S105 - a key name
BOT_TOKEN_KEY = "vault:bot_refresh_token"  # noqa: S105 - a key name


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class KeyValueStore(Protocol):
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str, ex: int | None = None) -> None: ...
    def delete(self, key: str) -> None: ...
    def hset(self, key: str, field: str, value: str) -> None: ...
    def hget(self, key: str, field: str) -> str | None: ...
    def hgetall(self, key: str) -> dict[str, str]: ...
    def hdel(self, key: str, field: str) -> None: ...
    def lpush(self, key: str, value: str) -> None: ...
    def ltrim(self, key: str, start: int, stop: int) -> None: ...
    def lrange(self, key: str, start: int, stop: int) -> list[str]: ...


class MemoryStore:
    """Thread-safe in-memory store with expiring keys. Per process only."""

    kind = "memory"

    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock = clock
        self._lock = threading.Lock()
        self._values: dict[str, tuple[float | None, Any]] = {}

    def _live(self, key: str) -> Any:
        item = self._values.get(key)
        if item is None:
            return None
        expires, value = item
        if expires is not None and expires <= self._clock():
            del self._values[key]
            return None
        return value

    def get(self, key: str) -> str | None:
        with self._lock:
            value = self._live(key)
            return value if isinstance(value, str) else None

    def getdel(self, key: str) -> str | None:
        """Return a string value and delete it. Expired keys disappear."""
        with self._lock:
            value = self._live(key)
            self._values.pop(key, None)
            return value if isinstance(value, str) else None

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        with self._lock:
            expires = self._clock() + ex if ex else None
            self._values[key] = (expires, value)

    def delete(self, key: str) -> None:
        with self._lock:
            self._values.pop(key, None)

    def hset(self, key: str, field: str, value: str) -> None:
        with self._lock:
            current = self._live(key)
            if not isinstance(current, dict):
                current = {}
                self._values[key] = (None, current)
            current[field] = value

    def hget(self, key: str, field: str) -> str | None:
        with self._lock:
            current = self._live(key)
            return current.get(field) if isinstance(current, dict) else None

    def hgetall(self, key: str) -> dict[str, str]:
        with self._lock:
            current = self._live(key)
            return dict(current) if isinstance(current, dict) else {}

    def hdel(self, key: str, field: str) -> None:
        with self._lock:
            current = self._live(key)
            if isinstance(current, dict):
                current.pop(field, None)

    def lpush(self, key: str, value: str) -> None:
        with self._lock:
            current = self._live(key)
            if not isinstance(current, list):
                current = []
                self._values[key] = (None, current)
            current.insert(0, value)

    def ltrim(self, key: str, start: int, stop: int) -> None:
        with self._lock:
            current = self._live(key)
            if isinstance(current, list):
                end = None if stop == -1 else stop + 1
                current[:] = current[start:end]

    def lrange(self, key: str, start: int, stop: int) -> list[str]:
        with self._lock:
            current = self._live(key)
            if not isinstance(current, list):
                return []
            end = None if stop == -1 else stop + 1
            return list(current[start:end])


class RedisStore:
    """Upstash Redis over its REST API (`upstash-redis`)."""

    kind = "redis"

    def __init__(self, url: str, token: str):
        from upstash_redis import Redis

        self._redis = Redis(url=url, token=token, allow_telemetry=False, rest_retries=1)

    def get(self, key: str) -> str | None:
        value = self._redis.get(key)
        return None if value is None else str(value)

    def getdel(self, key: str) -> str | None:
        value = self._redis.getdel(key)
        return None if value is None else str(value)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._redis.set(key, value, ex=ex)

    def delete(self, key: str) -> None:
        self._redis.delete(key)

    def hset(self, key: str, field: str, value: str) -> None:
        self._redis.hset(key, field, value)

    def hget(self, key: str, field: str) -> str | None:
        value = self._redis.hget(key, field)
        return None if value is None else str(value)

    def hgetall(self, key: str) -> dict[str, str]:
        return {str(k): str(v) for k, v in (self._redis.hgetall(key) or {}).items()}

    def hdel(self, key: str, field: str) -> None:
        self._redis.hdel(key, field)

    def lpush(self, key: str, value: str) -> None:
        self._redis.lpush(key, value)

    def ltrim(self, key: str, start: int, stop: int) -> None:
        self._redis.ltrim(key, start, stop)

    def lrange(self, key: str, start: int, stop: int) -> list[str]:
        return [str(v) for v in self._redis.lrange(key, start, stop) or []]


class PrefixedStore:
    """Namespaces every key so the Redis database can be shared safely."""

    def __init__(self, inner: KeyValueStore, prefix: str = KEY_PREFIX):
        self.inner = inner
        self.prefix = prefix
        self.kind = getattr(inner, "kind", "custom")

    def __getattr__(self, name: str) -> Any:
        method = getattr(self.inner, name)

        def call(key: str, *args: Any, **kwargs: Any) -> Any:
            return method(self.prefix + key, *args, **kwargs)

        return call


# ---- allowlist -------------------------------------------------------------


@dataclass(frozen=True)
class AllowEntry:
    id: str
    name: str
    mime_type: str
    permission_id: str | None
    granted_at: str = field(default_factory=utc_now)
    request_id: str | None = None
    # The bot address `permission_id` belongs to; None when no Drive share was made.
    shared_with: str | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> "AllowEntry":
        data = json.loads(raw)
        return cls(
            id=str(data["id"]),
            name=str(data.get("name", "")),
            mime_type=str(data.get("mime_type", "")),
            permission_id=data.get("permission_id"),
            granted_at=str(data.get("granted_at", "")),
            request_id=data.get("request_id"),
            shared_with=data.get("shared_with"),
        )


class Allowlist:
    def __init__(self, store: KeyValueStore):
        self.store = store

    def entries(self) -> dict[str, AllowEntry]:
        out: dict[str, AllowEntry] = {}
        for file_id, raw in self.store.hgetall(ALLOWLIST_KEY).items():
            try:
                out[file_id] = AllowEntry.from_json(raw)
            except (ValueError, KeyError, TypeError):
                continue
        return out

    def get(self, file_id: str) -> AllowEntry | None:
        raw = self.store.hget(ALLOWLIST_KEY, file_id)
        return AllowEntry.from_json(raw) if raw else None

    def add(self, entry: AllowEntry) -> None:
        self.store.hset(ALLOWLIST_KEY, entry.id, entry.to_json())

    def remove(self, file_id: str) -> None:
        self.store.hdel(ALLOWLIST_KEY, file_id)

    def mime_map(self) -> dict[str, str]:
        return {fid: e.mime_type for fid, e in self.entries().items()}


# ---- encrypted refresh tokens ---------------------------------------------


class TokenVault:
    """Refresh tokens for the owner and the bot, encrypted with Fernet (ENCRYPTION_KEY)."""

    def __init__(self, store: KeyValueStore, encryption_key: str | None):
        self.store = store
        self._fernet = None
        if encryption_key:
            from cryptography.fernet import Fernet

            self._fernet = Fernet(encryption_key.strip().encode())

    @property
    def enabled(self) -> bool:
        return self._fernet is not None

    def _put(self, key: str, token: str, email: str) -> None:
        if self._fernet is None:
            raise RuntimeError("ENCRYPTION_KEY is not set")
        payload = json.dumps({"t": token, "email": email, "at": utc_now()})
        self.store.set(key, self._fernet.encrypt(payload.encode()).decode())

    def _take(self, key: str) -> dict[str, str] | None:
        if self._fernet is None:
            return None
        raw = self.store.get(key)
        if not raw:
            return None
        from cryptography.fernet import InvalidToken

        try:
            return json.loads(self._fernet.decrypt(raw.encode()))
        except (InvalidToken, ValueError):
            return None

    def set_owner(self, token: str, email: str) -> None:
        self._put(OWNER_TOKEN_KEY, token, email)

    def owner(self) -> dict[str, str] | None:
        return self._take(OWNER_TOKEN_KEY)

    def set_bot(self, token: str, email: str) -> None:
        self._put(BOT_TOKEN_KEY, token, email)

    def bot(self) -> dict[str, str] | None:
        return self._take(BOT_TOKEN_KEY)

    def clear_owner(self) -> None:
        self.store.delete(OWNER_TOKEN_KEY)

    def clear_bot(self) -> None:
        self.store.delete(BOT_TOKEN_KEY)


# ---- activity log -----------------------------------------------------------


class ActivityLog:
    """The last ACTIVITY_MAX audit records, newest first."""

    def __init__(self, store: KeyValueStore, max_items: int = ACTIVITY_MAX):
        self.store = store
        self.max_items = max_items

    def __call__(self, record: dict[str, Any]) -> None:
        self.store.lpush(ACTIVITY_KEY, json.dumps(record, separators=(",", ":")))
        self.store.ltrim(ACTIVITY_KEY, 0, self.max_items - 1)

    def recent(self, limit: int = ACTIVITY_MAX) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for raw in self.store.lrange(ACTIVITY_KEY, 0, limit - 1):
            try:
                out.append(json.loads(raw))
            except ValueError:
                continue
        return out


def build_store(settings: Any) -> PrefixedStore:
    if settings.redis_configured:
        inner: KeyValueStore = RedisStore(
            settings.redis_rest_url, settings.redis_rest_token.get_secret_value().strip()
        )
    else:
        inner = MemoryStore()
    return PrefixedStore(inner)
