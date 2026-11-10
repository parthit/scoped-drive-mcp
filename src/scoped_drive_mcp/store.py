"""Persistent state: the allowlist, access requests' storage, encrypted OAuth tokens and the
activity log.

Everything sits behind the small `KeyValueStore` protocol so tests (and local development
without Redis) can use `MemoryStore`. In production `RedisStore` talks to Upstash Redis over
its REST API, and `PostgresStore` talks to Neon when `DATABASE_URL` or `POSTGRES_URL` is set.
All keys are prefixed with `sdm:`. The admin keeps the original key names. Every other person
is stored under `u:{email}:` on that same prefixed store.
"""

import json
import logging
import re
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from .auth import current_actor

logger = logging.getLogger(__name__)

KEY_PREFIX = "sdm:"
ALLOWLIST_KEY = "allowlist"
ACTIVITY_KEY = "activity"
ACTIVITY_MAX = 500
OWNER_TOKEN_KEY = "vault:owner_refresh_token"  # noqa: S105 - a key name
BOT_TOKEN_KEY = "vault:bot_refresh_token"  # noqa: S105 - a key name
USERS_INDEX = "users:index"
REDIS_IMPORT_FLAG = "sdm:meta:redis_admin_imported"  # on the raw store, not the sdm: view
REDIS_IMPORT_LOCK = "sdm:meta:redis_admin_import_lock"  # same raw store; expires if a copy dies
REDIS_IMPORT_LOCK_TTL = 120

_REPLACE_LIST_SCRIPT = """
redis.call('DEL', KEYS[1])
for i = #ARGV, 1, -1 do
    redis.call('LPUSH', KEYS[1], ARGV[i])
end
return #ARGV
"""

_INCR_SCRIPT = """
local n = redis.call('INCR', KEYS[1])
if tonumber(n) == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return n
"""

# Inbox rows are msg_id|link_id|created_epoch|expires_epoch|unread. Anything else is dropped.
_INBOX_TOKEN = re.compile(r"^([^|]+)\|([^|]+)\|([0-9]+)\|([0-9]+)\|([01])$")

_LDROP_EXPIRED_SCRIPT = """
local now = tonumber(ARGV[1])
local removed = 0
for _, value in ipairs(redis.call('LRANGE', KEYS[1], 0, -1)) do
    local expires = string.match(value, '^[^|]+|[^|]+|[0-9]+|([0-9]+)|[01]$')
    if (not expires) or (tonumber(expires) <= now) then
        redis.call('LREM', KEYS[1], 0, value)
        removed = removed + 1
    end
end
return removed
"""

_LREPLACE_SCRIPT = """
local replaced = 0
local index = 0
while true do
    local value = redis.call('LINDEX', KEYS[1], index)
    if not value then
        break
    end
    if value == ARGV[1] then
        redis.call('LSET', KEYS[1], index, ARGV[2])
        replaced = replaced + 1
    end
    index = index + 1
end
return replaced
"""


def parse_inbox_token(value: str) -> tuple[str, str, int, int, bool] | None:
    """Return msg_id, link_id, created epoch, expires epoch, and unread. None if malformed."""
    match = _INBOX_TOKEN.fullmatch(value)
    if match is None:
        return None
    return (
        match.group(1),
        match.group(2),
        int(match.group(3)),
        int(match.group(4)),
        match.group(5) == "1",
    )


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
    def lrem(self, key: str, value: str) -> int: ...
    def lreplace(self, key: str, old: str, new: str) -> int: ...
    def ldrop_expired(self, key: str, now: int) -> int: ...
    def incr(self, key: str, ex: int) -> int: ...


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

    def lrem(self, key: str, value: str) -> int:
        with self._lock:
            current = self._live(key)
            if not isinstance(current, list):
                return 0
            kept = [item for item in current if item != value]
            removed = len(current) - len(kept)
            current[:] = kept
            return removed

    def lreplace(self, key: str, old: str, new: str) -> int:
        with self._lock:
            current = self._live(key)
            if not isinstance(current, list):
                return 0
            replaced = 0
            for index, item in enumerate(current):
                if item == old:
                    current[index] = new
                    replaced += 1
            return replaced

    def ldrop_expired(self, key: str, now: int) -> int:
        """Remove expired or malformed inbox rows. A concurrent push of a new row stays."""
        with self._lock:
            current = self._live(key)
            if not isinstance(current, list):
                return 0
            kept = []
            removed = 0
            for item in current:
                parsed = parse_inbox_token(item)
                if parsed is not None and parsed[3] > now:
                    kept.append(item)
                else:
                    removed += 1
            current[:] = kept
            return removed

    def incr(self, key: str, ex: int) -> int:
        """Add one and return the new value. An expired key starts again at 1."""
        with self._lock:
            current = self._live(key)
            count = int(current) + 1 if isinstance(current, str) and current.isdigit() else 1
            expires = self._clock() + ex if ex else None
            self._values[key] = (expires, str(count))
            return count

    def set_if_absent(self, key: str, value: str, ex: int) -> bool:
        """Set `key` only when it is missing or expired. True when this caller won."""
        with self._lock:
            if self._live(key) is not None:
                return False
            expires = self._clock() + ex if ex else None
            self._values[key] = (expires, value)
            return True

    def replace_list(self, key: str, items: list[str]) -> None:
        """Replace a list in one step. `items` is newest-first, the same order as `lrange`."""
        with self._lock:
            self._values[key] = (None, list(items))


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

    def lrem(self, key: str, value: str) -> int:
        removed = self._redis.lrem(key, 0, value)
        return int(removed or 0)

    def lreplace(self, key: str, old: str, new: str) -> int:
        value = self._redis.eval(_LREPLACE_SCRIPT, keys=[key], args=[old, new])
        return int(value or 0)

    def ldrop_expired(self, key: str, now: int) -> int:
        """Remove expired or malformed inbox rows inside one script. New pushes stay."""
        value = self._redis.eval(_LDROP_EXPIRED_SCRIPT, keys=[key], args=[now])
        return int(value or 0)

    def incr(self, key: str, ex: int) -> int:
        """INCR and, on the first hit, EXPIRE. One script so the TTL cannot be skipped."""
        value = self._redis.eval(_INCR_SCRIPT, keys=[key], args=[ex])
        return int(value)

    def set_if_absent(self, key: str, value: str, ex: int) -> bool:
        """SET NX with a TTL. True only when this caller created the key."""
        result = self._redis.set(key, value, nx=True, ex=ex)
        return result is True or result == "OK"

    def replace_list(self, key: str, items: list[str]) -> None:
        """Replace a list in one Redis script so two copies cannot interleave item by item."""
        self._redis.eval(_REPLACE_LIST_SCRIPT, keys=[key], args=list(items))


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


class ActorStore:
    """Routes each call to the admin's legacy keys or to `u:{email}:`.

    The actor comes from `current_actor`. When it is unset, or it is the admin, keys stay
    where they are today (`allowlist`, `vault:...`). Other people get a prefix on this
    already-prefixed store, so the full key is `sdm:u:eve@example.com:allowlist`.
    """

    def __init__(self, inner: KeyValueStore, admin_email: str | None):
        self.inner = inner
        self.admin_email = admin_email
        self.kind = getattr(inner, "kind", "custom")

    def _key(self, key: str) -> str:
        actor = current_actor.get()
        if not actor or actor == self.admin_email:
            return key
        return f"u:{actor}:{key}"

    def get(self, key: str) -> str | None:
        return self.inner.get(self._key(key))

    def getdel(self, key: str) -> str | None:
        full = self._key(key)
        consume = getattr(self.inner, "getdel", None)
        if consume is None:
            value = self.inner.get(full)
            if value is not None:
                self.inner.delete(full)
            return value
        return consume(full)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.inner.set(self._key(key), value, ex=ex)

    def delete(self, key: str) -> None:
        self.inner.delete(self._key(key))

    def hset(self, key: str, field: str, value: str) -> None:
        self.inner.hset(self._key(key), field, value)

    def hget(self, key: str, field: str) -> str | None:
        return self.inner.hget(self._key(key), field)

    def hgetall(self, key: str) -> dict[str, str]:
        return self.inner.hgetall(self._key(key))

    def hdel(self, key: str, field: str) -> None:
        self.inner.hdel(self._key(key), field)

    def lpush(self, key: str, value: str) -> None:
        self.inner.lpush(self._key(key), value)

    def ltrim(self, key: str, start: int, stop: int) -> None:
        self.inner.ltrim(self._key(key), start, stop)

    def lrange(self, key: str, start: int, stop: int) -> list[str]:
        return self.inner.lrange(self._key(key), start, stop)

    def lrem(self, key: str, value: str) -> int:
        return int(self.inner.lrem(self._key(key), value))

    def lreplace(self, key: str, old: str, new: str) -> int:
        return int(self.inner.lreplace(self._key(key), old, new))

    def ldrop_expired(self, key: str, now: int) -> int:
        return int(self.inner.ldrop_expired(self._key(key), now))

    def incr(self, key: str, ex: int) -> int:
        return int(self.inner.incr(self._key(key), ex))


class PostgresStore:
    """One short Postgres connection per call. No pool (serverless-friendly)."""

    kind = "postgres"

    def __init__(self, url: str):
        self._url = url
        self._ready = False
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return "PostgresStore(kind='postgres')"

    def _connect(self) -> Any:
        import psycopg

        # Neon’s pooled URL is PgBouncer in transaction mode, which rejects
        # psycopg’s automatic prepared statements.
        conn = psycopg.connect(
            self._url, autocommit=True, connect_timeout=5, prepare_threshold=None
        )
        self._ensure(conn)
        return conn

    def _ensure(self, conn: Any) -> None:
        if self._ready:
            return
        with self._lock:
            if self._ready:
                return
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sdm_kv (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    expires_at TIMESTAMPTZ
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sdm_hash (
                    key TEXT NOT NULL,
                    field TEXT NOT NULL,
                    value TEXT NOT NULL,
                    PRIMARY KEY (key, field)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sdm_list (
                    pos BIGSERIAL PRIMARY KEY,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS sdm_list_key_pos ON sdm_list (key, pos DESC)")
            self._ready = True

    def _run(self, fn: Callable[[Any], Any]) -> Any:
        with self._connect() as conn:
            return fn(conn)

    def get(self, key: str) -> str | None:
        def read(conn: Any) -> str | None:
            conn.execute(
                """
                DELETE FROM sdm_kv
                WHERE key = %s AND expires_at IS NOT NULL AND expires_at <= NOW()
                """,
                (key,),
            )
            found = conn.execute(
                """
                SELECT value FROM sdm_kv
                WHERE key = %s AND (expires_at IS NULL OR expires_at > NOW())
                """,
                (key,),
            ).fetchone()
            return None if found is None else str(found[0])

        return self._run(read)

    def getdel(self, key: str) -> str | None:
        def take(conn: Any) -> str | None:
            conn.execute(
                """
                DELETE FROM sdm_kv
                WHERE key = %s AND expires_at IS NOT NULL AND expires_at <= NOW()
                """,
                (key,),
            )
            row = conn.execute(
                """
                DELETE FROM sdm_kv
                WHERE key = %s AND (expires_at IS NULL OR expires_at > NOW())
                RETURNING value
                """,
                (key,),
            ).fetchone()
            return None if row is None else str(row[0])

        return self._run(take)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        def write(conn: Any) -> None:
            if ex:
                conn.execute(
                    """
                    INSERT INTO sdm_kv (key, value, expires_at)
                    VALUES (%s, %s, NOW() + (%s * INTERVAL '1 second'))
                    ON CONFLICT (key) DO UPDATE
                    SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at
                    """,
                    (key, value, ex),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO sdm_kv (key, value, expires_at)
                    VALUES (%s, %s, NULL)
                    ON CONFLICT (key) DO UPDATE
                    SET value = EXCLUDED.value, expires_at = NULL
                    """,
                    (key, value),
                )

        self._run(write)

    def delete(self, key: str) -> None:
        def wipe(conn: Any) -> None:
            conn.execute("DELETE FROM sdm_kv WHERE key = %s", (key,))
            conn.execute("DELETE FROM sdm_hash WHERE key = %s", (key,))
            conn.execute("DELETE FROM sdm_list WHERE key = %s", (key,))

        self._run(wipe)

    def hset(self, key: str, field: str, value: str) -> None:
        def write(conn: Any) -> None:
            conn.execute(
                """
                INSERT INTO sdm_hash (key, field, value) VALUES (%s, %s, %s)
                ON CONFLICT (key, field) DO UPDATE SET value = EXCLUDED.value
                """,
                (key, field, value),
            )

        self._run(write)

    def hget(self, key: str, field: str) -> str | None:
        def read(conn: Any) -> str | None:
            row = conn.execute(
                "SELECT value FROM sdm_hash WHERE key = %s AND field = %s", (key, field)
            ).fetchone()
            return None if row is None else str(row[0])

        return self._run(read)

    def hgetall(self, key: str) -> dict[str, str]:
        def read(conn: Any) -> dict[str, str]:
            rows = conn.execute(
                "SELECT field, value FROM sdm_hash WHERE key = %s", (key,)
            ).fetchall()
            return {str(field): str(value) for field, value in rows}

        return self._run(read)

    def hdel(self, key: str, field: str) -> None:
        self._run(
            lambda conn: conn.execute(
                "DELETE FROM sdm_hash WHERE key = %s AND field = %s", (key, field)
            )
        )

    def lpush(self, key: str, value: str) -> None:
        self._run(
            lambda conn: conn.execute(
                "INSERT INTO sdm_list (key, value) VALUES (%s, %s)", (key, value)
            )
        )

    def ltrim(self, key: str, start: int, stop: int) -> None:
        def trim(conn: Any) -> None:
            if stop != -1 and stop < start:
                conn.execute("DELETE FROM sdm_list WHERE key = %s", (key,))
                return
            offset = max(start, 0)
            limit = 1_000_000 if stop == -1 else stop - offset + 1
            conn.execute(
                """
                DELETE FROM sdm_list WHERE key = %s AND pos NOT IN (
                    SELECT pos FROM sdm_list WHERE key = %s
                    ORDER BY pos DESC OFFSET %s LIMIT %s
                )
                """,
                (key, key, offset, limit),
            )

        self._run(trim)

    def lrange(self, key: str, start: int, stop: int) -> list[str]:
        def read(conn: Any) -> list[str]:
            if stop != -1 and stop < start:
                return []
            offset = max(start, 0)
            limit = 1_000_000 if stop == -1 else stop - offset + 1
            rows = conn.execute(
                """
                SELECT value FROM sdm_list WHERE key = %s
                ORDER BY pos DESC OFFSET %s LIMIT %s
                """,
                (key, offset, limit),
            ).fetchall()
            return [str(row[0]) for row in rows]

        return self._run(read)

    def lrem(self, key: str, value: str) -> int:
        def remove(conn: Any) -> int:
            result = conn.execute(
                "DELETE FROM sdm_list WHERE key = %s AND value = %s",
                (key, value),
            )
            return int(result.rowcount or 0)

        return int(self._run(remove))

    def lreplace(self, key: str, old: str, new: str) -> int:
        def swap(conn: Any) -> int:
            result = conn.execute(
                "UPDATE sdm_list SET value = %s WHERE key = %s AND value = %s",
                (new, key, old),
            )
            return int(result.rowcount or 0)

        return int(self._run(swap))

    def ldrop_expired(self, key: str, now: int) -> int:
        """Remove expired or malformed inbox rows. A row inserted concurrently stays."""

        def drop(conn: Any) -> int:
            malformed = conn.execute(
                """
                DELETE FROM sdm_list
                WHERE key = %s
                  AND value !~ '^[^|]+\\|[^|]+\\|[0-9]+\\|[0-9]+\\|[01]$'
                """,
                (key,),
            )
            expired = conn.execute(
                """
                DELETE FROM sdm_list
                WHERE key = %s
                  AND value ~ '^[^|]+\\|[^|]+\\|[0-9]+\\|[0-9]+\\|[01]$'
                  AND split_part(value, '|', 4)::bigint <= %s
                """,
                (key, now),
            )
            return int(malformed.rowcount or 0) + int(expired.rowcount or 0)

        return int(self._run(drop))

    def incr(self, key: str, ex: int) -> int:
        """Add one in a single statement. An expired row starts again at 1."""

        def bump(conn: Any) -> int:
            row = conn.execute(
                """
                INSERT INTO sdm_kv (key, value, expires_at)
                VALUES (%s, '1', NOW() + (%s * INTERVAL '1 second'))
                ON CONFLICT (key) DO UPDATE
                SET value = (
                    CASE
                        WHEN sdm_kv.expires_at IS NOT NULL AND sdm_kv.expires_at <= NOW()
                            THEN 1
                        WHEN sdm_kv.value ~ '^[0-9]+$' THEN sdm_kv.value::bigint + 1
                        ELSE 1
                    END
                )::text,
                expires_at = EXCLUDED.expires_at
                RETURNING value
                """,
                (key, ex),
            ).fetchone()
            return int(row[0])

        return int(self._run(bump))

    def set_if_absent(self, key: str, value: str, ex: int) -> bool:
        """Insert a row only when the key is missing. An expired row is cleared first."""

        def claim(conn: Any) -> bool:
            with conn.transaction():
                conn.execute(
                    """
                    DELETE FROM sdm_kv
                    WHERE key = %s AND expires_at IS NOT NULL AND expires_at <= NOW()
                    """,
                    (key,),
                )
                row = conn.execute(
                    """
                    INSERT INTO sdm_kv (key, value, expires_at)
                    VALUES (%s, %s, NOW() + (%s * INTERVAL '1 second'))
                    ON CONFLICT (key) DO NOTHING
                    RETURNING key
                    """,
                    (key, value, ex),
                ).fetchone()
                return row is not None

        return bool(self._run(claim))

    def replace_list(self, key: str, items: list[str]) -> None:
        """Delete and rewrite a list in one transaction. `items` is newest-first."""

        def write(conn: Any) -> None:
            with conn.transaction():
                conn.execute("DELETE FROM sdm_list WHERE key = %s", (key,))
                for item in reversed(items):
                    conn.execute(
                        "INSERT INTO sdm_list (key, value) VALUES (%s, %s)",
                        (key, item),
                    )

        self._run(write)


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


def _copy_string(source: KeyValueStore, dest: KeyValueStore, key: str) -> None:
    value = source.get(key)
    if value is not None:
        dest.set(key, value)


def _copy_hash(source: KeyValueStore, dest: KeyValueStore, key: str) -> None:
    for name, value in source.hgetall(key).items():
        dest.hset(key, name, value)


def _copy_list(source: KeyValueStore, dest: KeyValueStore, key: str) -> None:
    """Replace `key` with the source list in one step when the destination can.

    Pushing one item at a time lets two copies interleave and duplicate the list.
    """
    items = source.lrange(key, 0, -1)
    replace = getattr(dest, "replace_list", None)
    if replace is None:
        dest.delete(key)
        for item in reversed(items):
            dest.lpush(key, item)
        return
    replace(key, items)


class StoreImportError(RuntimeError):
    """The admin store was not copied, so Postgres must not be served."""


def import_admin_keys(source: KeyValueStore, dest: KeyValueStore) -> None:
    """Copy the admin's Redis records into Postgres once.

    Only the legacy admin keys move: allowlist, encrypted tokens, requests and activity.
    OAuth grants and other people's prefixes are left where they are. A flag on the
    destination stops a second copy. The flag is written only after the copy finishes.
    A lock so two serverless instances cannot both copy the activity list and the
    request index. The loser raises `StoreImportError` and must not be served as the
    live store. Lists are replaced in one step so a retry cannot splice duplicates in.
    """
    if dest.get(REDIS_IMPORT_FLAG):
        return
    claim = getattr(dest, "set_if_absent", None)
    if claim is None or not claim(REDIS_IMPORT_LOCK, utc_now(), REDIS_IMPORT_LOCK_TTL):
        raise StoreImportError("admin store copy is already running")
    try:
        if dest.get(REDIS_IMPORT_FLAG):
            return
        _copy_hash(source, dest, KEY_PREFIX + ALLOWLIST_KEY)
        _copy_string(source, dest, KEY_PREFIX + OWNER_TOKEN_KEY)
        _copy_string(source, dest, KEY_PREFIX + BOT_TOKEN_KEY)
        _copy_list(source, dest, KEY_PREFIX + ACTIVITY_KEY)
        index_key = KEY_PREFIX + "requests:index"
        _copy_list(source, dest, index_key)
        for rid in dest.lrange(index_key, 0, -1):
            raw = source.get(f"{KEY_PREFIX}req:{rid}")
            if raw is None:
                continue
            dest.set(f"{KEY_PREFIX}req:{rid}", raw)
            try:
                file_id = json.loads(raw).get("file_id")
            except ValueError:
                file_id = None
            if isinstance(file_id, str) and file_id:
                _copy_string(source, dest, f"{KEY_PREFIX}req:pending:{file_id}")
        _scan_request_keys(source, dest)
        dest.set(REDIS_IMPORT_FLAG, utc_now())
    finally:
        try:
            dest.delete(REDIS_IMPORT_LOCK)
        except Exception as exc:
            # The driver message can contain the connection URL.
            logger.warning(
                "releasing the Redis-to-Postgres import lock failed (%s)",
                type(exc).__name__,
            )


def _scan_request_keys(source: KeyValueStore, dest: KeyValueStore) -> None:
    """Copy any `sdm:req:*` key Redis can scan, including ones missing from the index."""
    client = getattr(source, "_redis", None)
    scan = getattr(client, "scan", None)
    if scan is None:
        return
    cursor: int | str = 0
    while True:
        cursor, keys = scan(cursor, match=f"{KEY_PREFIX}req:*", count=200)
        for key in keys or []:
            full = str(key)
            _copy_string(source, dest, full)
        if cursor in (0, "0"):
            return


class TenantDirectory:
    """Opens one person's store without changing `current_actor`.

    The admin uses the legacy keys. Everyone else uses `u:{email}:` on the already
    prefixed store. `users:index` records when each address first signed in.
    """

    def __init__(self, store: KeyValueStore, admin_email: str | None, encryption_key: str | None):
        self.store = store
        self.admin_email = admin_email
        self.encryption_key = encryption_key

    def store_for(self, email: str | None) -> KeyValueStore:
        if email is None or email == self.admin_email:
            return self.store
        return PrefixedStore(self.store, f"u:{email}:")

    def vault_for(self, email: str | None) -> TokenVault:
        return TokenVault(self.store_for(email), self.encryption_key)

    def actor_store(self) -> ActorStore:
        return ActorStore(self.store, self.admin_email)

    def has_owner_refresh(self, email: str) -> bool:
        record = self.vault_for(email).owner()
        return bool(record and record.get("t"))

    def remember_user(self, email: str) -> None:
        if self.store.hget(USERS_INDEX, email) is None:
            self.store.hset(USERS_INDEX, email, json.dumps({"created_at": utc_now()}))

    def created_at(self, email: str) -> str | None:
        raw = self.store.hget(USERS_INDEX, email)
        if not raw:
            return None
        try:
            value = json.loads(raw).get("created_at")
        except ValueError:
            return None
        return str(value) if value else None

    def stored_bot_email(self, email: str) -> str | None:
        record = self.vault_for(email).bot()
        if not record or not record.get("t"):
            return None
        bot = record.get("email")
        return str(bot) if bot else None

    def known_users(self) -> list[str]:
        found = set(self.store.hgetall(USERS_INDEX))
        if self.admin_email and self.has_owner_refresh(self.admin_email):
            found.add(self.admin_email)
        return sorted(found, key=lambda email: (self.created_at(email) or "", email))

    def email_in_use(self, candidate: str, *, except_user: str, reserved_bot: str | None) -> bool:
        """True when `candidate` is someone else's dashboard address or bot address."""
        candidate = candidate.lower()
        dashboards = set(self.store.hgetall(USERS_INDEX))
        if self.admin_email:
            dashboards.add(self.admin_email)
        if candidate in dashboards:
            return True
        if reserved_bot and candidate == reserved_bot and except_user != self.admin_email:
            return True
        for user in dashboards:
            if user == except_user:
                continue
            if self.stored_bot_email(user) == candidate:
                return True
        return False


def build_store(settings: Any) -> PrefixedStore:
    if settings.postgres_configured:
        inner: KeyValueStore = PostgresStore(settings.postgres_url)
        if settings.redis_configured:
            redis = RedisStore(
                settings.redis_rest_url, settings.redis_rest_token.get_secret_value().strip()
            )
            try:
                import_admin_keys(redis, inner)
            except StoreImportError:
                raise
            except Exception as exc:
                # The exception text from the driver can contain the connection URL.
                logger.warning(
                    "copying the admin store from Redis to Postgres failed (%s)",
                    type(exc).__name__,
                )
                raise StoreImportError("admin store was not copied from Redis") from None
        return PrefixedStore(inner)
    if settings.redis_configured:
        inner = RedisStore(
            settings.redis_rest_url, settings.redis_rest_token.get_secret_value().strip()
        )
    else:
        inner = MemoryStore()
    return PrefixedStore(inner)
