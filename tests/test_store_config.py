"""Settings for phase 2, the key-value stores, the token vault and the lazy bot client."""

import secrets
import threading

import pytest
from pydantic import ValidationError

from scoped_drive_mcp.auth import current_actor
from scoped_drive_mcp.config import Settings
from scoped_drive_mcp.drive_client import BotNotConnectedError, LazyBotDriveClient
from scoped_drive_mcp.store import (
    REDIS_IMPORT_FLAG,
    REDIS_IMPORT_LOCK,
    ActivityLog,
    AllowEntry,
    Allowlist,
    MemoryStore,
    PrefixedStore,
    RedisStore,
    StoreImportError,
    TokenVault,
    build_store,
    import_admin_keys,
)
from tests.conftest import API_TOKENS, ENCRYPTION_KEY, FakeClock, make_settings

KV_TOKEN = secrets.token_urlsafe(16)
UP_TOKEN = secrets.token_urlsafe(16)
VAULT_TOKEN = secrets.token_urlsafe(16)


def test_redis_env_names(monkeypatch) -> None:
    monkeypatch.setenv("API_TOKENS", API_TOKENS)
    monkeypatch.setenv("KV_REST_API_URL", "https://kv.example.upstash.io")
    monkeypatch.setenv("KV_REST_API_TOKEN", KV_TOKEN)
    s = Settings()
    assert s.redis_rest_url == "https://kv.example.upstash.io" and s.redis_configured
    monkeypatch.setenv("UPSTASH_REDIS_REST_URL", "https://up.example.upstash.io")
    monkeypatch.setenv("UPSTASH_REDIS_REST_TOKEN", UP_TOKEN)
    s = Settings()
    assert s.redis_rest_url == "https://up.example.upstash.io"  # Upstash names win
    assert s.redis_rest_token.get_secret_value() == UP_TOKEN
    assert UP_TOKEN not in repr(s)


def test_phase2_env(monkeypatch) -> None:
    monkeypatch.setenv("API_TOKENS", API_TOKENS)
    monkeypatch.setenv("OWNER_EMAIL", " Owner@Example.com ")
    monkeypatch.setenv("BOT_EMAIL", "bot@example.com")
    monkeypatch.setenv("APP_BASE_URL", "https://scoped-drive-mcp.vercel.app/")
    monkeypatch.setenv("ROOT_FOLDER_ID", "")
    s = Settings()
    assert s.owner_email == "owner@example.com"
    assert s.app_base_url == "https://scoped-drive-mcp.vercel.app"
    assert s.root_folder_id is None
    assert s.missing_settings() == [
        "GOOGLE_OAUTH_CLIENT_ID",
        "GOOGLE_OAUTH_CLIENT_SECRET",
        "SESSION_SECRET",
        "ENCRYPTION_KEY",
        "UPSTASH_REDIS_REST_URL",
        "UPSTASH_REDIS_REST_TOKEN",
    ]


@pytest.mark.parametrize(
    "overrides",
    [
        {"encryption_key": "not-a-fernet-key"},
        {"session_secret": "short"},
        {"owner_email": "not-an-email"},
        {"allowed_emails": "not-an-email"},
        {"app_base_url": "http://scoped.example.com"},
        {"app_base_url": "ftp://x"},
        {"redis_rest_url": "http://insecure.example.com"},
        {"allowlist_cache_ttl": 60},
    ],
)
def test_invalid_phase2_settings(overrides) -> None:
    with pytest.raises(ValidationError):
        make_settings(**overrides)


def test_allowed_emails_blank_is_open(monkeypatch) -> None:
    monkeypatch.setenv("API_TOKENS", API_TOKENS)
    monkeypatch.setenv("OWNER_EMAIL", "owner@example.com")
    monkeypatch.setenv("ALLOWED_EMAILS", " Eve@Example.com , ")
    listed = Settings()
    assert listed.allowed_emails == frozenset({"eve@example.com"})
    assert listed.sign_in_allowed("eve@example.com")
    assert listed.sign_in_allowed("owner@example.com")
    assert not listed.sign_in_allowed("other@example.com")
    monkeypatch.setenv("ALLOWED_EMAILS", "  ")
    assert Settings().sign_in_allowed("other@example.com")


def test_localhost_base_url_allowed_and_cookies() -> None:
    s = make_settings(app_base_url="http://localhost:8000")
    assert s.app_base_url == "http://localhost:8000" and s.secure_cookies is False
    assert make_settings().secure_cookies is True


def test_build_store_picks_backend() -> None:
    assert build_store(make_settings()).kind == "memory"
    s = make_settings(redis_rest_url="https://x.upstash.io", redis_rest_token="tok")
    store = build_store(s)
    assert store.kind == "redis" and isinstance(store.inner, RedisStore)


def test_memory_store_ttl_and_lists() -> None:
    clock = FakeClock()
    m = MemoryStore(clock=clock)
    m.set("k", "v", ex=5)
    assert m.get("k") == "v"
    clock.advance(6)
    assert m.get("k") is None
    for i in range(5):
        m.lpush("l", str(i))
    m.ltrim("l", 0, 2)
    assert m.lrange("l", 0, -1) == ["4", "3", "2"]
    m.hset("h", "a", "1")
    assert m.hgetall("h") == {"a": "1"} and m.hget("h", "b") is None
    m.hdel("h", "a")
    assert m.hgetall("h") == {}


def test_prefixed_store_namespaces_keys() -> None:
    inner = MemoryStore()
    p = PrefixedStore(inner)
    p.set("a", "1")
    assert inner.get("sdm:a") == "1" and inner.get("a") is None


def test_redis_store_calls(monkeypatch) -> None:
    calls = []

    class FakeRedis:
        def __init__(self, **kwargs):
            calls.append(("init", kwargs))

        def __getattr__(self, name):
            def call(*args, **kwargs):
                calls.append((name, args, kwargs))
                return {"hgetall": {"a": "1"}, "lrange": ["x"], "get": "v"}.get(name)

            return call

    import upstash_redis

    monkeypatch.setattr(upstash_redis, "Redis", FakeRedis)
    r = RedisStore("https://x.upstash.io", "tok")
    assert calls[0][1]["allow_telemetry"] is False
    r.set("k", "v", ex=10)
    assert r.get("k") == "v"
    assert r.hgetall("h") == {"a": "1"} and r.lrange("l", 0, -1) == ["x"]
    assert ("set", ("k", "v"), {"ex": 10}) in calls


def test_token_vault_encrypts() -> None:
    kv = PrefixedStore(MemoryStore())
    vault = TokenVault(kv, ENCRYPTION_KEY)
    vault.set_owner(VAULT_TOKEN, "owner@example.com")
    raw = kv.get("vault:owner_refresh_token")
    assert raw and VAULT_TOKEN not in raw and "owner@example.com" not in raw
    assert vault.owner()["t"] == VAULT_TOKEN
    from cryptography.fernet import Fernet

    other = TokenVault(kv, Fernet.generate_key().decode())
    assert other.owner() is None  # wrong key cannot read it
    assert TokenVault(kv, None).owner() is None
    vault.clear_owner()
    assert vault.owner() is None


def test_allowlist_roundtrip_and_corrupt_entries() -> None:
    kv = PrefixedStore(MemoryStore())
    allow = Allowlist(kv)
    allow.add(AllowEntry("f1", "File", "text/plain", "perm-1"))
    kv.hset("allowlist", "bad", "{not json")
    assert set(allow.entries()) == {"f1"}
    assert allow.mime_map() == {"f1": "text/plain"}


def test_activity_log_newest_first() -> None:
    log = ActivityLog(PrefixedStore(MemoryStore()), max_items=3)
    for i in range(5):
        log({"n": i})
    assert [r["n"] for r in log.recent()] == [4, 3, 2]


def test_lazy_bot_client_prefers_env_then_store() -> None:
    built = []

    def factory(token):
        built.append(token)
        return object()

    stored = {"t": None}
    clock = FakeClock()
    lazy = LazyBotDriveClient(None, lambda: stored["t"], factory, ttl=30, clock=clock)
    with pytest.raises(BotNotConnectedError):
        lazy._inner()
    stored["t"] = "from-store"
    with pytest.raises(BotNotConnectedError):
        lazy._inner()  # cached "not connected" for up to ttl
    lazy.invalidate()
    lazy._inner()
    lazy._inner()
    assert built == ["from-store"]
    stored["t"] = "rotated"
    clock.advance(31)
    lazy._inner()
    assert built == ["from-store", "rotated"]

    env = LazyBotDriveClient("from-env", lambda: "from-store", factory)
    env._inner()
    assert built[-1] == "from-env"


def test_actor_store_keeps_admin_keys_and_prefixes_others() -> None:
    from scoped_drive_mcp.store import ActorStore

    inner = MemoryStore()
    actor = ActorStore(PrefixedStore(inner), "owner@example.com")
    token = current_actor.set("owner@example.com")
    try:
        actor.set("allowlist", "admin")
    finally:
        current_actor.reset(token)
    token = current_actor.set("eve@example.com")
    try:
        actor.set("allowlist", "eve")
    finally:
        current_actor.reset(token)
    assert inner.get("sdm:allowlist") == "admin"
    assert inner.get("sdm:u:eve@example.com:allowlist") == "eve"
    unset = current_actor.set(None)
    try:
        assert actor.get("allowlist") == "admin"
    finally:
        current_actor.reset(unset)


def test_import_admin_keys_runs_once() -> None:
    source = MemoryStore()
    dest = MemoryStore()
    source.hset("sdm:allowlist", "file-1", "{}")
    source.set("sdm:vault:owner_refresh_token", "enc-owner")
    source.set("sdm:vault:bot_refresh_token", "enc-bot")
    source.lpush("sdm:activity", "older")
    source.lpush("sdm:activity", "newer")
    source.lpush("sdm:requests:index", "rid")
    source.set("sdm:req:rid", '{"file_id":"file-1"}')
    source.set("sdm:req:pending:file-1", "rid")
    import_admin_keys(source, dest)
    import_admin_keys(source, dest)
    assert dest.hget("sdm:allowlist", "file-1") == "{}"
    assert dest.get("sdm:vault:owner_refresh_token") == "enc-owner"
    assert dest.get("sdm:vault:bot_refresh_token") == "enc-bot"
    assert dest.lrange("sdm:activity", 0, -1) == ["newer", "older"]
    assert dest.get("sdm:req:rid") == '{"file_id":"file-1"}'
    assert dest.get("sdm:req:pending:file-1") == "rid"
    assert dest.get("sdm:meta:redis_admin_imported")


def test_set_if_absent_and_replace_list() -> None:
    clock = FakeClock()
    store = MemoryStore(clock=clock)
    assert store.set_if_absent("lock", "first", ex=10) is True
    assert store.set_if_absent("lock", "second", ex=10) is False
    assert store.get("lock") == "first"
    clock.advance(11)
    assert store.set_if_absent("lock", "third", ex=10) is True
    store.lpush("items", "old")
    store.replace_list("items", ["newer", "older"])
    assert store.lrange("items", 0, -1) == ["newer", "older"]
    store.replace_list("items", [])
    assert store.lrange("items", 0, -1) == []


def test_import_failure_does_not_mark_done(monkeypatch) -> None:
    import scoped_drive_mcp.store as store_mod

    source = MemoryStore()
    dest = MemoryStore()
    source.hset("sdm:allowlist", "file-1", "{}")
    source.lpush("sdm:activity", "older")
    source.lpush("sdm:activity", "newer")
    source.lpush("sdm:requests:index", "rid")
    calls = {"n": 0}
    real_copy = store_mod._copy_list

    def flaky(src: MemoryStore, dst: MemoryStore, key: str) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("postgresql://user:secret-token@localhost/db")
        real_copy(src, dst, key)

    monkeypatch.setattr(store_mod, "_copy_list", flaky)
    with pytest.raises(RuntimeError, match="secret-token"):
        import_admin_keys(source, dest)
    assert dest.get(REDIS_IMPORT_FLAG) is None
    assert dest.get(REDIS_IMPORT_LOCK) is None
    import_admin_keys(source, dest)
    assert dest.hget("sdm:allowlist", "file-1") == "{}"
    assert dest.lrange("sdm:activity", 0, -1) == ["newer", "older"]
    assert dest.lrange("sdm:requests:index", 0, -1) == ["rid"]
    assert dest.get(REDIS_IMPORT_FLAG)
    assert dest.get(REDIS_IMPORT_LOCK) is None


def test_concurrent_import_has_one_winner(monkeypatch) -> None:
    import scoped_drive_mcp.store as store_mod

    source = MemoryStore()
    dest = MemoryStore()
    source.lpush("sdm:activity", "older")
    source.lpush("sdm:activity", "newer")
    source.lpush("sdm:requests:index", "rid-a")
    source.lpush("sdm:requests:index", "rid-b")
    entered = threading.Event()
    release = threading.Event()
    real_copy = store_mod._copy_list

    def slow(src: MemoryStore, dst: MemoryStore, key: str) -> None:
        if key.endswith("activity"):
            entered.set()
            assert release.wait(2)
        real_copy(src, dst, key)

    monkeypatch.setattr(store_mod, "_copy_list", slow)
    errors: list[str] = []

    def loser() -> None:
        try:
            import_admin_keys(source, dest)
        except StoreImportError as exc:
            errors.append(str(exc))

    winner = threading.Thread(target=import_admin_keys, args=(source, dest))
    winner.start()
    assert entered.wait(2)
    loser()
    release.set()
    winner.join(2)
    assert not winner.is_alive()
    assert errors == ["admin store copy is already running"]
    assert dest.lrange("sdm:activity", 0, -1) == ["newer", "older"]
    assert dest.lrange("sdm:requests:index", 0, -1) == ["rid-b", "rid-a"]
    assert dest.get(REDIS_IMPORT_FLAG)
    assert dest.get(REDIS_IMPORT_LOCK) is None
    import_admin_keys(source, dest)
    assert dest.lrange("sdm:activity", 0, -1) == ["newer", "older"]


def test_build_store_does_not_serve_postgres_when_import_fails(monkeypatch) -> None:
    import scoped_drive_mcp.store as store_mod

    created: dict[str, MemoryStore] = {}

    class Boom(MemoryStore):
        kind = "postgres"

        def __init__(self, url: str):
            super().__init__()
            self.url = url
            created["store"] = self

        def get(self, key: str) -> str | None:
            raise RuntimeError(f"could not connect to {self.url}")

    monkeypatch.setattr(store_mod, "PostgresStore", Boom)
    monkeypatch.setattr(store_mod, "RedisStore", lambda url, token: MemoryStore())
    settings = make_settings(
        database_url="postgresql://user:secret-token@localhost/db",
        redis_rest_url="https://x.upstash.io",
        redis_rest_token="tok",
    )
    with pytest.raises(StoreImportError) as caught:
        build_store(settings)
    assert "secret-token" not in str(caught.value)
    assert "postgresql" not in str(caught.value)
    assert REDIS_IMPORT_FLAG not in created["store"]._values


def test_postgres_url_is_not_in_repr() -> None:
    url = "postgresql://user:secret-token@localhost/db"
    settings = make_settings(database_url=url)
    assert settings.postgres_configured
    assert "secret-token" not in repr(settings)
    store = build_store(settings)
    assert store.kind == "postgres"
    assert "secret-token" not in repr(store)
    assert settings.missing_settings() == []


def test_make_secrets_script(capsys) -> None:
    import runpy

    runpy.run_path("scripts/make_secrets.py", run_name="__main__")
    out = capsys.readouterr().out
    lines = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    assert len(lines["SESSION_SECRET"]) >= 32
    make_settings(session_secret=lines["SESSION_SECRET"], encryption_key=lines["ENCRYPTION_KEY"])
