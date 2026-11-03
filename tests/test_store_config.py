"""Settings for phase 2, the key-value stores, the token vault and the lazy bot client."""

import pytest
from pydantic import ValidationError

from scoped_drive_mcp.config import Settings
from scoped_drive_mcp.drive_client import BotNotConnectedError, LazyBotDriveClient
from scoped_drive_mcp.store import (
    ActivityLog,
    AllowEntry,
    Allowlist,
    MemoryStore,
    PrefixedStore,
    RedisStore,
    TokenVault,
    build_store,
)
from tests.conftest import API_TOKENS, ENCRYPTION_KEY, FakeClock, make_settings


def test_redis_env_names(monkeypatch) -> None:
    monkeypatch.setenv("API_TOKENS", API_TOKENS)
    monkeypatch.setenv("KV_REST_API_URL", "https://kv.example.upstash.io")
    monkeypatch.setenv("KV_REST_API_TOKEN", "kv-token")
    s = Settings()
    assert s.redis_rest_url == "https://kv.example.upstash.io" and s.redis_configured
    monkeypatch.setenv("UPSTASH_REDIS_REST_URL", "https://up.example.upstash.io")
    monkeypatch.setenv("UPSTASH_REDIS_REST_TOKEN", "up-token")
    s = Settings()
    assert s.redis_rest_url == "https://up.example.upstash.io"  # Upstash names win
    assert s.redis_rest_token.get_secret_value() == "up-token"
    assert "up-token" not in repr(s)


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
        {"app_base_url": "http://scoped.example.com"},
        {"app_base_url": "ftp://x"},
        {"redis_rest_url": "http://insecure.example.com"},
        {"allowlist_cache_ttl": 60},
    ],
)
def test_invalid_phase2_settings(overrides) -> None:
    with pytest.raises(ValidationError):
        make_settings(**overrides)


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
    vault.set_owner("refresh-secret", "owner@example.com")
    raw = kv.get("vault:owner_refresh_token")
    assert raw and "refresh-secret" not in raw and "owner@example.com" not in raw
    assert vault.owner()["t"] == "refresh-secret"
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


def test_make_secrets_script(capsys) -> None:
    import runpy

    runpy.run_path("scripts/make_secrets.py", run_name="__main__")
    out = capsys.readouterr().out
    lines = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    assert len(lines["SESSION_SECRET"]) >= 32
    make_settings(session_secret=lines["SESSION_SECRET"], encryption_key=lines["ENCRYPTION_KEY"])
