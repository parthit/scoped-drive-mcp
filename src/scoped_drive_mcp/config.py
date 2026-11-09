"""Settings loaded from environment variables only (no credential files on disk).

Only malformed values (and a missing API_TOKENS) make the settings fail to load. Settings the
dashboard or the bot connection need are optional at load time; `missing_settings()` reports
which ones are absent so /health can list them (names only, never values).
"""

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_DRIVE_ID = re.compile(r"^[A-Za-z0-9_-]{10,200}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_LOCAL_HOSTS = ("localhost", "127.0.0.1")


class Role(StrEnum):
    VIEWER = "viewer"
    EDITOR = "editor"
    ADMIN = "admin"


@dataclass(frozen=True)
class TokenEntry:
    name: str
    role: Role
    sha256: str


def parse_api_tokens(raw: str) -> list[TokenEntry]:
    """Parse `name:role:sha256hex,name:role:sha256hex,...`."""
    entries: list[TokenEntry] = []
    seen_names: set[str] = set()
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split(":")
        if len(parts) != 3:
            raise ValueError("each API_TOKENS entry must look like name:role:sha256hex")
        name, role, digest = (p.strip() for p in parts)
        digest = digest.lower()
        if not _TOKEN_NAME.fullmatch(name):
            raise ValueError(f"invalid token name {name!r} (use letters, digits, _ . -)")
        if name in seen_names:
            raise ValueError(f"duplicate token name {name!r}")
        try:
            parsed_role = Role(role.lower())
        except ValueError:
            raise ValueError(
                f"invalid role {role!r} for token {name!r} (use viewer, editor or admin)"
            ) from None
        if not _SHA256_HEX.fullmatch(digest):
            raise ValueError(f"token {name!r} hash must be 64 lowercase hex characters (SHA-256)")
        seen_names.add(name)
        entries.append(TokenEntry(name=name, role=parsed_role, sha256=digest))
    if not entries:
        raise ValueError("API_TOKENS must contain at least one entry")
    return entries


def _secret_set(value: SecretStr | None) -> bool:
    return value is not None and bool(value.get_secret_value().strip())


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore", case_sensitive=False)

    # Optional since phase 2: when set it is one more allowlisted root folder.
    root_folder_id: str | None = None
    auth_mode: Literal["oauth_bot"] = "oauth_bot"

    google_oauth_client_id: SecretStr | None = None
    google_oauth_client_secret: SecretStr | None = None
    # Optional since phase 2: the bot can be connected from the dashboard instead.
    google_oauth_refresh_token: SecretStr | None = None

    api_tokens: Annotated[list[TokenEntry], NoDecode]

    owner_email: str | None = None
    bot_email: str | None = None
    app_base_url: str | None = None
    session_secret: SecretStr | None = None
    encryption_key: SecretStr | None = None

    redis_rest_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "redis_rest_url", "upstash_redis_rest_url", "kv_rest_api_url"
        ),
    )
    redis_rest_token: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "redis_rest_token", "upstash_redis_rest_token", "kv_rest_api_token"
        ),
    )
    # Vercel Marketplace Neon injects a pooled DATABASE_URL (or POSTGRES_URL).
    database_url: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("database_url", "postgres_url"),
    )

    max_bytes: int = Field(default=5 * 1024 * 1024, ge=1024, le=50 * 1024 * 1024)
    max_chars: int = Field(default=100_000, ge=1000, le=2_000_000)
    scope_cache_ttl: float = Field(default=60.0, ge=0, le=3600)
    # How long the allowlist is cached per instance; bounds how fast a revoke takes effect.
    allowlist_cache_ttl: float = Field(default=2.0, ge=0, le=10)

    @field_validator(
        "root_folder_id",
        "owner_email",
        "bot_email",
        "app_base_url",
        "redis_rest_url",
        "google_oauth_client_id",
        "google_oauth_client_secret",
        "google_oauth_refresh_token",
        "session_secret",
        "encryption_key",
        "redis_rest_token",
        "database_url",
        mode="before",
    )
    @classmethod
    def _blank_is_unset(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("root_folder_id")
    @classmethod
    def _check_root(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not _DRIVE_ID.fullmatch(value):
            raise ValueError("ROOT_FOLDER_ID does not look like a Google Drive folder ID")
        return value

    @field_validator("owner_email", "bot_email")
    @classmethod
    def _check_email(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().lower()
        if not _EMAIL.fullmatch(value):
            raise ValueError("must be an email address")
        return value

    @field_validator("app_base_url")
    @classmethod
    def _check_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().rstrip("/")
        scheme, _, rest = value.partition("://")
        host = rest.split("/", 1)[0].split(":", 1)[0]
        if scheme == "https" and host:
            return value
        if scheme == "http" and host in _LOCAL_HOSTS:
            return value
        raise ValueError("APP_BASE_URL must be https://... (http:// only for localhost)")

    @field_validator("database_url")
    @classmethod
    def _check_database_url(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        url = value.get_secret_value().strip()
        if not url.startswith(("postgres://", "postgresql://")):
            raise ValueError("DATABASE_URL must start with postgres:// or postgresql://")
        return SecretStr(url)

    @field_validator("redis_rest_url")
    @classmethod
    def _check_redis_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value.startswith("https://"):
            raise ValueError("the Redis REST URL must start with https://")
        return value

    @field_validator("session_secret")
    @classmethod
    def _check_session_secret(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value().strip()) < 32:
            raise ValueError("SESSION_SECRET must be at least 32 characters")
        return value

    @field_validator("encryption_key")
    @classmethod
    def _check_encryption_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        from cryptography.fernet import Fernet

        try:
            Fernet(value.get_secret_value().strip().encode())
        except (ValueError, TypeError):
            raise ValueError(
                "ENCRYPTION_KEY must be a Fernet key (run scripts/make_secrets.py)"
            ) from None
        return value

    @field_validator("api_tokens", mode="before")
    @classmethod
    def _parse_tokens(cls, value: object) -> object:
        if isinstance(value, str):
            return parse_api_tokens(value)
        return value

    # ---- derived ---------------------------------------------------------

    @property
    def same_account(self) -> bool:
        """No separate bot: the MCP tools act as the owner and the allowlist is the only wall."""
        return self.bot_email is None or self.bot_email == self.owner_email

    @property
    def mode(self) -> Literal["same_account", "separate_bot"]:
        return "same_account" if self.same_account else "separate_bot"

    @property
    def oauth_client_configured(self) -> bool:
        return _secret_set(self.google_oauth_client_id) and _secret_set(
            self.google_oauth_client_secret
        )

    @property
    def redis_configured(self) -> bool:
        return bool(self.redis_rest_url) and _secret_set(self.redis_rest_token)

    @property
    def postgres_configured(self) -> bool:
        return _secret_set(self.database_url)

    @property
    def postgres_url(self) -> str | None:
        if not self.postgres_configured or self.database_url is None:
            return None
        return self.database_url.get_secret_value()

    @property
    def env_bot_refresh_token(self) -> str | None:
        if _secret_set(self.google_oauth_refresh_token):
            assert self.google_oauth_refresh_token is not None
            return self.google_oauth_refresh_token.get_secret_value().strip()
        return None

    def missing_settings(self) -> list[str]:
        """Names of required phase-2 settings that are not set (never their values)."""
        checks = [
            ("GOOGLE_OAUTH_CLIENT_ID", _secret_set(self.google_oauth_client_id)),
            ("GOOGLE_OAUTH_CLIENT_SECRET", _secret_set(self.google_oauth_client_secret)),
            ("OWNER_EMAIL", self.owner_email is not None),
            ("APP_BASE_URL", self.app_base_url is not None),
            ("SESSION_SECRET", _secret_set(self.session_secret)),
            ("ENCRYPTION_KEY", _secret_set(self.encryption_key)),
            ("UPSTASH_REDIS_REST_URL", self.redis_rest_url is not None),
            ("UPSTASH_REDIS_REST_TOKEN", _secret_set(self.redis_rest_token)),
        ]
        missing = [name for name, ok in checks if not ok]
        if self.postgres_configured:
            missing = [name for name in missing if not name.startswith("UPSTASH_")]
        return missing

    def dashboard_missing(self) -> list[str]:
        """Settings the web dashboard cannot run without (Redis may fall back to memory)."""
        return [m for m in self.missing_settings() if not m.startswith("UPSTASH_")]

    @property
    def secure_cookies(self) -> bool:
        return not (self.app_base_url or "").startswith("http://")
