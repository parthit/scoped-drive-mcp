"""Settings loaded from environment variables only (no credential files on disk)."""

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_DRIVE_ID = re.compile(r"^[A-Za-z0-9_-]{10,200}$")


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


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore", case_sensitive=False)

    root_folder_id: str
    auth_mode: Literal["oauth_bot"] = "oauth_bot"

    google_oauth_client_id: SecretStr | None = None
    google_oauth_client_secret: SecretStr | None = None
    google_oauth_refresh_token: SecretStr | None = None

    api_tokens: Annotated[list[TokenEntry], NoDecode]

    max_bytes: int = Field(default=5 * 1024 * 1024, ge=1024, le=50 * 1024 * 1024)
    max_chars: int = Field(default=100_000, ge=1000, le=2_000_000)
    scope_cache_ttl: float = Field(default=60.0, ge=0, le=3600)

    @field_validator("root_folder_id")
    @classmethod
    def _check_root(cls, value: str) -> str:
        value = value.strip()
        if not _DRIVE_ID.fullmatch(value):
            raise ValueError("ROOT_FOLDER_ID does not look like a Google Drive folder ID")
        return value

    @field_validator("api_tokens", mode="before")
    @classmethod
    def _parse_tokens(cls, value: object) -> object:
        if isinstance(value, str):
            return parse_api_tokens(value)
        return value

    @model_validator(mode="after")
    def _check_credentials(self) -> "Settings":
        if self.auth_mode == "oauth_bot":
            missing = [
                env
                for env, val in (
                    ("GOOGLE_OAUTH_CLIENT_ID", self.google_oauth_client_id),
                    ("GOOGLE_OAUTH_CLIENT_SECRET", self.google_oauth_client_secret),
                    ("GOOGLE_OAUTH_REFRESH_TOKEN", self.google_oauth_refresh_token),
                )
                if val is None or not val.get_secret_value().strip()
            ]
            if missing:
                raise ValueError(f"oauth_bot mode requires {', '.join(missing)}")
        return self
