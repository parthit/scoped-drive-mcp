import pytest
from pydantic import ValidationError

from scoped_drive_mcp.auth import extract_token, hash_token, verify_token
from scoped_drive_mcp.config import Role, Settings, parse_api_tokens
from tests.conftest import API_TOKENS, ROOT, TOKENS, make_settings, sha


def test_hash_token_is_sha256_hex() -> None:
    assert hash_token("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_verify_token() -> None:
    entries = parse_api_tokens(API_TOKENS)
    for role, token in TOKENS.items():
        principal = verify_token(token, entries)
        assert principal is not None
        assert principal.role == Role(role) and principal.token_name == f"{role}-tok"
    assert verify_token("wrong", entries) is None
    assert verify_token(sha(TOKENS["admin"]), entries) is None  # the hash itself is not a token


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("Bearer abc", "abc"),
        ("bearer abc", "abc"),
        ("Bearer   abc  ", "abc"),
        ("abc", "abc"),
        ("Basic abc", None),
        ("Bearer a b", None),
        ("Bearer ", None),
        ("", None),
        (None, None),
    ],
)
def test_extract_token(header, expected) -> None:
    assert extract_token(header) == expected


def test_parse_api_tokens() -> None:
    entries = parse_api_tokens(f" a:viewer:{sha('1')} , b:ADMIN:{sha('2').upper()} ,")
    assert [(e.name, e.role) for e in entries] == [("a", Role.VIEWER), ("b", Role.ADMIN)]
    assert entries[1].sha256 == sha("2")


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "a:viewer",
        f"a:root:{sha('1')}",
        "a:viewer:nothex",
        f"a:viewer:{sha('1')},a:admin:{sha('2')}",
        f"bad name:viewer:{sha('1')}",
        f"a:viewer:{sha('1')}:extra",
    ],
)
def test_parse_api_tokens_rejects(raw: str) -> None:
    with pytest.raises(ValueError):
        parse_api_tokens(raw)


def test_settings_from_env(monkeypatch) -> None:
    monkeypatch.setenv("ROOT_FOLDER_ID", ROOT)
    monkeypatch.setenv("API_TOKENS", API_TOKENS)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "id")
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "s3cr3t-value")
    monkeypatch.setenv("GOOGLE_OAUTH_REFRESH_TOKEN", "r3fr3sh-value")
    monkeypatch.setenv("MAX_BYTES", "2048")
    s = Settings()
    assert s.root_folder_id == ROOT
    assert len(s.api_tokens) == 3
    assert s.max_bytes == 2048
    assert s.max_chars == 100_000
    assert s.scope_cache_ttl == 60
    assert "s3cr3t-value" not in repr(s) and "r3fr3sh-value" not in repr(s)
    assert s.google_oauth_refresh_token.get_secret_value() == "r3fr3sh-value"


def test_refresh_token_and_root_are_optional() -> None:
    s = make_settings(google_oauth_refresh_token=None, root_folder_id=None)
    assert s.env_bot_refresh_token is None and s.root_folder_id is None
    # blank env values count as unset (the .env.example ships with empty values)
    s = make_settings(google_oauth_refresh_token="  ", root_folder_id="")
    assert s.env_bot_refresh_token is None and s.root_folder_id is None
    with pytest.raises(ValidationError):
        make_settings(root_folder_id="root")


def test_build_credentials_oauth_bot() -> None:
    from scoped_drive_mcp.drive_client import DRIVE_SCOPE, TOKEN_URI, build_credentials

    creds = build_credentials(make_settings())
    assert creds.refresh_token == "test-refresh-token"
    assert creds.client_id == "test-client-id"
    assert creds.token_uri == TOKEN_URI
    assert creds.scopes == [DRIVE_SCOPE]
