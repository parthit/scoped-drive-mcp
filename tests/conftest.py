import hashlib

import pytest

from scoped_drive_mcp.config import Settings
from scoped_drive_mcp.drive_client import FOLDER_MIME, SHORTCUT_MIME
from scoped_drive_mcp.scope import ScopeGuard
from scoped_drive_mcp.server import build_app
from scoped_drive_mcp.service import DOC_MIME, SHEET_MIME, DriveService
from tests.fake_drive import FakeDrive

ROOT = "root-folder-0001"

TOKENS = {
    "viewer": "viewer-secret-token",
    "editor": "editor-secret-token",
    "admin": "admin-secret-token",
}


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


API_TOKENS = ",".join(f"{role}-tok:{role}:{sha(tok)}" for role, tok in TOKENS.items())


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def build_tree() -> FakeDrive:
    d = FakeDrive()
    d.add(ROOT, "Shared With Grok", FOLDER_MIME, ["bot-my-drive-root"])
    d.add("bot-my-drive-root", "My Drive", FOLDER_MIME, [])
    d.add("sub-a", "Projects", FOLDER_MIME, [ROOT])
    d.add("sub-a-deep", "Deep", FOLDER_MIME, ["sub-a"])
    d.add("doc-deep", "Deep plan", DOC_MIME, ["sub-a-deep"], b"the deep secret plan")
    d.add("notes-txt", "notes.txt", "text/plain", ["sub-a"], b"plan notes inside")
    d.add("sheet-1", "Budget", SHEET_MIME, [ROOT], b"a,b\n1,2\n")
    d.add("image-png", "photo.png", "image/png", [ROOT], b"\x89PNG\r\n\x1a\n\x00\x00")
    d.add("trashed-txt", "old plan.txt", "text/plain", [ROOT], b"plan trashed", trashed=True)
    d.add("shortcut-1", "link to outside", SHORTCUT_MIME, [ROOT])
    d.add("outside-folder", "Private", FOLDER_MIME, ["bot-my-drive-root"])
    d.add("outside-file", "plan outside.txt", "text/plain", ["outside-folder"], b"outside plan")
    d.add("multi-parent", "plan both.txt", "text/plain", ["outside-folder", "sub-a"], b"plan x")
    d.add("cycle-a", "Cycle A", FOLDER_MIME, ["cycle-b"])
    d.add("cycle-b", "Cycle B", FOLDER_MIME, ["cycle-a"])
    d.add("cycle-file", "plan cycle.txt", "text/plain", ["cycle-a"], b"cycle plan")
    d.add("orphan-file", "plan orphan.txt", "text/plain", [], b"orphan plan")
    d.add("dangling-file", "plan dangling.txt", "text/plain", ["missing-parent"], b"dangling")
    return d


def make_settings(**overrides) -> Settings:
    values = {
        "root_folder_id": ROOT,
        "api_tokens": API_TOKENS,
        "google_oauth_client_id": "test-client-id",
        "google_oauth_client_secret": "test-client-secret",
        "google_oauth_refresh_token": "test-refresh-token",
        "scope_cache_ttl": 60,
        "max_bytes": 4096,
        "max_chars": 2000,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def drive() -> FakeDrive:
    return build_tree()


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def guard(drive: FakeDrive, clock: FakeClock) -> ScopeGuard:
    return ScopeGuard(drive, ROOT, ttl=60, clock=clock)


@pytest.fixture
def service(drive: FakeDrive, guard: ScopeGuard, settings: Settings) -> DriveService:
    return DriveService(drive, guard, settings)


@pytest.fixture
def app(drive: FakeDrive, settings: Settings, clock: FakeClock):
    return build_app(
        settings,
        drive,
        guard_factory=lambda d, s: ScopeGuard(
            d, s.root_folder_id, ttl=s.scope_cache_ttl, clock=clock
        ),
    )
