import hashlib
import secrets

import pytest
from cryptography.fernet import Fernet

from scoped_drive_mcp.access import AccessRequests, AccessService
from scoped_drive_mcp.config import Settings
from scoped_drive_mcp.drive_client import FOLDER_MIME, SHORTCUT_MIME
from scoped_drive_mcp.scope import ScopeGuard
from scoped_drive_mcp.server import build_app
from scoped_drive_mcp.service import DOC_MIME, SHEET_MIME, DriveService
from scoped_drive_mcp.store import MemoryStore, PrefixedStore
from tests.fake_drive import FakeDrive

ROOT = "root-folder-0001"
BASE_URL = "https://drive-test.example.com"
OWNER_EMAIL = "owner@example.com"
BOT_EMAIL = "bot@example.com"
# Generated per test run so nothing in the repo looks like a real credential.
SESSION_SECRET = secrets.token_urlsafe(48)
ENCRYPTION_KEY = Fernet.generate_key().decode()
TOKENS = {role: secrets.token_urlsafe(32) for role in ("viewer", "editor", "admin")}
CLIENT_ID = "placeholder-client-id"
CLIENT_SECRET = f"placeholder-{secrets.token_hex(8)}"
REFRESH_TOKEN = f"placeholder-{secrets.token_hex(8)}"


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


MODES = ("same_account",)


def build_tree(mode: str | None = None) -> FakeDrive:
    """The phase-1 tree. With `mode`, every file belongs to the owner and the result is
    that owner's view: the tools can see the whole Drive, and the allowlist is the limit."""
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
    d.add("shortcut-1", "link to outside", SHORTCUT_MIME, [ROOT], shortcut_target="outside-file")
    d.add("outside-folder", "Private", FOLDER_MIME, ["bot-my-drive-root"])
    d.add("outside-file", "plan outside.txt", "text/plain", ["outside-folder"], b"outside plan")
    d.add("multi-parent", "plan both.txt", "text/plain", ["outside-folder", "sub-a"], b"plan x")
    d.add("cycle-a", "Cycle A", FOLDER_MIME, ["cycle-b"])
    d.add("cycle-b", "Cycle B", FOLDER_MIME, ["cycle-a"])
    d.add("cycle-file", "plan cycle.txt", "text/plain", ["cycle-a"], b"cycle plan")
    d.add("orphan-file", "plan orphan.txt", "text/plain", [], b"orphan plan")
    d.add("dangling-file", "plan dangling.txt", "text/plain", ["missing-parent"], b"dangling")
    if mode is None:
        return d
    for f in d.files.values():
        f.owner = OWNER_EMAIL
    d.default_owner = OWNER_EMAIL
    return d.as_user(OWNER_EMAIL)


def make_settings(**overrides) -> Settings:
    values = {
        "root_folder_id": ROOT,
        "api_tokens": API_TOKENS,
        "google_oauth_client_id": CLIENT_ID,
        "google_oauth_client_secret": CLIENT_SECRET,
        "google_oauth_refresh_token": REFRESH_TOKEN,
        "scope_cache_ttl": 60,
        "max_bytes": 4096,
        "max_chars": 2000,
        "owner_email": OWNER_EMAIL,
        "bot_email": BOT_EMAIL,
        "app_base_url": BASE_URL,
        "session_secret": SESSION_SECRET,
        "encryption_key": ENCRYPTION_KEY,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture(params=MODES)
def mode(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture
def drive(mode: str) -> FakeDrive:
    return build_tree(mode)


@pytest.fixture
def settings(mode: str) -> Settings:
    return make_settings(bot_email=None if mode == "same_account" else BOT_EMAIL)


@pytest.fixture
def guard(drive: FakeDrive, clock: FakeClock) -> ScopeGuard:
    return ScopeGuard(drive, ROOT, ttl=60, clock=clock)


@pytest.fixture
def service(drive: FakeDrive, guard: ScopeGuard, settings: Settings) -> DriveService:
    return DriveService(drive, guard, settings)


@pytest.fixture
def requests_store() -> AccessRequests:
    return AccessRequests(PrefixedStore(MemoryStore()))


@pytest.fixture
def access(requests_store: AccessRequests, guard: ScopeGuard, service: DriveService):
    return AccessService(requests_store, BASE_URL, guard, service.peek_name)


@pytest.fixture
def app(drive: FakeDrive, settings: Settings, clock: FakeClock):
    return build_app(
        settings,
        drive,
        guard_factory=lambda d, s, allow: ScopeGuard(
            d,
            s.root_folder_id,
            ttl=s.scope_cache_ttl,
            allowlist=allow,
            clock=clock,
            admin_email=s.owner_email,
        ),
        store=MemoryStore(),
    )


# ---- phase 2: one Drive seen by the owner and by the bot -------------------

EVE = "eve@example.com"


class FakeOAuth:
    """Google OAuth stand-in: the code says which account signed in."""

    def __init__(self) -> None:
        self.revoked: list[str] = []
        self.hints: list[str | None] = []
        self.accounts = {
            "owner-code": (OWNER_EMAIL, True),
            "bot-code": (BOT_EMAIL, True),
            "eve-code": (EVE, True),
            "unverified-owner-code": (OWNER_EMAIL, False),
        }
        self.scopes = frozenset({"openid", "email", "https://www.googleapis.com/auth/drive"})

    def authorization_url(self, state: str, login_hint: str | None = None) -> str:
        self.hints.append(login_hint)
        return f"https://accounts.google.com/o/oauth2/v2/auth?state={state}"

    def exchange_code(self, code: str):
        from scoped_drive_mcp.oauth import OAuthError, OAuthTokens

        if code not in self.accounts:
            raise OAuthError("Google rejected the sign-in code")
        email = self.accounts[code][0]
        return OAuthTokens(
            access_token=f"at:{code}", refresh_token=f"rt-{email}", scopes=self.scopes
        )

    def userinfo(self, access_token: str) -> dict:
        email, verified = self.accounts[access_token.removeprefix("at:")]
        return {"email": email, "email_verified": verified}

    def revoke(self, token: str) -> None:
        self.revoked.append(token)


def build_world() -> FakeDrive:
    """The owner's My Drive. Nothing is shared with the bot yet, except one stray file a
    third party shared with it (which must still be refused: it is not on the allowlist)."""
    w = FakeDrive()
    w.roots[OWNER_EMAIL] = "owner-root"
    w.roots[BOT_EMAIL] = "bot-root"
    o = {"owner": OWNER_EMAIL}
    w.add("owner-root", "My Drive", FOLDER_MIME, [], **o)
    w.add("bot-root", "My Drive", FOLDER_MIME, [], owner=BOT_EMAIL)
    w.add("proj", "Projects", FOLDER_MIME, ["owner-root"], **o)
    w.add("proj-sub", "Sub", FOLDER_MIME, ["proj"], **o)
    w.add("proj-deep-doc", "Deep roadmap", DOC_MIME, ["proj-sub"], b"roadmap secret", **o)
    w.add("proj-notes", "notes.txt", "text/plain", ["proj"], b"project notes alpha", **o)
    w.add(
        "proj-shortcut",
        "link to payroll",
        SHORTCUT_MIME,
        ["proj"],
        shortcut_target="priv-secret",
        **o,
    )
    w.add("priv", "Private", FOLDER_MIME, ["owner-root"], **o)
    w.add("priv-secret", "payroll.txt", "text/plain", ["priv"], b"TOP SECRET payroll", **o)
    w.add("priv-other", "other.txt", "text/plain", ["priv"], b"other private", **o)
    w.add("loose-doc", "Loose memo", DOC_MIME, ["owner-root"], b"memo beta", **o)
    w.add("loose-two", "Second memo", DOC_MIME, ["owner-root"], b"memo gamma", **o)
    w.add("eve-root", "My Drive", FOLDER_MIME, [], owner=EVE)
    w.add(
        "stray-shared", "secret from eve.txt", "text/plain", ["eve-root"], b"eve secret", owner=EVE
    )
    w.share("stray-shared", BOT_EMAIL, "reader")
    return w


@pytest.fixture
def world() -> FakeDrive:
    return build_world()


@pytest.fixture
def oauth() -> FakeOAuth:
    return FakeOAuth()


@pytest.fixture
def memstore() -> MemoryStore:
    return MemoryStore()


@pytest.fixture
def p2_settings() -> Settings:
    return make_settings(root_folder_id=None, allowlist_cache_ttl=0)


@pytest.fixture
def p2_app(world: FakeDrive, p2_settings: Settings, memstore: MemoryStore, oauth: FakeOAuth):
    owner_tokens: list[str] = []

    def owner_factory(token: str) -> FakeDrive:
        owner_tokens.append(token)
        return world.as_user(OWNER_EMAIL)

    app = build_app(
        p2_settings,
        world.as_user(OWNER_EMAIL),
        store=memstore,
        owner_drive_factory=owner_factory,
        oauth=oauth,
    )
    app.state.owner_tokens = owner_tokens
    return app
