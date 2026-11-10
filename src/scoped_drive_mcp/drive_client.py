"""Google credentials and a thin Drive v3 wrapper.

The rest of the server only talks to the `DriveClient` protocol, so tests can
swap in an in-memory fake. The bot-facing wrapper deliberately exposes no way to
change parents, permissions or to permanently delete anything: `create` and
`update` only forward whitelisted metadata keys and never pass
addParents/removeParents. Permission calls exist only on `GoogleOwnerDriveClient`,
which the dashboard uses with the owner's own credentials.
"""

import io
import threading
import time
from collections.abc import Callable
from typing import Any, Protocol

from .config import Settings

DRIVE_SCOPE = "https://www.googleapis.com/auth/drive"
TOKEN_URI = "https://oauth2.googleapis.com/token"  # noqa: S105 - public endpoint, not a secret

FOLDER_MIME = "application/vnd.google-apps.folder"
SHORTCUT_MIME = "application/vnd.google-apps.shortcut"
GOOGLE_APPS_PREFIX = "application/vnd.google-apps."

CREATE_METADATA_KEYS = frozenset({"name", "mimeType", "parents"})
UPDATE_METADATA_KEYS = frozenset({"name", "trashed"})


class DriveNotFoundError(Exception):
    """The file does not exist or the identity cannot see it."""


OWNER_NOT_SIGNED_IN = (
    "The owner has not signed in to the dashboard yet. Ask the owner to open the "
    "dashboard and sign in with Google."
)
BOT_NOT_CONNECTED = OWNER_NOT_SIGNED_IN


class BotNotConnectedError(Exception):
    """No refresh token for the signed-in user (neither env var nor dashboard sign-in)."""

    def __init__(self, detail: str = "", user_message: str = BOT_NOT_CONNECTED):
        super().__init__(detail or user_message)
        self.user_message = user_message


class DriveClient(Protocol):
    def get_file(self, file_id: str, fields: str) -> dict[str, Any]: ...

    def list_files(
        self, q: str, fields: str, page_size: int, page_token: str | None = None
    ) -> dict[str, Any]: ...

    def export(self, file_id: str, mime_type: str) -> bytes: ...

    def download(self, file_id: str, max_bytes: int) -> bytes:
        """Return at most `max_bytes` bytes of the file's content."""
        ...

    def create(
        self,
        metadata: dict[str, Any],
        content: bytes | None,
        content_mime: str | None,
        fields: str,
    ) -> dict[str, Any]: ...

    def update(
        self,
        file_id: str,
        metadata: dict[str, Any] | None,
        content: bytes | None,
        content_mime: str | None,
        fields: str,
    ) -> dict[str, Any]: ...


class OwnerDriveClient(DriveClient, Protocol):
    def create_permission(self, file_id: str, email: str, role: str) -> str:
        """Share `file_id` with `email` without a notification email; return the permission id."""
        ...

    def delete_permission(self, file_id: str, permission_id: str) -> None: ...


def check_create_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    extra = set(metadata) - CREATE_METADATA_KEYS
    if extra:
        raise ValueError(f"refusing to send metadata keys {sorted(extra)}")
    parents = metadata.get("parents")
    if not isinstance(parents, list) or len(parents) != 1:
        raise ValueError("create needs exactly one parent")
    return dict(metadata)


def check_update_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    """Only rename and trash are allowed; `parents` and anything else is rejected."""
    metadata = dict(metadata or {})
    extra = set(metadata) - UPDATE_METADATA_KEYS
    if extra:
        raise ValueError(f"refusing to send metadata keys {sorted(extra)}")
    return metadata


class CredentialsProvider(Protocol):
    def __call__(self, settings: Settings) -> Any: ...


def oauth_credentials(settings: Settings, refresh_token: str) -> Any:
    from google.oauth2.credentials import Credentials

    assert settings.google_oauth_client_id is not None
    assert settings.google_oauth_client_secret is not None
    return Credentials(
        token=None,
        refresh_token=refresh_token,
        client_id=settings.google_oauth_client_id.get_secret_value(),
        client_secret=settings.google_oauth_client_secret.get_secret_value(),
        token_uri=TOKEN_URI,
        scopes=[DRIVE_SCOPE],
    )


def _oauth_bot_credentials(settings: Settings) -> Any:
    refresh_token = settings.env_bot_refresh_token
    if refresh_token is None:
        raise BotNotConnectedError("GOOGLE_OAUTH_REFRESH_TOKEN is not set")
    return oauth_credentials(settings, refresh_token)


# A `service_account` provider can be registered here later.
CREDENTIAL_PROVIDERS: dict[str, CredentialsProvider] = {
    "oauth_bot": _oauth_bot_credentials,
}


def build_credentials(settings: Settings) -> Any:
    try:
        provider = CREDENTIAL_PROVIDERS[settings.auth_mode]
    except KeyError:
        raise ValueError(f"unsupported AUTH_MODE {settings.auth_mode!r}") from None
    return provider(settings)


class GoogleDriveClient:
    """Drive v3 client. Builds one discovery service per thread (httplib2 is not thread-safe)."""

    def __init__(self, credentials: Any):
        self._credentials = credentials
        self._local = threading.local()

    def _service(self) -> Any:
        service = getattr(self._local, "service", None)
        if service is None:
            from googleapiclient.discovery import build

            service = build("drive", "v3", credentials=self._credentials, cache_discovery=False)
            self._local.service = service
        return service

    @staticmethod
    def _execute(request: Any) -> Any:
        from googleapiclient.errors import HttpError

        try:
            return request.execute(num_retries=2)
        except HttpError as exc:
            if exc.resp is not None and exc.resp.status == 404:
                raise DriveNotFoundError(str(exc.resp.status)) from None
            raise

    def get_file(self, file_id: str, fields: str) -> dict[str, Any]:
        files = self._service().files()
        return self._execute(files.get(fileId=file_id, fields=fields, supportsAllDrives=True))

    def list_files(
        self, q: str, fields: str, page_size: int, page_token: str | None = None
    ) -> dict[str, Any]:
        files = self._service().files()
        return self._execute(
            files.list(
                q=q,
                fields=f"nextPageToken, files({fields})",
                pageSize=page_size,
                pageToken=page_token,
                spaces="drive",
                corpora="allDrives",
                includeItemsFromAllDrives=True,
                supportsAllDrives=True,
            )
        )

    def export(self, file_id: str, mime_type: str) -> bytes:
        files = self._service().files()
        return self._execute(files.export(fileId=file_id, mimeType=mime_type))

    def download(self, file_id: str, max_bytes: int) -> bytes:
        files = self._service().files()
        request = files.get_media(fileId=file_id, supportsAllDrives=True)
        request.headers["Range"] = f"bytes=0-{max_bytes - 1}"
        from googleapiclient.errors import HttpError

        try:
            data = self._execute(request)
        except HttpError as exc:
            # 416 Range Not Satisfiable is what Drive returns for an empty file.
            if exc.resp is not None and exc.resp.status == 416:
                return b""
            raise
        return data[:max_bytes]

    @staticmethod
    def _media(content: bytes | None, content_mime: str | None) -> Any:
        if content is None:
            return None
        from googleapiclient.http import MediaIoBaseUpload

        return MediaIoBaseUpload(
            io.BytesIO(content), mimetype=content_mime or "application/octet-stream"
        )

    def create(
        self,
        metadata: dict[str, Any],
        content: bytes | None,
        content_mime: str | None,
        fields: str,
    ) -> dict[str, Any]:
        files = self._service().files()
        return self._execute(
            files.create(
                body=check_create_metadata(metadata),
                media_body=self._media(content, content_mime),
                fields=fields,
                supportsAllDrives=True,
            )
        )

    def update(
        self,
        file_id: str,
        metadata: dict[str, Any] | None,
        content: bytes | None,
        content_mime: str | None,
        fields: str,
    ) -> dict[str, Any]:
        files = self._service().files()
        return self._execute(
            files.update(
                fileId=file_id,
                body=check_update_metadata(metadata),
                media_body=self._media(content, content_mime),
                fields=fields,
                supportsAllDrives=True,
            )
        )


class GoogleOwnerDriveClient(GoogleDriveClient):
    """The owner's Drive, used only by the dashboard (browse, grant, revoke)."""

    def create_permission(self, file_id: str, email: str, role: str) -> str:
        permissions = self._service().permissions()
        resp = self._execute(
            permissions.create(
                fileId=file_id,
                body={"type": "user", "role": role, "emailAddress": email},
                sendNotificationEmail=False,
                supportsAllDrives=True,
                fields="id",
            )
        )
        return str(resp["id"])

    def delete_permission(self, file_id: str, permission_id: str) -> None:
        permissions = self._service().permissions()
        self._execute(
            permissions.delete(fileId=file_id, permissionId=permission_id, supportsAllDrives=True)
        )


class LazyBotDriveClient:
    """DriveClient for the signed-in user, whose refresh token is looked up on use.

    The env var GOOGLE_OAUTH_REFRESH_TOKEN wins; otherwise the token stored by
    dashboard sign-in is used (re-read at most every `ttl` seconds).
    """

    def __init__(
        self,
        env_token: str | None,
        stored_token: Callable[[], str | None],
        factory: Callable[[str], DriveClient],
        ttl: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
        not_connected_message: str = BOT_NOT_CONNECTED,
    ):
        self._not_connected_message = not_connected_message
        self._env_token = env_token
        self._stored_token = stored_token
        self._factory = factory
        self._ttl = ttl
        self._clock = clock
        self._lock = threading.Lock()
        self._checked: tuple[float, str | None] | None = None
        self._client: tuple[str, DriveClient] | None = None

    def invalidate(self) -> None:
        with self._lock:
            self._checked = None

    def current_token(self) -> str | None:
        if self._env_token:
            return self._env_token
        now = self._clock()
        with self._lock:
            if self._checked is not None and self._checked[0] > now:
                return self._checked[1]
        token = self._stored_token()
        with self._lock:
            self._checked = (now + self._ttl, token)
        return token

    def _inner(self) -> DriveClient:
        token = self.current_token()
        if not token:
            raise BotNotConnectedError(
                "the bot account is not connected", self._not_connected_message
            )
        with self._lock:
            if self._client is not None and self._client[0] == token:
                return self._client[1]
        client = self._factory(token)
        with self._lock:
            self._client = (token, client)
        return client

    def get_file(self, file_id: str, fields: str) -> dict[str, Any]:
        return self._inner().get_file(file_id, fields)

    def list_files(
        self, q: str, fields: str, page_size: int, page_token: str | None = None
    ) -> dict[str, Any]:
        return self._inner().list_files(q, fields, page_size, page_token)

    def export(self, file_id: str, mime_type: str) -> bytes:
        return self._inner().export(file_id, mime_type)

    def download(self, file_id: str, max_bytes: int) -> bytes:
        return self._inner().download(file_id, max_bytes)

    def create(
        self,
        metadata: dict[str, Any],
        content: bytes | None,
        content_mime: str | None,
        fields: str,
    ) -> dict[str, Any]:
        return self._inner().create(check_create_metadata(metadata), content, content_mime, fields)

    def update(
        self,
        file_id: str,
        metadata: dict[str, Any] | None,
        content: bytes | None,
        content_mime: str | None,
        fields: str,
    ) -> dict[str, Any]:
        return self._inner().update(
            file_id, check_update_metadata(metadata), content, content_mime, fields
        )


class RoutingDriveClient:
    """Sends each Drive call to the admin's client or to that person's own Drive.

    Tests that inject one Drive client keep using it for the admin and for API tokens.
    Any other actor resolves their own sign-in refresh token and builds a client with
    `bot_drive_factory`. A missing sign-in is the same error the dashboard already shows.
    """

    def __init__(
        self,
        admin_client: DriveClient,
        admin_email: str | None,
        token_for: Callable[[str], str | None],
        factory: Callable[[str], DriveClient],
    ):
        self._admin = admin_client
        self._admin_email = admin_email
        self._token_for = token_for
        self._factory = factory
        self._lock = threading.Lock()
        self._clients: dict[str, tuple[str, DriveClient]] = {}

    def invalidate(self, email: str | None = None) -> None:
        with self._lock:
            if email is None or email == self._admin_email:
                self._clients.clear()
            else:
                self._clients.pop(email, None)
        inner = getattr(self._admin, "invalidate", None)
        if (email is None or email == self._admin_email) and callable(inner):
            inner()

    def _client(self) -> DriveClient:
        from .auth import current_actor

        actor = current_actor.get()
        if not actor or actor == self._admin_email:
            return self._admin
        token = self._token_for(actor)
        if not token:
            raise BotNotConnectedError("the owner has not signed in", OWNER_NOT_SIGNED_IN)
        with self._lock:
            cached = self._clients.get(actor)
            if cached is not None and cached[0] == token:
                return cached[1]
        client = self._factory(token)
        with self._lock:
            self._clients[actor] = (token, client)
        return client

    def get_file(self, file_id: str, fields: str) -> dict[str, Any]:
        return self._client().get_file(file_id, fields)

    def list_files(
        self, q: str, fields: str, page_size: int, page_token: str | None = None
    ) -> dict[str, Any]:
        return self._client().list_files(q, fields, page_size, page_token)

    def export(self, file_id: str, mime_type: str) -> bytes:
        return self._client().export(file_id, mime_type)

    def download(self, file_id: str, max_bytes: int) -> bytes:
        return self._client().download(file_id, max_bytes)

    def create(
        self,
        metadata: dict[str, Any],
        content: bytes | None,
        content_mime: str | None,
        fields: str,
    ) -> dict[str, Any]:
        return self._client().create(metadata, content, content_mime, fields)

    def update(
        self,
        file_id: str,
        metadata: dict[str, Any] | None,
        content: bytes | None,
        content_mime: str | None,
        fields: str,
    ) -> dict[str, Any]:
        return self._client().update(file_id, metadata, content, content_mime, fields)
