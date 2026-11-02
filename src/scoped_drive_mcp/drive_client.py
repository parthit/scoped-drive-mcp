"""Google credentials and a thin Drive v3 wrapper.

The rest of the server only talks to the `DriveClient` protocol, so tests can
swap in an in-memory fake. The wrapper deliberately exposes no way to change
parents, permissions or to permanently delete anything.
"""

import io
import threading
from typing import Any, Protocol

from .config import Settings

DRIVE_SCOPE = "https://www.googleapis.com/auth/drive"
TOKEN_URI = "https://oauth2.googleapis.com/token"  # noqa: S105 - public endpoint, not a secret

FOLDER_MIME = "application/vnd.google-apps.folder"
SHORTCUT_MIME = "application/vnd.google-apps.shortcut"
GOOGLE_APPS_PREFIX = "application/vnd.google-apps."


class DriveNotFoundError(Exception):
    """The file does not exist or the bot identity cannot see it."""


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


class CredentialsProvider(Protocol):
    def __call__(self, settings: Settings) -> Any: ...


def _oauth_bot_credentials(settings: Settings) -> Any:
    from google.oauth2.credentials import Credentials

    assert settings.google_oauth_client_id is not None
    assert settings.google_oauth_client_secret is not None
    assert settings.google_oauth_refresh_token is not None
    return Credentials(
        token=None,
        refresh_token=settings.google_oauth_refresh_token.get_secret_value(),
        client_id=settings.google_oauth_client_id.get_secret_value(),
        client_secret=settings.google_oauth_client_secret.get_secret_value(),
        token_uri=TOKEN_URI,
        scopes=[DRIVE_SCOPE],
    )


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
                body=metadata,
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
                body=metadata or {},
                media_body=self._media(content, content_mime),
                fields=fields,
                supportsAllDrives=True,
            )
        )
