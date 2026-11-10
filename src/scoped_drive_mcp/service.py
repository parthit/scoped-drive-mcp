"""Synchronous tool implementations. Every Drive access goes through the ScopeGuard first.

Shortcuts (application/vnd.google-apps.shortcut) are never followed: no code path reads
`shortcutDetails.targetId`, and a shortcut is not a folder, so it cannot be listed or used
as a create parent. Writes never send `parents` except the single, scope-checked parent
on create (see drive_client.check_create_metadata / check_update_metadata).
"""

import base64
import binascii
import posixpath
import re
from typing import Any

from .config import Settings
from .drive_client import (
    FOLDER_MIME,
    GOOGLE_APPS_PREFIX,
    SHORTCUT_MIME,
    DriveClient,
    DriveNotFoundError,
)
from .scope import (
    FileRef,
    InvalidInputError,
    OutOfScopeError,
    ScopeGuard,
    escape_query_value,
    validate_drive_id,
)

META_FIELDS = "id,name,mimeType,parents,size,createdTime,modifiedTime,webViewLink,trashed"
PUBLIC_META_KEYS = (
    "id",
    "name",
    "mimeType",
    "parents",
    "size",
    "createdTime",
    "modifiedTime",
    "webViewLink",
)

DOC_MIME = "application/vnd.google-apps.document"
SHEET_MIME = "application/vnd.google-apps.spreadsheet"
SLIDES_MIME = "application/vnd.google-apps.presentation"

EXPORT_FORMATS = {
    DOC_MIME: "text/plain",
    SHEET_MIME: "text/csv",
    SLIDES_MIME: "text/plain",
}

TEXT_MIME_TYPES = frozenset(
    {
        "application/json",
        "application/xml",
        "application/javascript",
        "application/x-javascript",
        "application/ecmascript",
        "application/x-yaml",
        "application/yaml",
        "application/toml",
        "application/x-sh",
        "application/x-python",
        "application/x-python-code",
        "application/sql",
        "application/csv",
        "application/rtf",
        "application/x-tex",
        "application/x-httpd-php",
        "application/graphql",
    }
)

TEXT_EXTENSIONS = frozenset(
    {
        ".txt",
        ".md",
        ".markdown",
        ".csv",
        ".tsv",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".log",
        ".xml",
        ".html",
        ".htm",
        ".css",
        ".js",
        ".ts",
        ".py",
        ".rb",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".c",
        ".h",
        ".cpp",
        ".hpp",
        ".sh",
        ".sql",
        ".tex",
        ".rst",
    }
)

_MIME_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$"
)
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

MAX_NAME_LEN = 255
MAX_QUERY_LEN = 200
MAX_TOP_LEVEL = 500
TOP_LEVEL_NOTE = (
    "These are the items the owner shared with you. Call list_folder with a folder's id to "
    "see inside it."
)


def public_meta(data: dict[str, Any]) -> dict[str, Any]:
    return {k: data[k] for k in PUBLIC_META_KEYS if k in data}


def is_text_like(mime_type: str, name: str = "") -> bool:
    mime = mime_type.lower().split(";")[0].strip()
    if mime.startswith("text/") or mime in TEXT_MIME_TYPES:
        return True
    if mime.endswith("+json") or mime.endswith("+xml"):
        return True
    if mime in ("", "application/octet-stream"):
        return posixpath.splitext(name.lower())[1] in TEXT_EXTENSIONS
    return False


def validate_name(value: Any, what: str = "name") -> str:
    if not isinstance(value, str):
        raise InvalidInputError(f"{what} must be a string")
    value = value.strip()
    if not value:
        raise InvalidInputError(f"{what} must not be empty")
    if len(value) > MAX_NAME_LEN:
        raise InvalidInputError(f"{what} must be at most {MAX_NAME_LEN} characters")
    if _CONTROL_CHARS.search(value):
        raise InvalidInputError(f"{what} must not contain control characters")
    return value


class DriveService:
    def __init__(self, drive: DriveClient, guard: ScopeGuard, settings: Settings):
        self.drive = drive
        self.guard = guard
        self.max_bytes = settings.max_bytes
        self.max_chars = settings.max_chars

    def _fetch_meta(self, file_id: str) -> dict[str, Any]:
        validate_drive_id(file_id)
        try:
            return self.drive.get_file(file_id, fields=META_FIELDS)
        except DriveNotFoundError:
            raise OutOfScopeError(file_id) from None

    def _get_in_scope(self, file_id: str, *, allow_root: bool = True) -> dict[str, Any]:
        """Fetch full metadata once and run the scope check on it."""
        meta = self._fetch_meta(file_id)
        self.guard.assert_in_scope(file_id, allow_root=allow_root, ref=FileRef.from_api(meta))
        return meta

    def peek_name(self, file_id: str) -> str | None:
        """The file's name if this sign-in can see it (for the approval page only)."""
        try:
            return str(self.drive.get_file(file_id, fields="id,name").get("name") or "") or None
        except Exception:
            return None

    def _public(self, meta: dict[str, Any], memo: dict[str, bool] | None = None) -> dict[str, Any]:
        """public_meta with `parents` cut down to in-scope folder ids (dropped if none)."""
        out = public_meta(meta)
        if "parents" not in out:
            return out
        memo = {} if memo is None else memo
        kept = []
        for parent_id in out["parents"] or []:
            parent_id = str(parent_id)
            if parent_id not in memo:
                memo[parent_id] = self.guard.parent_in_scope(parent_id)
            if memo[parent_id]:
                kept.append(parent_id)
        if kept:
            out["parents"] = kept
        else:
            del out["parents"]
        return out

    def _encode(self, content: str, what: str = "content") -> bytes:
        if not isinstance(content, str):
            raise InvalidInputError(f"{what} must be a string")
        data = content.encode("utf-8")
        if len(data) > self.max_bytes:
            raise InvalidInputError(f"{what} is larger than the {self.max_bytes}-byte limit")
        return data

    # ---- viewer tools ----------------------------------------------------

    def search_files(self, query: str, max_results: int = 10) -> dict[str, Any]:
        if not isinstance(query, str) or not query.strip():
            raise InvalidInputError("query must be a non-empty string")
        if len(query) > MAX_QUERY_LEN:
            raise InvalidInputError(f"query must be at most {MAX_QUERY_LEN} characters")
        max_results = max(1, min(int(max_results), 50))
        items = self.guard.search(query, max_results, fields=META_FIELDS)
        memo: dict[str, bool] = {}
        return {"files": [self._public(i, memo) for i in items], "count": len(items)}

    def list_top_level(self) -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        memo: dict[str, bool] = {}
        for file_id in list(self.guard.allowed())[:MAX_TOP_LEVEL]:
            try:
                meta = self.drive.get_file(file_id, fields=META_FIELDS)
            except DriveNotFoundError:
                continue
            if meta.get("trashed") or meta.get("id") != file_id:
                continue
            self.guard.remember(FileRef.from_api(meta))
            items.append(self._public(meta, memo))
        items.sort(key=lambda m: (m.get("mimeType") != FOLDER_MIME, str(m.get("name", "")).lower()))
        return {"folder": None, "files": items, "truncated": False, "note": TOP_LEVEL_NOTE}

    def list_folder(self, folder_id: str | None = None, max_results: int = 100) -> dict[str, Any]:
        if not folder_id:
            return self.list_top_level()
        meta = self._get_in_scope(folder_id)
        if meta.get("mimeType") != FOLDER_MIME:
            raise InvalidInputError("folder_id is not a folder")
        max_results = max(1, min(int(max_results), 500))
        q = f"'{escape_query_value(folder_id)}' in parents and trashed=false"
        items: list[dict[str, Any]] = []
        memo: dict[str, bool] = {folder_id: True}
        page_token: str | None = None
        while len(items) <= max_results:
            resp = self.drive.list_files(
                q, fields=META_FIELDS, page_size=min(max_results + 1, 200), page_token=page_token
            )
            for item in resp.get("files", []):
                ref = FileRef.from_api(item)
                if folder_id not in ref.parents or ref.trashed:
                    continue
                self.guard.remember(ref)
                items.append(self._public(item, memo))
            page_token = resp.get("nextPageToken")
            if not page_token:
                break
        truncated = len(items) > max_results or bool(page_token)
        return {
            "folder": self._public(meta, memo),
            "files": items[:max_results],
            "truncated": truncated,
        }

    def get_metadata(self, file_id: str) -> dict[str, Any]:
        return self._public(self._get_in_scope(file_id))

    def read_file(self, file_id: str) -> dict[str, Any]:
        meta = self._get_in_scope(file_id)
        mime = meta.get("mimeType", "")
        result: dict[str, Any] = {"file": self._public(meta), "content": None, "truncated": False}

        if mime == FOLDER_MIME:
            raise InvalidInputError("this is a folder; use list_folder")
        if mime == SHORTCUT_MIME:
            result["note"] = "shortcuts are not followed; ask the owner to share the target"
            return result

        if mime in EXPORT_FORMATS:
            export_mime = EXPORT_FORMATS[mime]
            data = self.drive.export(file_id, export_mime)
            result["exported_as"] = export_mime
        elif mime.startswith(GOOGLE_APPS_PREFIX):
            result["note"] = f"{mime} cannot be exported as text"
            return result
        elif is_text_like(mime, meta.get("name", "")):
            data = self.drive.download(file_id, self.max_bytes + 1)
        else:
            result["note"] = f"binary file ({mime or 'unknown type'}); content not returned"
            return result

        if len(data) > self.max_bytes:
            data = data[: self.max_bytes]
            result["truncated"] = True
        if b"\x00" in data[:8192]:
            result["note"] = "file looks binary; content not returned"
            return result
        text = data.decode("utf-8", errors="replace")
        if len(text) > self.max_chars:
            text = text[: self.max_chars]
            result["truncated"] = True
        result["content"] = text
        return result

    # ---- editor tools ----------------------------------------------------

    def _create(
        self,
        metadata: dict[str, Any],
        content: bytes | None,
        mime: str | None,
        parent_id: str | None,
    ) -> dict[str, Any]:
        if not parent_id:
            parent_id = self.guard.default_parent()
            if parent_id is None:
                raise InvalidInputError(
                    "parent_id is required; call list_folder to find a folder you may use"
                )
        parent = self.guard.assert_parent_in_scope(parent_id)
        metadata = {**metadata, "parents": [parent.id]}
        created = self.drive.create(metadata, content, mime, fields=META_FIELDS)
        ref = FileRef.from_api(created)
        if ref.is_folder:
            self.guard.remember(ref)
            self.guard.invalidate()
        return self._public(created, {parent.id: True})

    def create_folder(self, name: str, parent_id: str | None = None) -> dict[str, Any]:
        name = validate_name(name)
        return self._create({"name": name, "mimeType": FOLDER_MIME}, None, None, parent_id)

    def create_doc(
        self, title: str, content: str = "", parent_id: str | None = None
    ) -> dict[str, Any]:
        title = validate_name(title, "title")
        data = self._encode(content)
        return self._create({"name": title, "mimeType": DOC_MIME}, data, "text/plain", parent_id)

    def upload_file(
        self,
        name: str,
        mime_type: str,
        content_text: str | None = None,
        content_base64: str | None = None,
        parent_id: str | None = None,
    ) -> dict[str, Any]:
        name = validate_name(name)
        if not isinstance(mime_type, str) or not _MIME_RE.fullmatch(mime_type.strip()):
            raise InvalidInputError("mime_type must look like type/subtype")
        mime_type = mime_type.strip()
        if mime_type.lower().startswith(GOOGLE_APPS_PREFIX):
            raise InvalidInputError("use create_doc or create_folder for Google Workspace types")
        if (content_text is None) == (content_base64 is None):
            raise InvalidInputError("provide exactly one of content_text or content_base64")
        if content_text is not None:
            data = self._encode(content_text, "content_text")
        else:
            if not isinstance(content_base64, str):
                raise InvalidInputError("content_base64 must be a string")
            if len(content_base64) > (self.max_bytes * 4) // 3 + 8:
                raise InvalidInputError(f"content is larger than the {self.max_bytes}-byte limit")
            try:
                data = base64.b64decode(content_base64, validate=True)
            except (binascii.Error, ValueError):
                raise InvalidInputError("content_base64 is not valid base64") from None
            if len(data) > self.max_bytes:
                raise InvalidInputError(f"content is larger than the {self.max_bytes}-byte limit")
        return self._create({"name": name, "mimeType": mime_type}, data, mime_type, parent_id)

    def update_file_content(self, file_id: str, content: str) -> dict[str, Any]:
        meta = self._fetch_meta(file_id)
        mime = meta.get("mimeType", "")
        # A directly granted file may be edited; a granted folder is protected like rename/trash.
        self.guard.assert_in_scope(
            file_id, allow_root=mime != FOLDER_MIME, ref=FileRef.from_api(meta)
        )
        data = self._encode(content)
        if mime == DOC_MIME:
            upload_mime = "text/plain"
        elif mime.startswith(GOOGLE_APPS_PREFIX):
            raise InvalidInputError("only Google Docs and text files can be updated")
        elif is_text_like(mime, meta.get("name", "")):
            upload_mime = mime or "text/plain"
        else:
            raise InvalidInputError("binary files cannot be updated with text content")
        updated = self.drive.update(file_id, None, data, upload_mime, fields=META_FIELDS)
        return self._public(updated)

    def rename_file(self, file_id: str, new_name: str) -> dict[str, Any]:
        new_name = validate_name(new_name, "new_name")
        self._get_in_scope(file_id, allow_root=False)
        updated = self.drive.update(file_id, {"name": new_name}, None, None, fields=META_FIELDS)
        return self._public(updated)

    # ---- admin tools -----------------------------------------------------

    def trash_file(self, file_id: str) -> dict[str, Any]:
        self._get_in_scope(file_id, allow_root=False)
        updated = self.drive.update(file_id, {"trashed": True}, None, None, fields=META_FIELDS)
        self.guard.invalidate(file_id)
        return {**self._public(updated), "trashed": bool(updated.get("trashed", True))}
