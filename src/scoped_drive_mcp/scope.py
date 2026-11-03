"""Scope guard: every file the server touches must be allowlisted or live under an
allowlisted folder.

The allowlist is what the owner ticked in the dashboard, plus ROOT_FOLDER_ID if set.

Rules:
- A file is in scope if its own id is allowlisted, or if walking up its `parents`
  chain (with the bot's credentials) reaches an allowlisted id. If the walk stops
  because a parent is missing or not visible to the bot, the file is out of scope.
- Multiple parents: in scope if ANY parent chain reaches an allowlisted id. The bot
  can only see a file at all if the owner shared it (directly or through a folder),
  so this does not widen what Google already allows.
- The target file itself is always fetched fresh; only ancestor folders are cached
  (for `ttl` seconds), so a folder moved out of the tree drops out of scope once its
  cache entry expires. The allowlist is re-read every `allowlist_ttl` seconds
  (default 2), so a revoke takes effect within that time on every instance.
- Trashed files and files Drive reports as missing are treated as out of scope.
- The walk is breadth-first over all parents, tracks visited IDs (cycles) and is
  capped in depth and total lookups.
- Allowlisted items are in scope for reads and (if folders) as parents for creates,
  but callers pass `allow_root=False` for rename/trash so Grok cannot rename or
  trash something the owner granted.
- Shortcuts are ordinary files here: the guard never follows `shortcutDetails`.
- Search never forwards user-written Drive queries: the user text is escaped and
  placed into a fixed template restricted to folders in scope, and every result is
  re-checked with `assert_in_scope`.
"""

import re
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .drive_client import FOLDER_MIME, DriveClient, DriveNotFoundError

_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,200}$")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

REF_FIELDS = "id,parents,trashed,mimeType"
NOT_IN_SCOPE = "file not found or not shared with the assistant"
PROTECTED = "items the owner granted directly cannot be renamed or trashed"


class ForbiddenError(Exception):
    """The request is not allowed (e.g. modifying an allowlisted item itself)."""


class OutOfScopeError(ForbiddenError):
    """The file is outside the allowlist. The owner can approve access to it."""

    def __init__(self, file_id: str, message: str = NOT_IN_SCOPE):
        super().__init__(message)
        self.file_id = file_id


class InvalidInputError(ValueError):
    """A tool argument is malformed."""


def validate_drive_id(value: Any, what: str = "file_id") -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise InvalidInputError(f"{what} must be a Google Drive ID (letters, digits, - and _)")
    return value


def escape_query_value(value: str) -> str:
    """Escape a string for use inside single quotes in a Drive `q` expression."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def clean_search_text(text: str) -> str:
    return escape_query_value(_CONTROL_CHARS.sub(" ", text).strip())


def parents_clause(folder_ids: Iterable[str]) -> str:
    return " or ".join(f"'{escape_query_value(fid)}' in parents" for fid in folder_ids)


def chunked(items: list[str], size: int) -> list[list[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


@dataclass(frozen=True)
class FileRef:
    id: str
    parents: tuple[str, ...]
    trashed: bool
    mime_type: str

    @property
    def is_folder(self) -> bool:
        return self.mime_type == FOLDER_MIME

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "FileRef":
        return cls(
            id=str(data["id"]),
            parents=tuple(str(p) for p in data.get("parents") or ()),
            trashed=bool(data.get("trashed", False)),
            mime_type=str(data.get("mimeType", "")),
        )


AllowlistSource = Callable[[], Mapping[str, str]]


class ScopeGuard:
    def __init__(
        self,
        drive: DriveClient,
        root_folder_id: str | None = None,
        ttl: float = 60.0,
        *,
        allowlist: AllowlistSource | None = None,
        allowlist_ttl: float = 2.0,
        clock: Callable[[], float] = time.monotonic,
        max_depth: int = 64,
        max_lookups: int = 256,
        max_folders: int = 5000,
        parents_chunk_size: int = 40,
        max_individual_files: int = 200,
    ):
        self.drive = drive
        self.root_id = root_folder_id
        self.ttl = ttl
        self.allowlist_source = allowlist
        self.allowlist_ttl = allowlist_ttl
        self._clock = clock
        self.max_depth = max_depth
        self.max_lookups = max_lookups
        self.max_folders = max_folders
        self.parents_chunk_size = parents_chunk_size
        self.max_individual_files = max_individual_files
        self._lock = threading.Lock()
        self._ancestors: dict[str, tuple[float, FileRef | None]] = {}
        self._folders: tuple[float, frozenset[str], tuple[str, ...]] | None = None
        self._allowed: tuple[float, dict[str, str]] | None = None

    # ---- allowlist -----------------------------------------------------

    def allowed(self) -> dict[str, str]:
        """Allowlisted id -> mime type (ROOT_FOLDER_ID included), cached for `allowlist_ttl`."""
        now = self._clock()
        with self._lock:
            if self._allowed is not None and self._allowed[0] > now:
                return self._allowed[1]
        items: dict[str, str] = {}
        if self.allowlist_source is not None:
            items.update(self.allowlist_source())
        if self.root_id:
            items[self.root_id] = FOLDER_MIME
        with self._lock:
            self._allowed = (now + self.allowlist_ttl, items)
        return items

    def invalidate_allowlist(self) -> None:
        with self._lock:
            self._allowed = None
            self._folders = None

    def default_parent(self) -> str | None:
        """Where creates go without a parent_id: ROOT_FOLDER_ID, else the only allowed folder."""
        if self.root_id:
            return self.root_id
        folders = [fid for fid, mime in self.allowed().items() if mime == FOLDER_MIME]
        return folders[0] if len(folders) == 1 else None

    # ---- lookups -------------------------------------------------------

    def _fetch(self, file_id: str) -> FileRef | None:
        try:
            data = self.drive.get_file(file_id, fields=REF_FIELDS)
        except DriveNotFoundError:
            return None
        return FileRef.from_api(data)

    def _ancestor(self, folder_id: str) -> FileRef | None:
        now = self._clock()
        with self._lock:
            cached = self._ancestors.get(folder_id)
            if cached is not None and cached[0] > now:
                return cached[1]
        ref = self._fetch(folder_id)
        with self._lock:
            self._ancestors[folder_id] = (now + self.ttl, ref)
        return ref

    def remember(self, ref: FileRef) -> None:
        """Seed the ancestor cache with a folder we just saw from Drive."""
        if ref.is_folder:
            with self._lock:
                self._ancestors[ref.id] = (self._clock() + self.ttl, ref)

    def invalidate(self, file_id: str | None = None) -> None:
        with self._lock:
            if file_id is not None:
                self._ancestors.pop(file_id, None)
            self._folders = None

    def resolve(self, file_id: str) -> FileRef:
        """Fetch a file fresh (never cached). Missing files are reported as out of scope."""
        validate_drive_id(file_id)
        ref = self._fetch(file_id)
        if ref is None:
            raise OutOfScopeError(file_id)
        return ref

    # ---- scope checks --------------------------------------------------

    def _reaches_allowed(self, ref: FileRef, allowed: Mapping[str, str]) -> bool:
        if ref.id in allowed:
            return True
        visited = {ref.id}
        frontier = list(ref.parents)
        lookups = 0
        for _depth in range(self.max_depth):
            if not frontier:
                return False
            next_frontier: list[str] = []
            for parent_id in frontier:
                if parent_id in allowed:
                    return True
                if parent_id in visited:
                    continue
                visited.add(parent_id)
                lookups += 1
                if lookups > self.max_lookups:
                    return False
                parent = self._ancestor(parent_id)
                if parent is None or parent.trashed or parent.id != parent_id:
                    continue
                next_frontier.extend(parent.parents)
            frontier = next_frontier
        return False

    def assert_in_scope(
        self, file_id: str, *, allow_root: bool = True, ref: FileRef | None = None
    ) -> FileRef:
        """Return the file's FileRef, or raise if it is outside the allowlist.

        `allow_root=False` additionally refuses allowlisted items themselves (used for
        rename/trash)."""
        validate_drive_id(file_id)
        if ref is None:
            ref = self.resolve(file_id)
        if ref.id != file_id or ref.trashed:
            raise OutOfScopeError(file_id)
        allowed = self.allowed()
        if ref.id in allowed:
            if not allow_root:
                raise ForbiddenError(PROTECTED)
            return ref
        if not self._reaches_allowed(ref, allowed):
            raise OutOfScopeError(file_id)
        return ref

    def is_in_scope(self, file_id: str, *, ref: FileRef | None = None) -> bool:
        try:
            self.assert_in_scope(file_id, ref=ref)
        except (ForbiddenError, InvalidInputError):
            return False
        return True

    def assert_parent_in_scope(self, parent_id: str) -> FileRef:
        """A create/upload target: must be an in-scope, non-trashed folder (allowlisted ok)."""
        validate_drive_id(parent_id, "parent_id")
        ref = self.assert_in_scope(parent_id, allow_root=True)
        if not ref.is_folder:
            raise InvalidInputError("parent_id must be a folder")
        return ref

    # ---- folder tree and search ---------------------------------------

    def folders_in_scope(self) -> tuple[str, ...]:
        """All non-trashed folders under allowlisted folders (included), BFS, cached for `ttl`."""
        allowed = self.allowed()
        roots = [fid for fid, mime in allowed.items() if mime in (FOLDER_MIME, "")]
        key = frozenset(roots)
        now = self._clock()
        with self._lock:
            if self._folders is not None and self._folders[0] > now and self._folders[1] == key:
                return self._folders[2]

        seen: dict[str, None] = dict.fromkeys(roots)
        level = list(roots)
        while level and len(seen) < self.max_folders:
            next_level: list[str] = []
            for group in chunked(level, self.parents_chunk_size):
                q = f"mimeType='{FOLDER_MIME}' and trashed=false and ({parents_clause(group)})"
                page_token: str | None = None
                while True:
                    resp = self.drive.list_files(
                        q, fields=REF_FIELDS, page_size=1000, page_token=page_token
                    )
                    for item in resp.get("files", []):
                        ref = FileRef.from_api(item)
                        if ref.id in seen or not ref.is_folder or ref.trashed:
                            continue
                        if not any(p in seen for p in ref.parents):
                            continue
                        seen[ref.id] = None
                        next_level.append(ref.id)
                        self.remember(ref)
                    page_token = resp.get("nextPageToken")
                    if not page_token or len(seen) >= self.max_folders:
                        break
            level = next_level

        folders = tuple(seen)
        with self._lock:
            self._folders = (now + self.ttl, key, folders)
        return folders

    def individual_files(self) -> set[str]:
        """Allowlisted ids that are not folders (searched separately)."""
        return {fid for fid, mime in self.allowed().items() if mime not in (FOLDER_MIME, "")}

    def search_queries(self, text: str) -> list[str]:
        """Build the fixed-template Drive queries for a user search string."""
        term = clean_search_text(text)
        match = f"(fullText contains '{term}' or name contains '{term}')"
        folders = list(self.folders_in_scope())
        return [
            f"trashed=false and {match} and ({parents_clause(group)})"
            for group in chunked(folders, self.parents_chunk_size)
        ]

    def individual_query(self, text: str) -> str:
        """Query for individually allowlisted files. Drive's `q` cannot filter by id, so
        this is not parent-restricted; results are only accepted if their id is one of
        the individually allowlisted files."""
        term = clean_search_text(text)
        return f"trashed=false and (fullText contains '{term}' or name contains '{term}')"

    def search(self, text: str, max_results: int, fields: str) -> list[dict[str, Any]]:
        all_fields = ",".join(dict.fromkeys([*REF_FIELDS.split(","), *fields.split(",")]))
        results: list[dict[str, Any]] = []
        seen: set[str] = set()

        def collect(q: str, accept: Callable[[FileRef], bool], max_pages: int) -> None:
            page_token: str | None = None
            pages = 0
            while len(results) < max_results and pages < max_pages:
                pages += 1
                resp = self.drive.list_files(
                    q, fields=all_fields, page_size=min(100, max_results), page_token=page_token
                )
                for item in resp.get("files", []):
                    if "id" not in item:
                        continue
                    ref = FileRef.from_api(item)
                    if ref.id in seen or not accept(ref):
                        continue
                    if not self.is_in_scope(ref.id, ref=ref):
                        continue
                    seen.add(ref.id)
                    results.append(item)
                    if len(results) >= max_results:
                        return
                page_token = resp.get("nextPageToken")
                if not page_token:
                    return

        for q in self.search_queries(text):
            collect(q, lambda _ref: True, max_pages=50)
            if len(results) >= max_results:
                return results

        individual = self.individual_files()
        if individual and len(individual) <= self.max_individual_files:
            collect(self.individual_query(text), lambda ref: ref.id in individual, max_pages=5)
        return results
