"""What other people share with you, as one browsable tree per source.

`external.py` decides *whether* a guest may read an item. This module turns those
decisions into something a person can click through on the dashboard's "Shared with me"
page: people, then the sources each person shares from, then folders and items.

A *source* is one kind of thing a person can share. Google Drive is the first. Every source
offers the same small read-only surface, so the dashboard does not care which one it is
showing:

* `shared_roots(caller, owner)`: the top-level items `owner` shares, from the stored list
  only (no provider call), for the overview page.
* `list(caller, owner, container_id)`: one level of the tree. `None` is the top.
* `open(caller, owner, item_id)`: an item's details and a text preview when there is one.
* `download(caller, owner, item_id)`: size-capped bytes, when the type has any.
* `search(caller, owner, query, limit)`: items inside the share whose name or text matches.

A new source (a mail label, a calendar, a notes workspace) implements `SharedSource` and is
added to `SharedWithMe`. It must enforce the same rules as Drive on every call: the caller
and owner have an active pairing, the item is on the owner's shared list or inside a
container on it, and nothing here writes.

Containers nest to any depth. A listing carries `path`, the containers from the shared
item down to the one being shown, so the page can draw breadcrumbs without ever naming a
folder that sits above what the owner shared.
"""

import base64
import binascii
import builtins
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from .drive_client import FOLDER_MIME, GOOGLE_APPS_PREFIX, SHORTCUT_MIME
from .external import (
    SKIPPABLE_IN_SEARCH,
    ExternalShares,
    SharedAccessError,
    clean_query,
    guest_of,
    normalize_email,
)
from .scope import ForbiddenError, OutOfScopeError
from .service import EXPORT_FORMATS

# Google Docs, Sheets and Slides have no file bytes. "Download" on the dashboard gives the
# same export read_shared_file returns (text for Docs and Slides, CSV for Sheets).
EXPORT_EXTENSIONS = {"text/plain": ".txt", "text/csv": ".csv"}

# How many containers above the current one the breadcrumb walk may fetch.
MAX_PATH_DEPTH = 20
# Items shown per folder on the page. Drive folders larger than this say "truncated".
LIST_LIMIT = 200
# Hits per person and source on the search page.
SEARCH_LIMIT = 25
# Dashboard reads are recorded on the owner's activity log with this marker, so the owner
# can tell their friend's own browsing apart from that friend's assistant.
VIA_DASHBOARD = "dashboard"


@dataclass(frozen=True)
class SharedNode:
    id: str
    name: str
    mime_type: str = ""
    is_container: bool = False
    modified: str | None = None
    size: int | None = None
    kind: str | None = None
    """A label for the type, for sources whose `mime_type` is not a real MIME type."""
    can_download: bool = False


@dataclass(frozen=True)
class SharedListing:
    container: SharedNode | None
    """The container being shown, or None at the top of what the owner shares."""
    path: list[SharedNode]
    """From the shared item down to `container`, inclusive. Empty at the top."""
    items: list[SharedNode]
    truncated: bool = False


@dataclass(frozen=True)
class SharedDocument:
    node: SharedNode
    path: list[SharedNode]
    """Containers above the item, inside the share only."""
    text: str | None
    note: str | None
    truncated: bool
    downloadable: bool
    download_label: str = "Download"


@dataclass(frozen=True)
class SharedHit:
    node: SharedNode
    path: list[SharedNode]
    """Containers above the hit, inside the share only. Empty for a shared item itself."""


@dataclass(frozen=True)
class SharedDownload:
    filename: str
    data: bytes
    truncated: bool


class SharedSource(Protocol):
    key: str
    """URL-safe id. Matches the `connections.py` key for the same service."""
    name: str
    container_noun: str
    item_noun: str

    def shared_roots(self, caller: str, owner: str) -> list[SharedNode]: ...

    def list(self, caller: str, owner: str, container_id: str | None) -> SharedListing: ...

    def open(self, caller: str, owner: str, item_id: str) -> SharedDocument: ...

    def download(self, caller: str, owner: str, item_id: str) -> SharedDownload: ...

    def search(
        self, caller: str, owner: str, query: str, limit: int
    ) -> builtins.list[SharedHit]: ...


@dataclass(frozen=True)
class SourceShares:
    source: SharedSource
    roots: list[SharedNode]


@dataclass(frozen=True)
class PersonShares:
    owner: str
    sources: list[SourceShares] = field(default_factory=list)

    @property
    def item_count(self) -> int:
        return sum(len(s.roots) for s in self.sources)


@dataclass(frozen=True)
class SearchGroup:
    owner: str
    source: SharedSource
    hits: list[SharedHit]


@dataclass(frozen=True)
class SearchResults:
    query: str
    groups: list[SearchGroup]
    unavailable: list[str]
    """People whose sign-in could not be used right now. Their items were not searched."""

    @property
    def count(self) -> int:
        return sum(len(g.hits) for g in self.groups)


class SharedWithMe:
    """Every source, and who shares what with the caller across all of them."""

    def __init__(self, sources: Sequence[SharedSource], active_peers: Callable[[str], list[str]]):
        self._sources = {s.key: s for s in sources}
        self.active_peers = active_peers

    @property
    def sources(self) -> list[SharedSource]:
        return list(self._sources.values())

    def get(self, key: str | None) -> SharedSource | None:
        return self._sources.get(key or "")

    def overview(self, caller: str) -> list[PersonShares]:
        """People paired with the caller who share something, newest pairing order kept."""
        you = normalize_email(caller)
        people: list[PersonShares] = []
        for peer in self.active_peers(you):
            groups = []
            for source in self._sources.values():
                roots = source.shared_roots(you, peer)
                if roots:
                    groups.append(SourceShares(source, roots))
            if groups:
                people.append(PersonShares(peer, groups))
        return people

    def search(self, caller: str, query: str, limit: int = SEARCH_LIMIT) -> SearchResults:
        """Search every source of every paired person. Each (person, source) is its own
        guest call, so a hit can only come from that person's shared list. A person whose
        sign-in is unavailable is skipped and reported; other errors are raised."""
        text = clean_query(query)
        you = normalize_email(caller)
        groups: list[SearchGroup] = []
        unavailable: list[str] = []
        for peer in self.active_peers(you):
            for source in self._sources.values():
                if not source.shared_roots(you, peer):
                    continue
                try:
                    hits = source.search(you, peer, text, limit)
                except SharedAccessError as exc:
                    # One owner who is down, or whose pairing just ended, is skipped.
                    if exc.code not in SKIPPABLE_IN_SEARCH:
                        raise
                    if exc.code == "owner_unavailable" and peer not in unavailable:
                        unavailable.append(peer)
                    continue
                if hits:
                    groups.append(SearchGroup(peer, source, hits))
        return SearchResults(text, groups, unavailable)


# ---- Google Drive ------------------------------------------------------------


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def drive_node(meta: dict[str, Any]) -> SharedNode:
    mime = str(meta.get("mimeType") or meta.get("mime_type") or "")
    return SharedNode(
        id=str(meta["id"]),
        name=str(meta.get("name") or ""),
        mime_type=mime,
        is_container=mime == FOLDER_MIME,
        modified=meta.get("modifiedTime"),
        size=_int(meta.get("size")),
        can_download=_can_download(mime),
    )


def _sorted(nodes: list[SharedNode]) -> list[SharedNode]:
    return sorted(nodes, key=lambda n: (not n.is_container, n.name.lower()))


def _downloadable(mime: str) -> bool:
    """The item has file bytes of its own."""
    return mime not in (FOLDER_MIME, SHORTCUT_MIME) and not mime.startswith(GOOGLE_APPS_PREFIX)


def _export_extension(mime: str) -> str | None:
    """`.txt` or `.csv` for a Google file the dashboard downloads as an export."""
    export = EXPORT_FORMATS.get(mime)
    return EXPORT_EXTENSIONS.get(export) if export else None


def _can_download(mime: str) -> bool:
    return _downloadable(mime) or _export_extension(mime) is not None


def _download_label(mime: str) -> str:
    extension = _export_extension(mime)
    return f"Download as {extension}" if extension else "Download"


def _person_note(result: dict[str, Any], mime: str, owner: str) -> str | None:
    """DriveService notes are written for an assistant (they name tools). Say it for a person."""
    if mime == SHORTCUT_MIME:
        return f"This is a shortcut. Shortcuts are not followed; ask {owner} to share the original."
    if result.get("content") is not None:
        if result.get("truncated"):
            return "This preview shows only the first part of the file. Download it for the rest."
        return None
    if mime.startswith(GOOGLE_APPS_PREFIX):
        return "This Google file type has no text preview."
    if _downloadable(mime):
        return "There is no text preview for this file type. Download it to open it."
    return "There is no preview for this item."


class DriveSharedSource:
    key = "google_drive"
    name = "Google Drive"
    container_noun = "folder"
    item_noun = "file"

    def __init__(self, shares: ExternalShares):
        self.shares = shares

    def shared_roots(self, caller: str, owner: str) -> list[SharedNode]:
        you, them = normalize_email(caller), normalize_email(owner)
        if you == them or not self.shares.is_linked(you, them):
            return []
        with guest_of(them, you):
            entries = self.shares.allowlist.entries_for(you)
        return _sorted(
            [
                SharedNode(
                    id=e.id,
                    name=e.name,
                    mime_type=e.mime_type,
                    is_container=e.mime_type == FOLDER_MIME,
                    can_download=_can_download(e.mime_type),
                )
                for e in entries.values()
            ]
        )

    def _path(
        self,
        start: dict[str, Any],
        include_start: bool,
        memo: dict[str, dict[str, Any] | None] | None = None,
    ) -> list[SharedNode]:
        """Walk up from `start` while the parent is inside the share. Runs as the owner,
        inside a guest call. `_public` already dropped parents outside the share, so a
        folder above the shared item is never fetched or named. `memo` shares folder
        lookups between calls (search results often sit in the same folders)."""
        service = self.shares.service
        memo = {} if memo is None else memo
        chain: list[SharedNode] = [drive_node(start)] if include_start else []
        seen = {str(start["id"])}
        node = start
        while len(chain) < MAX_PATH_DEPTH:
            parents = node.get("parents") or []
            if not parents:
                break
            parent_id = str(parents[0])
            if parent_id in seen:
                break
            seen.add(parent_id)
            if parent_id not in memo:
                try:
                    memo[parent_id] = service.get_metadata(parent_id)
                except (OutOfScopeError, ForbiddenError):
                    memo[parent_id] = None
            parent = memo[parent_id]
            if parent is None:
                break
            node = parent
            chain.insert(0, drive_node(node))
        return chain

    def list(self, caller: str, owner: str, container_id: str | None) -> SharedListing:
        def run() -> SharedListing:
            service = self.shares.service
            if not container_id:
                top = service.list_top_level()
                items = [drive_node(m) for m in top.get("files", [])]
                return SharedListing(None, [], _sorted(items), bool(top.get("truncated")))
            res = service.list_folder(container_id, LIST_LIMIT)
            folder = res["folder"]
            items = [drive_node(m) for m in res.get("files", [])]
            return SharedListing(
                drive_node(folder),
                self._path(folder, include_start=True),
                _sorted(items),
                bool(res.get("truncated")),
            )

        return self.shares.guest_call(
            caller, owner, "list_shared_folder", container_id, run, via=VIA_DASHBOARD
        )

    def open(self, caller: str, owner: str, item_id: str) -> SharedDocument:
        them = normalize_email(owner)

        def run() -> SharedDocument:
            service = self.shares.service
            meta = service.get_metadata(item_id)
            mime = str(meta.get("mimeType") or "")
            if mime == FOLDER_MIME:
                path = self._path(meta, include_start=False)
                return SharedDocument(drive_node(meta), path, None, None, False, False)
            result = service.read_file(item_id)
            content = result.get("content")
            return SharedDocument(
                node=drive_node(result.get("file") or meta),
                path=self._path(meta, include_start=False),
                text=content if isinstance(content, str) else None,
                note=_person_note(result, mime, them),
                truncated=bool(result.get("truncated")),
                downloadable=_can_download(mime),
                download_label=_download_label(mime),
            )

        return self.shares.guest_call(
            caller, owner, "read_shared_file", item_id, run, via=VIA_DASHBOARD
        )

    def download(self, caller: str, owner: str, item_id: str) -> SharedDownload:
        def run() -> SharedDownload:
            service = self.shares.service
            result = service.download_file(item_id)
            raw = result.get("content_base64")
            meta = result.get("file") or {}
            extension = _export_extension(str(meta.get("mimeType") or ""))
            if raw is None and extension is not None:
                return self._export(item_id, meta, extension)
            if raw is None:
                raise SharedAccessError(
                    "no_bytes", "This item has no file to download. Open it to read it instead."
                )
            try:
                data = base64.b64decode(raw, validate=True)
            except (binascii.Error, ValueError):
                raise SharedAccessError("no_bytes", "The download could not be read.") from None
            name = str((result.get("file") or {}).get("name") or "download")
            return SharedDownload(name, data, bool(result.get("truncated")))

        return self.shares.guest_call(
            caller, owner, "download_shared_file", item_id, run, via=VIA_DASHBOARD
        )

    def _export(self, item_id: str, meta: dict[str, Any], extension: str) -> SharedDownload:
        """A Google Doc, Sheet or Slides file, exported exactly as read_shared_file reads it
        (same size caps). Runs inside the caller's guest call."""
        result = self.shares.service.read_file(item_id)
        content = result.get("content")
        if not isinstance(content, str):
            raise SharedAccessError(
                "no_bytes", "This file could not be exported. Open it to read it instead."
            )
        name = str(meta.get("name") or "download")
        if not name.lower().endswith(extension):
            name += extension
        return SharedDownload(name, content.encode("utf-8"), bool(result.get("truncated")))

    def search(self, caller: str, owner: str, query: str, limit: int) -> builtins.list[SharedHit]:
        """Names and full text, plus shared folders by name, run as the owner's guest."""
        text = clean_query(query)

        def run() -> builtins.list[SharedHit]:
            found = self.shares.search_as_owner(text, max(1, min(limit, 50)))
            memo: dict[str, dict[str, Any] | None] = {}
            hits = [
                SharedHit(drive_node(meta), self._path(meta, include_start=False, memo=memo))
                for meta in found
            ]
            return sorted(hits, key=lambda h: (not h.node.is_container, h.node.name.lower()))

        return self.shares.guest_call(
            caller, owner, "search_shared_files", None, run, via=VIA_DASHBOARD
        )
