"""In-memory Drive v3 stand-in that understands the subset of the `q` language we generate.

A FakeDrive with `viewer=None` sees every file (the phase-1 tests use that). `as_user(email)`
returns a view that shares the same files but only sees what that account could see in
Drive: files it owns, files under a folder it owns, and files shared with it directly or
through an ancestor folder (sharing is inherited).
"""

import itertools
import re
from dataclasses import dataclass, field
from typing import Any

from scoped_drive_mcp.drive_client import (
    FOLDER_MIME,
    UPDATE_METADATA_KEYS,
    DriveNotFoundError,
    check_create_metadata,
)


class FakeForbiddenError(Exception):
    """Stands in for a Drive 403 (e.g. sharing an item you do not own)."""


@dataclass
class FakeFile:
    id: str
    name: str
    mime_type: str
    parents: list[str]
    content: bytes = b""
    trashed: bool = False
    owner: str | None = None
    permissions: list[dict[str, str]] = field(default_factory=list)
    shortcut_target: str | None = None

    def as_api(self, fields: str) -> dict[str, Any]:
        full = {
            "id": self.id,
            "name": self.name,
            "mimeType": self.mime_type,
            "parents": list(self.parents),
            "trashed": self.trashed,
            "size": str(len(self.content)),
            "createdTime": "2026-01-01T00:00:00Z",
            "modifiedTime": "2026-01-01T00:00:00Z",
            "webViewLink": f"https://drive.google.com/file/d/{self.id}/view",
        }
        if self.mime_type == FOLDER_MIME:
            full.pop("size")
        if self.shortcut_target is not None:
            full["shortcutDetails"] = {"targetId": self.shortcut_target}
        wanted = {f.strip() for f in fields.split(",")}
        return {k: v for k, v in full.items() if k in wanted}


_TOKEN_RE = re.compile(r"\s*(?:(?P<str>'(?:\\.|[^'\\])*')|(?P<op>!=|=|\(|\))|(?P<word>[A-Za-z]+))")


def _unescape(raw: str) -> str:
    body = raw[1:-1]
    return re.sub(r"\\(.)", r"\1", body)


def tokenize(q: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    q = q.rstrip()
    while pos < len(q):
        m = _TOKEN_RE.match(q, pos)
        if not m:
            raise ValueError(f"cannot tokenize query at {q[pos : pos + 20]!r}")
        pos = m.end()
        kind = m.lastgroup
        assert kind is not None
        tokens.append((kind, m.group(kind)))
    return tokens


class _Parser:
    """expr := term ('or' term)* ; term := factor ('and' factor)* ;
    factor := '(' expr ')' | STRING 'in' 'parents' | FIELD op VALUE | FIELD 'contains' STRING"""

    def __init__(self, tokens: list[tuple[str, str]]):
        self.tokens = tokens
        self.i = 0

    def peek(self) -> tuple[str, str] | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def take(self) -> tuple[str, str]:
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def expect(self, value: str) -> None:
        tok = self.take()
        if tok[1] != value:
            raise ValueError(f"expected {value!r}, got {tok[1]!r}")

    def parse(self):
        pred = self.expr()
        if self.peek() is not None:
            raise ValueError(f"trailing tokens: {self.tokens[self.i :]}")
        return pred

    def expr(self):
        preds = [self.term()]
        while self.peek() == ("word", "or"):
            self.take()
            preds.append(self.term())
        return lambda f, ps=preds: any(p(f) for p in ps)

    def term(self):
        preds = [self.factor()]
        while self.peek() == ("word", "and"):
            self.take()
            preds.append(self.factor())
        return lambda f, ps=preds: all(p(f) for p in ps)

    def factor(self):
        kind, value = self.take()
        if value == "(":
            pred = self.expr()
            self.expect(")")
            return pred
        if kind == "str":
            literal = _unescape(value)
            self.expect("in")
            self.expect("parents")
            return lambda f: literal in f.parents
        if kind == "word":
            fld = value
            op_kind, op = self.take()
            if op == "contains":
                literal = _unescape(self.take()[1])
                if fld == "name":
                    return lambda f: literal.lower() in f.name.lower()
                if fld == "fullText":
                    return lambda f: (
                        literal.lower() in f.name.lower()
                        or literal.lower() in f.content.decode("utf-8", "replace").lower()
                    )
                raise ValueError(f"unsupported contains field {fld}")
            if op in ("=", "!="):
                vkind, raw = self.take()
                target: Any = _unescape(raw) if vkind == "str" else raw == "true"
                getter = {"trashed": lambda f: f.trashed, "mimeType": lambda f: f.mime_type}[fld]
                if op == "=":
                    return lambda f: getter(f) == target
                return lambda f: getter(f) != target
        raise ValueError(f"unexpected token {value!r}")


def compile_query(q: str):
    return _Parser(tokenize(q)).parse()


@dataclass
class FakeDrive:
    files: dict[str, FakeFile] = field(default_factory=dict)
    queries: list[str] = field(default_factory=list)
    get_calls: list[str] = field(default_factory=list)
    ignore_parent_filter: bool = False
    page_size_cap: int = 1000
    _ids: Any = field(default_factory=lambda: itertools.count(1))
    viewer: str | None = None
    roots: dict[str, str] = field(default_factory=dict)
    content_calls: list[str] = field(default_factory=list)
    permission_calls: list[tuple] = field(default_factory=list)
    default_owner: str | None = None

    def add(
        self,
        file_id: str,
        name: str,
        mime_type: str,
        parents: list[str],
        content: bytes = b"",
        trashed: bool = False,
        *,
        owner: str | None = None,
        shortcut_target: str | None = None,
    ) -> FakeFile:
        f = FakeFile(
            file_id,
            name,
            mime_type,
            list(parents),
            content,
            trashed,
            owner=owner if owner is not None else self.default_owner,
            shortcut_target=shortcut_target,
        )
        self.files[file_id] = f
        return f

    def as_user(self, email: str) -> "FakeDrive":
        return FakeDrive(
            files=self.files,
            viewer=email,
            roots=self.roots,
            _ids=self._ids,
            default_owner=self.default_owner,
        )

    def share(self, file_id: str, email: str, role: str = "writer") -> str:
        pid = f"perm-{next(self._ids):04d}"
        self.files[file_id].permissions.append({"id": pid, "emailAddress": email, "role": role})
        return pid

    def visible(self, f: FakeFile) -> bool:
        if self.viewer is None:
            return True
        seen: set[str] = set()
        frontier = [f]
        while frontier:
            node = frontier.pop()
            if node.id in seen:
                continue
            seen.add(node.id)
            if node.owner == self.viewer:
                return True
            if any(p["emailAddress"] == self.viewer for p in node.permissions):
                return True
            frontier.extend(self.files[p] for p in node.parents if p in self.files)
        return False

    def _get(self, file_id: str) -> FakeFile:
        if file_id == "root" and self.viewer in self.roots:
            file_id = self.roots[self.viewer]
        f = self.files.get(file_id)
        if f is None or not self.visible(f):
            raise DriveNotFoundError(file_id)
        return f

    def get_file(self, file_id: str, fields: str) -> dict[str, Any]:
        self.get_calls.append(file_id)
        return self._get(file_id).as_api(fields)

    def list_files(
        self, q: str, fields: str, page_size: int, page_token: str | None = None
    ) -> dict[str, Any]:
        self.queries.append(q)
        if self.ignore_parent_filter:
            pred = compile_query(re.sub(r" and \((?:'[^']*' in parents(?: or )?)+\)", "", q))
        else:
            pred = compile_query(q)
        matches = [f for f in self.files.values() if pred(f) and self.visible(f)]
        start = int(page_token or 0)
        size = min(page_size, self.page_size_cap)
        page = matches[start : start + size]
        resp: dict[str, Any] = {"files": [f.as_api(fields) for f in page]}
        if start + size < len(matches):
            resp["nextPageToken"] = str(start + size)
        return resp

    def export(self, file_id: str, mime_type: str) -> bytes:
        self.content_calls.append(file_id)
        f = self._get(file_id)
        return f.content

    def download(self, file_id: str, max_bytes: int) -> bytes:
        self.content_calls.append(file_id)
        return self._get(file_id).content[:max_bytes]

    def create(
        self, metadata: dict[str, Any], content: bytes | None, content_mime: str | None, fields: str
    ) -> dict[str, Any]:
        check_create_metadata(metadata)
        for parent in metadata["parents"]:
            self._get(parent)
        new_id = f"new-file-{next(self._ids):04d}"
        f = self.add(
            new_id,
            metadata["name"],
            metadata.get("mimeType", content_mime or ""),
            list(metadata.get("parents", [])),
            content or b"",
            owner=self.viewer,
        )
        return f.as_api(fields)

    def create_permission(self, file_id: str, email: str, role: str) -> str:
        f = self._get(file_id)
        if self.viewer is not None and f.owner != self.viewer:
            raise FakeForbiddenError(file_id)
        self.permission_calls.append(("create", file_id, email, role))
        return self.share(file_id, email, role)

    def delete_permission(self, file_id: str, permission_id: str) -> None:
        f = self._get(file_id)
        self.permission_calls.append(("delete", file_id, permission_id))
        before = len(f.permissions)
        f.permissions = [p for p in f.permissions if p["id"] != permission_id]
        if len(f.permissions) == before:
            raise DriveNotFoundError(permission_id)

    def update(
        self,
        file_id: str,
        metadata: dict[str, Any] | None,
        content: bytes | None,
        content_mime: str | None,
        fields: str,
    ) -> dict[str, Any]:
        f = self._get(file_id)
        metadata = metadata or {}
        assert set(metadata) <= UPDATE_METADATA_KEYS, f"unexpected metadata update {metadata}"
        if "name" in metadata:
            f.name = metadata["name"]
        if metadata.get("trashed"):
            f.trashed = True
        if content is not None:
            f.content = content
        return f.as_api(fields)

    # test helper
    def move(self, file_id: str, new_parents: list[str]) -> None:
        self.files[file_id].parents = list(new_parents)
