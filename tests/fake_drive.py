"""In-memory Drive v3 stand-in that understands the subset of the `q` language we generate."""

import itertools
import re
from dataclasses import dataclass, field
from typing import Any

from scoped_drive_mcp.drive_client import FOLDER_MIME, DriveNotFoundError


@dataclass
class FakeFile:
    id: str
    name: str
    mime_type: str
    parents: list[str]
    content: bytes = b""
    trashed: bool = False

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

    def add(
        self,
        file_id: str,
        name: str,
        mime_type: str,
        parents: list[str],
        content: bytes = b"",
        trashed: bool = False,
    ) -> FakeFile:
        f = FakeFile(file_id, name, mime_type, list(parents), content, trashed)
        self.files[file_id] = f
        return f

    def _get(self, file_id: str) -> FakeFile:
        try:
            return self.files[file_id]
        except KeyError:
            raise DriveNotFoundError(file_id) from None

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
        matches = [f for f in self.files.values() if pred(f)]
        start = int(page_token or 0)
        size = min(page_size, self.page_size_cap)
        page = matches[start : start + size]
        resp: dict[str, Any] = {"files": [f.as_api(fields) for f in page]}
        if start + size < len(matches):
            resp["nextPageToken"] = str(start + size)
        return resp

    def export(self, file_id: str, mime_type: str) -> bytes:
        f = self._get(file_id)
        return f.content

    def download(self, file_id: str, max_bytes: int) -> bytes:
        return self._get(file_id).content[:max_bytes]

    def create(
        self, metadata: dict[str, Any], content: bytes | None, content_mime: str | None, fields: str
    ) -> dict[str, Any]:
        new_id = f"new-file-{next(self._ids):04d}"
        f = self.add(
            new_id,
            metadata["name"],
            metadata.get("mimeType", content_mime or ""),
            list(metadata.get("parents", [])),
            content or b"",
        )
        return f.as_api(fields)

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
        assert set(metadata) <= {"name", "trashed"}, f"unexpected metadata update {metadata}"
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
