"""Shortcuts are never followed, and no write path can set or change `parents`."""

from typing import Any

import pytest

from scoped_drive_mcp.drive_client import (
    GoogleDriveClient,
    GoogleOwnerDriveClient,
    LazyBotDriveClient,
    check_update_metadata,
)
from scoped_drive_mcp.scope import InvalidInputError, OutOfScopeError
from scoped_drive_mcp.service import DriveService
from tests.conftest import ROOT

# ---- shortcuts --------------------------------------------------------------


def test_shortcut_to_outside_file_is_not_followed(drive, service: DriveService) -> None:
    assert drive.files["shortcut-1"].shortcut_target == "outside-file"
    result = service.read_file("shortcut-1")
    assert result["content"] is None
    assert "not followed" in result["note"]
    meta = service.get_metadata("shortcut-1")
    assert "shortcutDetails" not in meta and "outside" not in str(meta.get("parents"))
    with pytest.raises(InvalidInputError):
        service.list_folder("shortcut-1")
    with pytest.raises(InvalidInputError):
        service.create_folder("x", parent_id="shortcut-1")
    with pytest.raises(InvalidInputError):
        service.update_file_content("shortcut-1", "x")
    # the target was never fetched, exported or downloaded
    assert "outside-file" not in drive.get_calls
    assert drive.content_calls == []
    assert drive.files["outside-file"].content == b"outside plan"


def test_shortcut_listing_and_search_do_not_expose_target(drive, service: DriveService) -> None:
    listed = service.list_folder(ROOT)["files"]
    shortcut = next(f for f in listed if f["id"] == "shortcut-1")
    assert set(shortcut) <= {
        "id",
        "name",
        "mimeType",
        "parents",
        "size",
        "createdTime",
        "modifiedTime",
        "webViewLink",
    }
    ids = {f["id"] for f in service.search_files("outside", 50)["files"]}
    assert "outside-file" not in ids


def test_shortcut_target_out_of_scope_even_when_bot_can_see_it(world) -> None:
    """In the two-view world: grant a folder containing a shortcut to a private file."""
    from scoped_drive_mcp.scope import ScopeGuard
    from tests.conftest import BOT_EMAIL, make_settings

    bot = world.as_user(BOT_EMAIL)
    world.share("proj", BOT_EMAIL)
    world.share("priv-secret", BOT_EMAIL)  # even if Google would allow the target...
    guard = ScopeGuard(bot, None, allowlist=lambda: {"proj": "application/vnd.google-apps.folder"})
    svc = DriveService(bot, guard, make_settings(root_folder_id=None))
    assert svc.read_file("proj-shortcut")["content"] is None
    with pytest.raises(OutOfScopeError):  # ...the server allowlist does not
        svc.read_file("priv-secret")
    assert "priv-secret" not in bot.content_calls


# ---- parents ------------------------------------------------------------------


class _Request:
    def __init__(self, result: dict[str, Any]):
        self.result = result
        self.headers: dict[str, str] = {}

    def execute(self, num_retries: int = 0) -> dict[str, Any]:
        return self.result


class _Recorder:
    def __init__(self, calls: list, kind: str):
        self.calls = calls
        self.kind = kind

    def __getattr__(self, method: str):
        def call(**kwargs: Any) -> _Request:
            self.calls.append((self.kind, method, kwargs))
            return _Request({"id": kwargs.get("fileId", "new-id")})

        return call


class _Service:
    def __init__(self) -> None:
        self.calls: list = []

    def files(self) -> _Recorder:
        return _Recorder(self.calls, "files")

    def permissions(self) -> _Recorder:
        return _Recorder(self.calls, "permissions")


def _client(cls=GoogleDriveClient):
    client = cls(credentials=None)
    service = _Service()
    client._local.service = service
    return client, service


@pytest.mark.parametrize(
    "metadata",
    [
        {"parents": ["elsewhere"]},
        {"name": "x", "parents": []},
        {"addParents": "elsewhere"},
        {"removeParents": ROOT},
        {"mimeType": "application/vnd.google-apps.folder"},
        {"shortcutDetails": {"targetId": "x"}},
    ],
)
def test_update_rejects_parents_and_other_metadata(metadata) -> None:
    client, service = _client()
    with pytest.raises(ValueError):
        client.update("f1", metadata, None, None, fields="id")
    assert service.calls == []
    with pytest.raises(ValueError):
        check_update_metadata(metadata)


def test_update_sends_only_name_or_trashed() -> None:
    client, service = _client()
    client.update("f1", {"name": "new"}, None, None, fields="id")
    client.update("f1", {"trashed": True}, None, None, fields="id")
    client.update("f1", None, b"body", "text/plain", fields="id")
    for _kind, method, kwargs in service.calls:
        assert method == "update"
        assert "addParents" not in kwargs and "removeParents" not in kwargs
        assert set(kwargs["body"]) <= {"name", "trashed"}
    assert service.calls[2][2]["body"] == {}


def test_create_requires_exactly_one_parent() -> None:
    client, service = _client()
    client.create({"name": "a", "parents": ["p1"]}, None, None, fields="id")
    assert service.calls[0][2]["body"] == {"name": "a", "parents": ["p1"]}
    for bad in (
        {"name": "a"},
        {"name": "a", "parents": ["p1", "p2"]},
        {"name": "a", "parents": ["p1"], "addParents": "p2"},
    ):
        with pytest.raises(ValueError):
            client.create(bad, None, None, fields="id")
    assert len(service.calls) == 1


def test_lazy_bot_client_enforces_the_same_rules(drive) -> None:
    lazy = LazyBotDriveClient("token", lambda: None, lambda _t: drive)
    with pytest.raises(ValueError):
        lazy.update("notes-txt", {"parents": ["outside-folder"]}, None, None, fields="id")
    with pytest.raises(ValueError):
        lazy.create({"name": "x", "parents": [ROOT, "outside-folder"]}, None, None, fields="id")
    assert drive.files["notes-txt"].parents == ["sub-a"]


def test_service_create_sets_exactly_the_checked_parent(drive, service: DriveService) -> None:
    created = service.create_doc("t", "c", parent_id="sub-a")
    assert drive.files[created["id"]].parents == ["sub-a"]


def test_owner_permission_calls() -> None:
    client, service = _client(GoogleOwnerDriveClient)
    assert client.create_permission("f1", "bot@example.com", "writer") == "f1"
    client.delete_permission("f1", "perm-1")
    (_, m1, create), (_, m2, delete) = service.calls
    assert (m1, m2) == ("create", "delete")
    assert create["body"] == {"type": "user", "role": "writer", "emailAddress": "bot@example.com"}
    assert create["sendNotificationEmail"] is False
    assert delete == {"fileId": "f1", "permissionId": "perm-1", "supportsAllDrives": True}


def test_bot_client_has_no_permission_methods() -> None:
    assert not hasattr(GoogleDriveClient, "create_permission")
    assert not hasattr(LazyBotDriveClient, "create_permission")
