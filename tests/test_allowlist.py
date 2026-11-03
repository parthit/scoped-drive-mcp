"""Allowlist scope, grant/revoke through the owner's Drive, and revocation timing."""

import pytest

from scoped_drive_mcp.access import AccessRequests
from scoped_drive_mcp.drive_client import FOLDER_MIME
from scoped_drive_mcp.grants import GrantError, GrantService
from scoped_drive_mcp.scope import ForbiddenError, InvalidInputError, OutOfScopeError, ScopeGuard
from scoped_drive_mcp.service import DriveService
from scoped_drive_mcp.store import AllowEntry, Allowlist, MemoryStore, PrefixedStore
from tests.conftest import BOT_EMAIL, OWNER_EMAIL, ROOT, FakeClock, make_settings


@pytest.fixture
def kv():
    return PrefixedStore(MemoryStore())


@pytest.fixture
def allowlist(kv) -> Allowlist:
    return Allowlist(kv)


@pytest.fixture
def bot(world):
    return world.as_user(BOT_EMAIL)


@pytest.fixture
def owner(world):
    return world.as_user(OWNER_EMAIL)


@pytest.fixture
def p2_guard(bot, allowlist, clock) -> ScopeGuard:
    return ScopeGuard(bot, None, ttl=60, allowlist=allowlist.mime_map, allowlist_ttl=0, clock=clock)


@pytest.fixture
def grants(owner, allowlist, kv, p2_guard) -> GrantService:
    return GrantService(
        lambda: owner,
        allowlist,
        AccessRequests(kv),
        BOT_EMAIL,
        on_change=p2_guard.invalidate_allowlist,
    )


@pytest.fixture
def p2_service(bot, p2_guard) -> DriveService:
    return DriveService(bot, p2_guard, make_settings(root_folder_id=None))


def test_grant_creates_permission_and_allowlist_entry(world, owner, grants, allowlist) -> None:
    entry = grants.grant("proj")
    assert owner.permission_calls == [("create", "proj", BOT_EMAIL, "writer")]
    perms = world.files["proj"].permissions
    assert [(p["emailAddress"], p["role"]) for p in perms] == [(BOT_EMAIL, "writer")]
    assert entry.permission_id == perms[0]["id"]
    assert allowlist.get("proj") == entry
    assert entry.mime_type == FOLDER_MIME and entry.name == "Projects"
    # granting twice is a no-op
    assert grants.grant("proj") == entry
    assert len(owner.permission_calls) == 1


def test_revoke_deletes_permission_and_entry(world, owner, grants, allowlist) -> None:
    entry = grants.grant("proj")
    grants.revoke("proj")
    assert owner.permission_calls[-1] == ("delete", "proj", entry.permission_id)
    assert world.files["proj"].permissions == []
    assert allowlist.get("proj") is None
    with pytest.raises(GrantError):
        grants.revoke("proj")


def test_revoke_when_permission_already_gone(world, grants, allowlist) -> None:
    grants.grant("proj")
    world.files["proj"].permissions.clear()
    grants.revoke("proj")
    assert allowlist.get("proj") is None


def test_grant_refuses_missing_and_unowned(grants, allowlist) -> None:
    with pytest.raises(GrantError):
        grants.grant("does-not-exist")
    # the owner cannot see eve's file, so it cannot be granted
    with pytest.raises(GrantError):
        grants.grant("stray-shared")
    assert allowlist.entries() == {}


def test_grant_shortcut_grants_target(grants, allowlist) -> None:
    entry = grants.grant("proj-shortcut")
    assert entry.id == "priv-secret"
    assert allowlist.get("proj-shortcut") is None


def test_nested_folders_in_scope(grants, p2_guard) -> None:
    assert not p2_guard.is_in_scope("proj-deep-doc")
    grants.grant("proj")
    for fid in ("proj", "proj-sub", "proj-deep-doc", "proj-notes"):
        assert p2_guard.is_in_scope(fid), fid
    for fid in ("priv", "priv-secret", "loose-doc", "owner-root", "stray-shared"):
        assert not p2_guard.is_in_scope(fid), fid


def test_subfolder_grant_does_not_expose_parent(grants, p2_guard) -> None:
    grants.grant("proj-sub")
    assert p2_guard.is_in_scope("proj-deep-doc")
    assert not p2_guard.is_in_scope("proj-notes")
    assert not p2_guard.is_in_scope("proj")


def test_individual_file_grant(grants, p2_guard) -> None:
    grants.grant("loose-doc")
    assert p2_guard.is_in_scope("loose-doc")
    assert not p2_guard.is_in_scope("loose-two")


def test_bot_visible_but_not_allowlisted_is_refused(bot, p2_guard) -> None:
    # Google lets the bot see this (a third party shared it), the server allowlist does not.
    assert bot.get_file("stray-shared", "id")["id"] == "stray-shared"
    with pytest.raises(OutOfScopeError) as exc:
        p2_guard.assert_in_scope("stray-shared")
    assert exc.value.file_id == "stray-shared"


def test_allowlisted_but_not_shared_is_refused(allowlist, p2_guard) -> None:
    # Server layer allows it but Google does not: the bot cannot see it, so it is refused.
    from scoped_drive_mcp.store import AllowEntry

    allowlist.add(AllowEntry("priv-secret", "payroll.txt", "text/plain", None))
    assert not p2_guard.is_in_scope("priv-secret")


def test_revocation_takes_effect(grants, p2_service, p2_guard) -> None:
    grants.grant("proj")
    assert p2_service.read_file("proj-notes")["content"] == "project notes alpha"
    grants.revoke("proj")
    with pytest.raises(OutOfScopeError):
        p2_service.read_file("proj-notes")


def test_revocation_on_other_instance_within_allowlist_ttl(bot, allowlist, owner, kv) -> None:
    clock = FakeClock()
    other = ScopeGuard(bot, None, allowlist=allowlist.mime_map, allowlist_ttl=2, clock=clock)
    grants = GrantService(lambda: owner, allowlist, AccessRequests(kv), BOT_EMAIL)
    grants.grant("loose-doc")
    assert other.is_in_scope("loose-doc")
    allowlist.remove("loose-doc")  # revoke recorded by another instance; share still present
    assert other.is_in_scope("loose-doc")  # cached for at most allowlist_ttl
    clock.advance(2.5)
    assert not other.is_in_scope("loose-doc")


def test_bot_owned_file_in_revoked_folder_is_refused(grants, p2_service, bot) -> None:
    grants.grant("proj")
    created = p2_service.create_doc("bot note", "hi", parent_id="proj")
    assert p2_service.read_file(created["id"])["content"] == "hi"
    grants.revoke("proj")
    # Google still lets the bot see its own file, the allowlist does not
    assert bot.get_file(created["id"], "id")
    with pytest.raises(OutOfScopeError):
        p2_service.read_file(created["id"])


def test_allowlisted_items_cannot_be_renamed_or_trashed(grants, p2_service, world) -> None:
    grants.grant("proj")
    grants.grant("loose-doc")
    for fid in ("proj", "loose-doc"):
        with pytest.raises(ForbiddenError) as exc:
            p2_service.rename_file(fid, "hijacked")
        assert not isinstance(exc.value, OutOfScopeError)
        with pytest.raises(ForbiddenError):
            p2_service.trash_file(fid)
    assert world.files["proj"].name == "Projects" and not world.files["proj"].trashed
    # a granted file's content may still be edited; children of a granted folder can be renamed
    p2_service.update_file_content("loose-doc", "new memo")
    assert world.files["loose-doc"].content == b"new memo"
    p2_service.rename_file("proj-notes", "renamed.txt")
    assert world.files["proj-notes"].name == "renamed.txt"


def test_list_folder_without_id_lists_allowlisted_items(grants, p2_service) -> None:
    assert p2_service.list_folder()["files"] == []
    grants.grant("proj")
    grants.grant("loose-doc")
    result = p2_service.list_folder()
    assert [f["id"] for f in result["files"]] == ["proj", "loose-doc"]
    assert result["folder"] is None
    inside = {f["id"] for f in p2_service.list_folder("proj")["files"]}
    assert inside == {"proj-sub", "proj-notes", "proj-shortcut"}


def test_ticked_items_do_not_reveal_their_parents(grants, p2_service, world) -> None:
    world.add("two-homes", "two homes.txt", "text/plain", ["proj", "priv"], b"x", owner=OWNER_EMAIL)
    grants.grant("proj")
    grants.grant("loose-doc")
    top = p2_service.list_folder()["files"]
    assert all("parents" not in f for f in top)  # both live in the owner's My Drive root
    assert "parents" not in p2_service.get_metadata("proj")
    assert p2_service.get_metadata("two-homes")["parents"] == ["proj"]
    grants.grant("priv")
    assert p2_service.get_metadata("two-homes")["parents"] == ["proj", "priv"]
    assert "owner-root" not in str(p2_service.search_files("memo"))


def test_default_create_parent(grants, p2_service) -> None:
    with pytest.raises(InvalidInputError):
        p2_service.create_folder("x")
    grants.grant("proj")
    grants.grant("loose-doc")
    assert p2_service.create_folder("x")["parents"] == ["proj"]
    grants.grant("priv")
    with pytest.raises(InvalidInputError, match="parent_id is required"):
        p2_service.create_folder("y")


def test_search_allowlisted_folders_and_files(grants, p2_service, bot) -> None:
    grants.grant("proj")
    grants.grant("loose-doc")
    ids = {f["id"] for f in p2_service.search_files("secret", 50)["files"]}
    assert ids == {"proj-deep-doc"}  # not stray-shared, not priv-secret
    ids = {f["id"] for f in p2_service.search_files("memo", 50)["files"]}
    assert ids == {"loose-doc"}  # loose-two is not granted
    bot.ignore_parent_filter = True
    ids = {f["id"] for f in p2_service.search_files("secret", 50)["files"]}
    assert ids == {"proj-deep-doc"}


def test_share_all_refreshes_the_scope_cache(world, allowlist, grants, p2_service) -> None:
    allowlist.add(AllowEntry("proj", "Projects", FOLDER_MIME, None))
    assert p2_service.search_files("roadmap", 10)["count"] == 0
    assert grants.share_all()["shared"] == ["proj"]
    assert [p["emailAddress"] for p in world.files["proj"].permissions] == [BOT_EMAIL]
    assert p2_service.search_files("roadmap", 10)["count"] == 1


def test_search_after_revoke(grants, p2_service) -> None:
    grants.grant("proj")
    assert p2_service.search_files("roadmap", 10)["count"] == 1
    grants.revoke("proj")
    assert p2_service.search_files("roadmap", 10)["count"] == 0


def test_root_folder_id_is_an_extra_root(drive, clock, kv, mode) -> None:
    allowlist = Allowlist(kv)
    from scoped_drive_mcp.store import AllowEntry

    if mode == "separate_bot":
        drive.share("outside-folder", BOT_EMAIL)  # what ticking it on the dashboard does
    allowlist.add(AllowEntry("outside-folder", "Private", FOLDER_MIME, None))
    guard = ScopeGuard(drive, ROOT, allowlist=allowlist.mime_map, allowlist_ttl=0, clock=clock)
    assert guard.is_in_scope("notes-txt")  # via ROOT_FOLDER_ID
    assert guard.is_in_scope("outside-file")  # via the allowlist
    assert set(guard.folders_in_scope()) >= {ROOT, "outside-folder"}
    with pytest.raises(ForbiddenError):
        guard.assert_in_scope("outside-folder", allow_root=False)


def test_multi_parent_rule(drive, clock) -> None:
    """Documented rule: in scope if ANY parent chain reaches an allowlisted id."""
    guard = ScopeGuard(drive, None, allowlist=lambda: {"sub-a": FOLDER_MIME}, clock=clock)
    assert guard.is_in_scope("multi-parent")  # parents: outside-folder, sub-a
    guard = ScopeGuard(drive, None, allowlist=lambda: {"outside-folder": FOLDER_MIME}, clock=clock)
    assert guard.is_in_scope("multi-parent")
    guard = ScopeGuard(drive, None, allowlist=lambda: {"sub-a-deep": FOLDER_MIME}, clock=clock)
    assert not guard.is_in_scope("multi-parent")
