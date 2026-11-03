import pytest

from scoped_drive_mcp.scope import (
    ForbiddenError,
    InvalidInputError,
    ScopeGuard,
    escape_query_value,
)
from tests.conftest import ROOT
from tests.fake_drive import compile_query


@pytest.mark.parametrize("file_id", [ROOT, "sub-a", "sub-a-deep", "doc-deep", "notes-txt"])
def test_in_scope_reads_pass(guard: ScopeGuard, file_id: str) -> None:
    assert guard.assert_in_scope(file_id).id == file_id


@pytest.mark.parametrize(
    "file_id",
    [
        "outside-folder",
        "outside-file",
        "bot-my-drive-root",
        "cycle-file",
        "cycle-a",
        "orphan-file",
        "dangling-file",
        "trashed-txt",
        "does-not-exist",
    ],
)
def test_out_of_scope_is_forbidden(guard: ScopeGuard, file_id: str) -> None:
    with pytest.raises(ForbiddenError):
        guard.assert_in_scope(file_id)


def test_multiple_parents_one_in_scope(guard: ScopeGuard) -> None:
    assert guard.assert_in_scope("multi-parent").id == "multi-parent"


def test_cycle_terminates(drive, clock) -> None:
    guard = ScopeGuard(drive, ROOT, ttl=60, clock=clock, max_depth=1000, max_lookups=1000)
    with pytest.raises(ForbiddenError):
        guard.assert_in_scope("cycle-file")
    # each cycle folder fetched at most once
    assert drive.get_calls.count("cycle-a") <= 1 and drive.get_calls.count("cycle-b") <= 1


def test_depth_cap(drive, clock) -> None:
    from scoped_drive_mcp.drive_client import FOLDER_MIME

    parent = ROOT
    for i in range(10):
        drive.add(f"chain-{i:02d}", f"c{i}", FOLDER_MIME, [parent])
        parent = f"chain-{i:02d}"
    drive.add("chain-leaf", "leaf.txt", "text/plain", [parent])
    shallow = ScopeGuard(drive, ROOT, ttl=60, clock=clock, max_depth=5)
    with pytest.raises(ForbiddenError):
        shallow.assert_in_scope("chain-leaf")
    deep = ScopeGuard(drive, ROOT, ttl=60, clock=clock, max_depth=20)
    assert deep.assert_in_scope("chain-leaf").id == "chain-leaf"


def test_parent_moved_outside_forbidden_after_ttl(drive, guard: ScopeGuard, clock, mode) -> None:
    assert guard.is_in_scope("doc-deep")
    drive.move("sub-a-deep", ["outside-folder"])
    if mode == "separate_bot":
        # Google itself stops the bot at once: the file is no longer under a shared folder.
        assert not guard.is_in_scope("doc-deep")
    else:
        # ancestor lookups are cached, so the move is only noticed after the TTL
        assert guard.is_in_scope("doc-deep")
    clock.advance(61)
    assert not guard.is_in_scope("doc-deep")
    with pytest.raises(ForbiddenError):
        guard.assert_in_scope("doc-deep")


def test_target_itself_is_never_cached(drive, guard: ScopeGuard) -> None:
    assert guard.is_in_scope("notes-txt")
    drive.move("notes-txt", ["outside-folder"])
    assert not guard.is_in_scope("notes-txt")


def test_root_not_allowed_for_writes(guard: ScopeGuard) -> None:
    assert guard.assert_in_scope(ROOT, allow_root=True).id == ROOT
    with pytest.raises(ForbiddenError):
        guard.assert_in_scope(ROOT, allow_root=False)


def test_parent_must_be_in_scope_folder(guard: ScopeGuard) -> None:
    assert guard.assert_parent_in_scope(ROOT).id == ROOT
    assert guard.assert_parent_in_scope("sub-a-deep").id == "sub-a-deep"
    with pytest.raises(ForbiddenError):
        guard.assert_parent_in_scope("outside-folder")
    with pytest.raises(InvalidInputError):
        guard.assert_parent_in_scope("notes-txt")


@pytest.mark.parametrize("bad", ["", "a b", "x'or'1", "../etc", "id\n", "a" * 201, None, 123])
def test_invalid_ids_rejected(guard: ScopeGuard, bad) -> None:
    with pytest.raises(InvalidInputError):
        guard.assert_in_scope(bad)


def test_folders_in_scope(guard: ScopeGuard) -> None:
    folders = set(guard.folders_in_scope())
    assert folders == {ROOT, "sub-a", "sub-a-deep"}


def test_folders_in_scope_chunked_and_paginated(drive, clock) -> None:
    from scoped_drive_mcp.drive_client import FOLDER_MIME

    for i in range(25):
        drive.add(f"wide-{i:03d}", f"w{i}", FOLDER_MIME, [ROOT])
        drive.add(f"wide-child-{i:03d}", f"wc{i}", FOLDER_MIME, [f"wide-{i:03d}"])
    drive.page_size_cap = 7
    guard = ScopeGuard(drive, ROOT, ttl=60, clock=clock, parents_chunk_size=4)
    folders = set(guard.folders_in_scope())
    assert len(folders) == 3 + 50
    assert "outside-folder" not in folders
    for q in drive.queries:
        assert q.count(" in parents") <= 4


def test_search_never_returns_outside_files(guard: ScopeGuard) -> None:
    ids = {f["id"] for f in guard.search("plan", 50, fields="id,name")}
    assert ids == {"doc-deep", "notes-txt", "multi-parent"}


def test_search_rechecks_results_even_if_drive_ignores_filter(drive, guard: ScopeGuard) -> None:
    drive.ignore_parent_filter = True
    ids = {f["id"] for f in guard.search("plan", 50, fields="id,name")}
    assert ids == {"doc-deep", "notes-txt", "multi-parent"}
    assert "outside-file" not in ids and "cycle-file" not in ids


def test_search_respects_max_results(guard: ScopeGuard) -> None:
    assert len(guard.search("plan", 2, fields="id")) == 2


def test_search_query_shape(drive, guard: ScopeGuard) -> None:
    guard.search("it's", 5, fields="id")
    q = drive.queries[-1]
    assert q.startswith("trashed=false and (fullText contains 'it\\'s' or name contains 'it\\'s')")
    assert f"'{ROOT}' in parents" in q


def test_escape_query_value() -> None:
    assert escape_query_value("plain") == "plain"
    assert escape_query_value("it's") == "it\\'s"
    assert escape_query_value("back\\slash") == "back\\\\slash"
    assert escape_query_value("\\'") == "\\\\\\'"


@pytest.mark.parametrize(
    "payload",
    [
        "x' or trashed=true or name contains '",
        "x\\' or 'outside-folder' in parents or name contains '",
        "') or ('outside-folder' in parents",
        "\\",
        "'",
    ],
)
def test_injection_attempts_stay_literal(drive, guard: ScopeGuard, payload: str) -> None:
    results = guard.search(payload, 50, fields="id")
    assert results == []
    for q in drive.queries:
        compile_query(q)  # still a single well-formed expression
    q = drive.queries[-1]
    assert q.count("trashed=false") == 1
    assert "'outside-folder' in parents" not in q


def test_search_control_chars_are_stripped(drive, guard: ScopeGuard) -> None:
    guard.search("plan\nnotes", 5, fields="id")
    assert "\n" not in drive.queries[-1]
