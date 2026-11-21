"""Owner-side grant and revoke (server allowlist).

Grant and revoke change the allowlist. The dashboard never passes a bot address, so a tick
does not create a Drive permission. Revoke still deletes a permission id already stored on
an older entry.
"""

from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from .access import APPROVED, DENIED, AccessRequest, AccessRequests
from .audit import audit_owner
from .drive_client import FOLDER_MIME, SHORTCUT_MIME, DriveNotFoundError, OwnerDriveClient
from .scope import validate_drive_id
from .store import AllowEntry, Allowlist

OWNER_FIELDS = "id,name,mimeType,parents,trashed,webViewLink,shortcutDetails"
# Bounds for covering_entry's walk up the folder tree (levels, and folders looked at).
MAX_COVER_DEPTH = 25
MAX_COVER_NODES = 200


class GrantError(Exception):
    """A grant or revoke could not be completed; the message is safe to show the owner."""


@dataclass(frozen=True)
class ApprovalOption:
    id: str
    name: str
    mime_type: str
    label: str


class _Keep:
    """Leave this field as it is (set_audience's expires_at)."""


KEEP = _Keep()


class GrantService:
    def __init__(
        self,
        owner_drive: Callable[[], OwnerDriveClient],
        allowlist: Allowlist,
        requests: AccessRequests,
        bot_email: str | None,
        on_change: Callable[[], None] = lambda: None,
        audience: str | None = None,
        audit_actions: tuple[str, str] = ("grant", "revoke"),
    ):
        self._owner_drive = owner_drive
        self.allowlist = allowlist
        self.requests = requests
        self.bot_email = bot_email
        self._on_change = on_change
        # Stamped on new entries. Set for the external list (who may read the item).
        self.audience = audience
        # Activity-log names for grant and revoke, so the external list does not log
        # as if the person's own assistant were given access.
        self._grant_action, self._revoke_action = audit_actions

    def owner_drive(self) -> OwnerDriveClient:
        return self._owner_drive()

    def owner_meta(self, file_id: str) -> dict[str, Any] | None:
        validate_drive_id(file_id)
        try:
            return self.owner_drive().get_file(file_id, fields=OWNER_FIELDS)
        except DriveNotFoundError:
            return None

    def grant(
        self,
        file_id: str,
        *,
        request_id: str | None = None,
        audience: str | tuple[str, ...] | None = None,
        expires_at: str | None = None,
    ) -> AllowEntry:
        """Add an item. On the Sharing list, `audience` (default: everyone paired) and
        `expires_at` say who may read it and until when. For an item already on the list,
        a given audience or expiry is applied with set_audience; without them it keeps
        what it has."""
        meta = self.owner_meta(file_id)
        if meta is None:
            raise GrantError("That item was not found in your Drive.")
        if meta.get("mimeType") == SHORTCUT_MIME:
            target = (meta.get("shortcutDetails") or {}).get("targetId")
            if not target:
                raise GrantError("That shortcut has no target.")
            meta = self.owner_meta(str(target))
            if meta is None:
                raise GrantError("The shortcut's target was not found in your Drive.")
        if meta.get("trashed"):
            raise GrantError("That item is in the trash.")
        item_id = str(meta["id"])
        existing = self.allowlist.get(item_id)
        if existing is not None:
            if self.audience is not None and (audience is not None or expires_at is not None):
                return self.set_audience(
                    item_id,
                    audience
                    if audience is not None
                    # An item that names nobody stays that way; never widen it to everyone.
                    else (existing.audience if existing.audience is not None else self.audience),
                    expires_at if expires_at is not None else KEEP,
                )
            if request_id and not existing.request_id:
                updated = replace(existing, request_id=request_id)
                self.allowlist.add(updated)
                return updated
            return existing
        if item_id == self.my_drive_root_id():
            raise GrantError("Your whole My Drive cannot be shared; pick folders or files in it.")
        permission_id = self._share(item_id) if self.bot_email else None
        entry = AllowEntry(
            id=item_id,
            name=str(meta.get("name", "")),
            mime_type=str(meta.get("mimeType", "")),
            permission_id=permission_id,
            request_id=request_id,
            shared_with=self.bot_email if permission_id else None,
            audience=self._audience_for(audience),
            expires_at=expires_at if self.audience is not None else None,
        )
        self.allowlist.add(entry)
        self._on_change()
        self._access_changed(item_id)
        audit_owner(self._grant_action, file_id=item_id, request_id=request_id)
        return entry

    def _audience_for(self, audience: str | tuple[str, ...] | None) -> str | tuple[str, ...] | None:
        if self.audience is None:
            return None
        if isinstance(audience, tuple):
            return tuple(sorted({a.strip().lower() for a in audience if a.strip()}))
        return self.audience

    def set_audience(
        self,
        file_id: str,
        audience: str | tuple[str, ...],
        expires_at: "str | None | _Keep" = None,
    ) -> AllowEntry:
        """Sharing list only: change who may read an item, and until when. `expires_at`
        None clears the end date; KEEP leaves it as it is. An empty tuple is refused; use
        revoke to stop sharing with everyone."""
        if self.audience is None:
            raise GrantError("Only items on your Sharing list have an audience.")
        validate_drive_id(file_id)
        entry = self.allowlist.get(file_id)
        if entry is None:
            raise GrantError("That item is not on your Sharing list.")
        chosen = self._audience_for(audience)
        if isinstance(chosen, tuple) and not chosen:
            raise GrantError("Choose at least one person, or stop sharing the item.")
        until = entry.expires_at if isinstance(expires_at, _Keep) else (expires_at or None)
        updated = replace(entry, audience=chosen, expires_at=until)
        self.allowlist.add(updated)
        self._on_change()
        who = ",".join(chosen) if isinstance(chosen, tuple) else "everyone"
        audit_owner("share_audience", file_id=file_id, audience=who, expires_at=until or "")
        return updated

    def _access_changed(self, item_id: str) -> None:
        """The owner changed what the assistant may use, so an earlier denial for this
        item stops holding back new requests. The Sharing list is about other people's
        assistants and leaves those denials alone."""
        if self.audience is None:
            self.requests.clear_denials(item_id)

    def _share(self, item_id: str) -> str:
        assert self.bot_email is not None
        try:
            return self.owner_drive().create_permission(item_id, self.bot_email, "writer")
        except DriveNotFoundError:
            raise GrantError("That item was not found in your Drive.") from None
        except Exception as exc:
            audit_owner(self._grant_action, "error", file_id=item_id, reason=type(exc).__name__)
            raise GrantError(
                "Google refused to share this item with the bot (you may not own it)."
            ) from None

    def unshared(self) -> list[AllowEntry]:
        """Allowlisted items not yet shared with the current bot (e.g. ticked in
        same-account mode before a bot was configured)."""
        if not self.bot_email:
            return []
        return [e for e in self.allowlist.entries().values() if e.shared_with != self.bot_email]

    def share_all(self) -> dict[str, Any]:
        """Share every allowlisted item with the current bot. Safe to run again: items
        already shared with this bot are skipped, and a failure leaves the entry as it was."""
        if not self.bot_email:
            raise GrantError("Set BOT_EMAIL to a separate account first.")
        shared: list[str] = []
        failed: list[dict[str, str]] = []
        for entry in self.unshared():
            try:
                permission_id = self._share(entry.id)
            except GrantError as exc:
                failed.append({"id": entry.id, "name": entry.name, "error": str(exc)})
                continue
            if entry.permission_id:
                # Left over from an earlier bot address; that account should lose access.
                try:
                    self.owner_drive().delete_permission(entry.id, entry.permission_id)
                except Exception as exc:
                    audit_owner("share_all", "error", file_id=entry.id, reason=type(exc).__name__)
            current = self.allowlist.get(entry.id)
            if current is None:
                # Revoked while we were sharing: undo the new share.
                try:
                    self.owner_drive().delete_permission(entry.id, permission_id)
                except Exception:
                    failed.append({"id": entry.id, "name": entry.name, "error": "revoked"})
                continue
            self.allowlist.add(
                replace(current, permission_id=permission_id, shared_with=self.bot_email)
            )
            shared.append(entry.id)
        if shared:
            # Newly shared folders become visible to the bot. Drop the cached folder
            # tree the same way grant() does, or search keeps using the old set until TTL.
            self._on_change()
        audit_owner("share_all", shared=str(len(shared)), failed=str(len(failed)))
        return {"shared": shared, "failed": failed}

    def revoke(self, file_id: str) -> None:
        validate_drive_id(file_id)
        entry = self.allowlist.get(file_id)
        if entry is None:
            raise GrantError("That item is not in the allowlist.")
        self.allowlist.remove(file_id)
        self._on_change()
        self._access_changed(file_id)
        if entry.permission_id:
            try:
                self.owner_drive().delete_permission(file_id, entry.permission_id)
            except DriveNotFoundError:
                pass
            except Exception as exc:
                audit_owner(
                    self._revoke_action, "error", file_id=file_id, reason=type(exc).__name__
                )
                raise GrantError(
                    "Removed from the allowlist, but Google did not remove the bot's sharing. "
                    "Remove the bot from this item's Share dialog in Drive."
                ) from None
        audit_owner(self._revoke_action, file_id=file_id)

    def covering_entry(
        self, file_id: str, extra: dict[str, str] | None = None
    ) -> tuple[str, str] | None:
        """The nearest folder above `file_id` that is on this list, as (id, name).

        A folder on the list includes what is inside it, so after removing an item's own
        entry it can still be reachable through one of its folders. This walks every
        parent chain, the same way the scope guard does, so the dashboard can say so
        instead of claiming the item is gone. `extra` adds ids that count as allowed
        without being on the list (the server's root folder), mapped to a display name.
        """
        entries = self.allowlist.entries()
        drive = self.owner_drive()
        seen: set[str] = {file_id}
        frontier = [file_id]
        for _ in range(MAX_COVER_DEPTH):
            next_frontier: list[str] = []
            for fid in frontier:
                try:
                    meta = drive.get_file(fid, fields="id,parents")
                except DriveNotFoundError:
                    continue
                for parent in meta.get("parents") or []:
                    pid = str(parent)
                    if pid in seen:
                        continue
                    seen.add(pid)
                    if pid in entries:
                        return pid, entries[pid].name or pid
                    if extra and pid in extra:
                        return pid, extra[pid]
                    next_frontier.append(pid)
            if not next_frontier or len(seen) > MAX_COVER_NODES:
                return None
            frontier = next_frontier
        return None

    # ---- access request decisions --------------------------------------

    def approval_options(self, req: AccessRequest) -> list[ApprovalOption]:
        """For a file request: the item itself, plus its parent folder if the owner can see it
        (and it is not the owner's My Drive root, which cannot be shared)."""
        if not req.file_id:
            return []
        meta = self.owner_meta(req.file_id)
        if meta is None:
            return []
        root_id = self.my_drive_root_id()
        item_id = str(meta["id"])
        options: list[ApprovalOption] = []
        # The item itself is not an option when it is My Drive. Sharing it would
        # give the bot the owner's whole drive; grant() refuses that too.
        if item_id != root_id:
            options.append(
                ApprovalOption(
                    id=item_id,
                    name=str(meta.get("name", "")),
                    mime_type=str(meta.get("mimeType", "")),
                    label="Share just this item",
                )
            )
        for parent_id in meta.get("parents") or []:
            if parent_id == root_id:
                continue
            parent = self.owner_meta(str(parent_id))
            if parent is None or parent.get("mimeType") != FOLDER_MIME:
                continue
            options.append(
                ApprovalOption(
                    id=str(parent["id"]),
                    name=str(parent.get("name", "")),
                    mime_type=FOLDER_MIME,
                    label="Share its whole parent folder",
                )
            )
            break
        return options

    def my_drive_root_id(self) -> str | None:
        try:
            return str(self.owner_drive().get_file("root", fields="id")["id"])
        except DriveNotFoundError:
            return None

    def approve(self, req: AccessRequest, target_id: str) -> AllowEntry:
        if req.status != "pending":
            raise GrantError(f"This request was already {req.status}.")
        validate_drive_id(target_id)
        if req.file_id:
            allowed = {o.id for o in self.approval_options(req)}
            # No safe option (item missing, or it is My Drive itself): the approval page
            # sends the owner to Browse to pick a substitute. A visible file or its
            # parent is still the only thing that may be approved for that request.
            if allowed and target_id not in allowed:
                raise GrantError("Pick the requested item or its parent folder.")
        entry = self.grant(target_id, request_id=req.id)
        self.requests.decide(req, APPROVED, granted_id=entry.id, granted_name=entry.name)
        audit_owner("approve_request", request_id=req.id, file_id=entry.id)
        return entry

    def deny(self, req: AccessRequest) -> None:
        if req.status != "pending":
            raise GrantError(f"This request was already {req.status}.")
        self.requests.decide(req, DENIED)
        audit_owner("deny_request", request_id=req.id, file_id=req.file_id)
