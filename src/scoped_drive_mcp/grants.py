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


class GrantError(Exception):
    """A grant or revoke could not be completed; the message is safe to show the owner."""


@dataclass(frozen=True)
class ApprovalOption:
    id: str
    name: str
    mime_type: str
    label: str


class GrantService:
    def __init__(
        self,
        owner_drive: Callable[[], OwnerDriveClient],
        allowlist: Allowlist,
        requests: AccessRequests,
        bot_email: str | None,
        on_change: Callable[[], None] = lambda: None,
    ):
        self._owner_drive = owner_drive
        self.allowlist = allowlist
        self.requests = requests
        self.bot_email = bot_email
        self._on_change = on_change

    def owner_drive(self) -> OwnerDriveClient:
        return self._owner_drive()

    def owner_meta(self, file_id: str) -> dict[str, Any] | None:
        validate_drive_id(file_id)
        try:
            return self.owner_drive().get_file(file_id, fields=OWNER_FIELDS)
        except DriveNotFoundError:
            return None

    def grant(self, file_id: str, *, request_id: str | None = None) -> AllowEntry:
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
        )
        self.allowlist.add(entry)
        self._on_change()
        audit_owner("grant", file_id=item_id, request_id=request_id)
        return entry

    def _share(self, item_id: str) -> str:
        assert self.bot_email is not None
        try:
            return self.owner_drive().create_permission(item_id, self.bot_email, "writer")
        except DriveNotFoundError:
            raise GrantError("That item was not found in your Drive.") from None
        except Exception as exc:
            audit_owner("grant", "error", file_id=item_id, reason=type(exc).__name__)
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
        if entry.permission_id:
            try:
                self.owner_drive().delete_permission(file_id, entry.permission_id)
            except DriveNotFoundError:
                pass
            except Exception as exc:
                audit_owner("revoke", "error", file_id=file_id, reason=type(exc).__name__)
                raise GrantError(
                    "Removed from the allowlist, but Google did not remove the bot's sharing. "
                    "Remove the bot from this item's Share dialog in Drive."
                ) from None
        audit_owner("revoke", file_id=file_id)

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
