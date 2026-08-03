"""Data models for scan manifests."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any, ClassVar

SCHEMA_VERSION = 1


class Side(StrEnum):
    """Which tree a file record belongs to."""

    ENCRYPTED = "encrypted"
    DECRYPTED = "decrypted"


class EntryType(StrEnum):
    """Type of filesystem entry represented by a manifest record."""

    FILE = "file"
    DIRECTORY = "directory"


@dataclass(frozen=True, slots=True)
class RecordBase:
    """Fields and behavior shared by all manifest records."""

    schema_version: int
    side: Side
    inode: int
    path: str
    logical_path: str | None
    size: int
    mtime_ns: int

    entry_type: ClassVar[EntryType]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        data = asdict(self)
        data["side"] = self.side.value
        data["entry_type"] = self.entry_type.value
        return data

    def identity_key(self) -> tuple[str, str, str]:
        """Stable cross-host identity for diffing.

        Prefer logical_path (inode-mapped cleartext path). Fall back to the
        side-local path for unmatched encrypted metadata such as gocryptfs.conf.
        """
        if self.logical_path is not None:
            return (self.side.value, self.entry_type.value, self.logical_path)
        return (self.side.value, self.entry_type.value, self.path)


@dataclass(frozen=True, slots=True)
class FileRecord(RecordBase):
    """A file manifest record.

    ``sha256`` is ``None`` when the content could not be read during the scan;
    such a record documents the file's existence but not its integrity.
    """

    sha256: str | None
    entry_type: ClassVar[EntryType] = EntryType.FILE


@dataclass(frozen=True, slots=True)
class FolderRecord(RecordBase):
    """A directory manifest record without a content digest."""

    entry_type: ClassVar[EntryType] = EntryType.DIRECTORY


ManifestRecord = FileRecord | FolderRecord


def record_from_dict(data: dict[str, Any]) -> ManifestRecord:
    """Deserialize a manifest record based on its entry type."""
    entry_type = EntryType(str(data.get("entry_type", EntryType.FILE.value)))
    common = {
        "schema_version": int(data["schema_version"]),
        "side": Side(str(data["side"])),
        "inode": int(data["inode"]),
        "path": str(data["path"]),
        "logical_path": (
            None if data.get("logical_path") is None else str(data["logical_path"])
        ),
        "size": int(data["size"]),
        "mtime_ns": int(data["mtime_ns"]),
    }
    if entry_type is EntryType.DIRECTORY:
        return FolderRecord(**common)  # type: ignore[arg-type]

    digest = data["sha256"]
    if digest is not None and not isinstance(digest, str):
        msg = "file record sha256 must be a string or null"
        raise TypeError(msg)
    return FileRecord(**common, sha256=digest)  # type: ignore[arg-type]
