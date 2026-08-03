"""Data models for scan manifests."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

SCHEMA_VERSION = 1


class Side(StrEnum):
    """Which tree a file record belongs to."""

    ENCRYPTED = "encrypted"
    DECRYPTED = "decrypted"


@dataclass(frozen=True, slots=True)
class FileRecord:
    """One hashable file on one side of the tree pair."""

    schema_version: int
    side: Side
    inode: int
    path: str
    logical_path: str | None
    sha256: str
    size: int
    mtime_ns: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        data = asdict(self)
        data["side"] = self.side.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileRecord:
        """Deserialize from a JSON object."""
        return cls(
            schema_version=int(data["schema_version"]),
            side=Side(str(data["side"])),
            inode=int(data["inode"]),
            path=str(data["path"]),
            logical_path=None
            if data.get("logical_path") is None
            else str(data["logical_path"]),
            sha256=str(data["sha256"]),
            size=int(data["size"]),
            mtime_ns=int(data["mtime_ns"]),
        )

    def identity_key(self) -> tuple[str, str]:
        """Stable cross-host identity for diffing.

        Prefer logical_path (inode-mapped cleartext path). Fall back to the
        side-local path for unmatched encrypted metadata such as gocryptfs.conf.
        """
        if self.logical_path is not None:
            return (self.side.value, self.logical_path)
        return (self.side.value, self.path)
