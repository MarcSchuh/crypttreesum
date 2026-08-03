"""Tree scanning and inode-based encrypted/decrypted mapping."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from crypttreesum.exceptions import ScanError
from crypttreesum.hashutil import sha256_file
from crypttreesum.models import SCHEMA_VERSION, FileRecord, Side


@dataclass(frozen=True, slots=True)
class ScanLimits:
    """Optional bounds for a testrun scan."""

    max_depth: int | None = None
    max_files: int | None = None


@dataclass(frozen=True, slots=True)
class _Candidate:
    side: Side
    rel_path: str
    abs_path: Path
    inode: int
    size: int
    mtime_ns: int
    depth: int


def _iter_candidates(root: Path, side: Side, max_depth: int | None) -> list[_Candidate]:
    if not root.is_dir():
        msg = f"{side.value} root is not a directory: {root}"
        raise ScanError(msg)

    candidates: list[_Candidate] = []
    root = root.resolve()

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        try:
            rel_dir = current.relative_to(root)
        except ValueError as exc:  # pragma: no cover - defensive
            msg = f"walk escaped root {root}: {current}"
            raise ScanError(msg) from exc

        dir_depth = 0 if rel_dir == Path() else len(rel_dir.parts)

        # Do not descend into children beyond max_depth.
        if max_depth is not None and dir_depth >= max_depth:
            dirnames.clear()

        dirnames.sort()
        filenames.sort()

        for name in filenames:
            # File depth = number of directory components under root (root=0).
            file_depth = dir_depth
            if max_depth is not None and file_depth > max_depth:
                continue

            abs_path = current / name
            if abs_path.is_symlink() or not abs_path.is_file():
                continue

            try:
                stat = abs_path.stat(follow_symlinks=False)
            except OSError as exc:
                msg = f"cannot stat {abs_path}: {exc}"
                raise ScanError(msg) from exc

            rel_path = abs_path.relative_to(root).as_posix()
            candidates.append(
                _Candidate(
                    side=side,
                    rel_path=rel_path,
                    abs_path=abs_path,
                    inode=stat.st_ino,
                    size=stat.st_size,
                    mtime_ns=stat.st_mtime_ns,
                    depth=file_depth,
                ),
            )

    candidates.sort(key=lambda item: item.rel_path)
    return candidates


def scan_trees(
    encrypted: Path,
    decrypted: Path,
    *,
    limits: ScanLimits | None = None,
) -> list[FileRecord]:
    """Scan both trees, hash files, and map encrypted paths via inode.

    Enumeration is deterministic: decrypted files (path-sorted), then encrypted
    files (path-sorted). ``max_files`` applies globally across both sides.
    Depth is counted from root = 0.
    """
    limits = limits or ScanLimits()
    if limits.max_depth is not None and limits.max_depth < 0:
        msg = "max_depth must be >= 0"
        raise ScanError(msg)
    if limits.max_files is not None and limits.max_files < 0:
        msg = "max_files must be >= 0"
        raise ScanError(msg)

    decrypted_candidates = _iter_candidates(decrypted, Side.DECRYPTED, limits.max_depth)
    encrypted_candidates = _iter_candidates(encrypted, Side.ENCRYPTED, limits.max_depth)

    combined = decrypted_candidates + encrypted_candidates
    if limits.max_files is not None:
        combined = combined[: limits.max_files]

    inode_to_logical: dict[int, str] = {
        item.inode: item.rel_path for item in combined if item.side is Side.DECRYPTED
    }

    records: list[FileRecord] = []
    for item in combined:
        try:
            digest = sha256_file(item.abs_path)
        except OSError as exc:
            msg = f"cannot hash {item.abs_path}: {exc}"
            raise ScanError(msg) from exc

        if item.side is Side.DECRYPTED:
            logical_path: str | None = item.rel_path
        else:
            logical_path = inode_to_logical.get(item.inode)

        records.append(
            FileRecord(
                schema_version=SCHEMA_VERSION,
                side=item.side,
                inode=item.inode,
                path=item.rel_path,
                logical_path=logical_path,
                sha256=digest,
                size=item.size,
                mtime_ns=item.mtime_ns,
            ),
        )

    return records
