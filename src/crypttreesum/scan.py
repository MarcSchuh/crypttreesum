"""Tree scanning and inode-based encrypted/decrypted mapping."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from crypttreesum.exceptions import ScanError
from crypttreesum.hashutil import sha256_file
from crypttreesum.logutil import get_logger
from crypttreesum.models import (
    SCHEMA_VERSION,
    EntryType,
    FileRecord,
    FolderRecord,
    ManifestRecord,
    Side,
)

_LOG = get_logger("scan")


@dataclass(frozen=True, slots=True)
class ScanLimits:
    """Optional bounds for a testrun scan."""

    max_depth: int | None = None
    max_files: int | None = None
    include_directories: bool = False


@dataclass(frozen=True, slots=True)
class _Candidate:
    side: Side
    rel_path: str
    abs_path: Path
    inode: int
    size: int
    mtime_ns: int
    depth: int
    entry_type: EntryType


def _candidate_from_path(
    path: Path,
    root: Path,
    side: Side,
    depth: int,
    entry_type: EntryType,
) -> _Candidate:
    try:
        stat = path.stat(follow_symlinks=False)
    except OSError as exc:
        msg = f"cannot stat {path}: {exc}"
        raise ScanError(msg) from exc
    return _Candidate(
        side=side,
        rel_path=path.relative_to(root).as_posix(),
        abs_path=path,
        inode=stat.st_ino,
        size=stat.st_size,
        mtime_ns=stat.st_mtime_ns,
        depth=depth,
        entry_type=entry_type,
    )


def _directory_candidates(
    current: Path,
    root: Path,
    side: Side,
    dirnames: list[str],
    depth: int,
) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for name in dirnames:
        abs_path = current / name
        if abs_path.is_symlink():
            _LOG.debug("skipping symlinked directory: %s", abs_path)
            continue
        candidates.append(
            _candidate_from_path(
                abs_path,
                root,
                side,
                depth,
                EntryType.DIRECTORY,
            ),
        )
    return candidates


def _file_candidates(
    current: Path,
    root: Path,
    side: Side,
    filenames: list[str],
    depth: int,
) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for name in filenames:
        abs_path = current / name
        if abs_path.is_symlink() or not abs_path.is_file():
            _LOG.debug("skipping non-regular file: %s", abs_path)
            continue
        candidate = _candidate_from_path(
            abs_path,
            root,
            side,
            depth,
            EntryType.FILE,
        )
        _LOG.debug(
            "found %s file: %s (inode=%d size=%d)",
            side.value,
            candidate.rel_path,
            candidate.inode,
            candidate.size,
        )
        candidates.append(candidate)
    return candidates


def _iter_candidates(
    root: Path,
    side: Side,
    max_depth: int | None,
    *,
    include_directories: bool,
) -> list[_Candidate]:
    if not root.is_dir():
        msg = f"{side.value} root is not a directory: {root}"
        raise ScanError(msg)

    candidates: list[_Candidate] = []
    root = root.resolve()
    _LOG.info("enumerating %s tree: %s", side.value, root)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        try:
            rel_dir = current.relative_to(root)
        except ValueError as exc:  # pragma: no cover - defensive
            msg = f"walk escaped root {root}: {current}"
            raise ScanError(msg) from exc

        dir_depth = 0 if rel_dir == Path() else len(rel_dir.parts)
        rel_display = "." if rel_dir == Path() else rel_dir.as_posix()
        _LOG.info(
            "scanning %s [%s] depth=%d (%d entries)",
            side.value,
            rel_display,
            dir_depth,
            len(filenames),
        )

        dirnames.sort()
        filenames.sort()

        if include_directories:
            candidates.extend(
                _directory_candidates(
                    current,
                    root,
                    side,
                    dirnames,
                    dir_depth,
                ),
            )

        # Do not descend into children beyond max_depth.
        if max_depth is not None and dir_depth >= max_depth:
            dirnames.clear()

        candidates.extend(
            _file_candidates(current, root, side, filenames, dir_depth),
        )

    candidates.sort(key=lambda item: (item.rel_path, item.entry_type.value))
    file_count = sum(
        1 for candidate in candidates if candidate.entry_type is EntryType.FILE
    )
    directory_count = len(candidates) - file_count
    _LOG.info(
        "found %d files and %d directories under %s",
        file_count,
        directory_count,
        side.value,
    )
    return candidates


def _apply_file_limit(
    candidates: list[_Candidate],
    max_files: int | None,
) -> list[_Candidate]:
    if max_files is None:
        return candidates

    file_count = 0
    limited: list[_Candidate] = []
    for candidate in candidates:
        if candidate.entry_type is EntryType.FILE:
            if file_count >= max_files:
                continue
            file_count += 1
        limited.append(candidate)

    original_file_count = sum(
        1 for candidate in candidates if candidate.entry_type is EntryType.FILE
    )
    if original_file_count != file_count:
        _LOG.info(
            "max_files=%d truncated file list from %d to %d",
            max_files,
            original_file_count,
            file_count,
        )
    return limited


def _hash_candidate(item: _Candidate, index: int, total: int) -> str | None:
    if item.entry_type is EntryType.DIRECTORY:
        _LOG.info("recording %s directory: %s", item.side.value, item.rel_path)
        return None

    _LOG.info(
        "hashing [%d/%d] %s: %s (%d bytes)",
        index,
        total,
        item.side.value,
        item.rel_path,
        item.size,
    )
    try:
        return sha256_file(item.abs_path)
    except OSError as exc:
        msg = f"cannot hash {item.abs_path}: {exc}"
        raise ScanError(msg) from exc


def _logical_path_for(
    item: _Candidate,
    inode_to_logical: dict[tuple[EntryType, int], str],
) -> str | None:
    if item.side is Side.DECRYPTED:
        return item.rel_path

    logical_path = inode_to_logical.get((item.entry_type, item.inode))
    if logical_path is None:
        _LOG.debug("no inode mapping for encrypted path %s", item.rel_path)
    else:
        _LOG.debug(
            "mapped encrypted %s -> logical %s",
            item.rel_path,
            logical_path,
        )
    return logical_path


def _build_records(candidates: list[_Candidate]) -> list[ManifestRecord]:
    inode_to_logical: dict[tuple[EntryType, int], str] = {
        (item.entry_type, item.inode): item.rel_path
        for item in candidates
        if item.side is Side.DECRYPTED
    }
    hash_count = sum(
        1 for candidate in candidates if candidate.entry_type is EntryType.FILE
    )
    _LOG.info(
        "built inode map with %d decrypted entries; hashing %d files",
        len(inode_to_logical),
        hash_count,
    )

    records: list[ManifestRecord] = []
    hash_index = 0
    for item in candidates:
        logical_path = _logical_path_for(item, inode_to_logical)
        if item.entry_type is EntryType.FILE:
            hash_index += 1
            digest = _hash_candidate(item, hash_index, hash_count)
            if digest is None:  # pragma: no cover - guarded by entry type
                msg = f"missing digest for file: {item.abs_path}"
                raise ScanError(msg)
            record: ManifestRecord = FileRecord(
                schema_version=SCHEMA_VERSION,
                side=item.side,
                inode=item.inode,
                path=item.rel_path,
                logical_path=logical_path,
                size=item.size,
                mtime_ns=item.mtime_ns,
                sha256=digest,
            )
        else:
            _hash_candidate(item, hash_index, hash_count)
            record = FolderRecord(
                schema_version=SCHEMA_VERSION,
                side=item.side,
                inode=item.inode,
                path=item.rel_path,
                logical_path=logical_path,
                size=item.size,
                mtime_ns=item.mtime_ns,
            )
        records.append(record)
    return records


def scan_trees(
    encrypted: Path,
    decrypted: Path,
    *,
    limits: ScanLimits | None = None,
) -> list[ManifestRecord]:
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

    _LOG.info(
        "starting scan encrypted=%s decrypted=%s max_depth=%s max_files=%s "
        "include_directories=%s",
        encrypted,
        decrypted,
        limits.max_depth,
        limits.max_files,
        limits.include_directories,
    )

    decrypted_candidates = _iter_candidates(
        decrypted,
        Side.DECRYPTED,
        limits.max_depth,
        include_directories=limits.include_directories,
    )
    encrypted_candidates = _iter_candidates(
        encrypted,
        Side.ENCRYPTED,
        limits.max_depth,
        include_directories=limits.include_directories,
    )

    combined = _apply_file_limit(
        decrypted_candidates + encrypted_candidates,
        limits.max_files,
    )
    records = _build_records(combined)

    mapped = sum(
        1 for record in records if record.side is Side.ENCRYPTED and record.logical_path
    )
    unmatched = sum(
        1
        for record in records
        if record.side is Side.ENCRYPTED and record.logical_path is None
    )
    _LOG.info(
        "scan complete: %d records (mapped_encrypted=%d unmatched_encrypted=%d)",
        len(records),
        mapped,
        unmatched,
    )
    return records
