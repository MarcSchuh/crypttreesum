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


@dataclass(frozen=True, slots=True)
class ScanIssue:
    """An entry the scan could not fully inspect.

    ``operation`` is ``"hash"`` (the entry is still recorded, with
    ``sha256: null``) or ``"list"``/``"stat"`` (the entry is skipped entirely
    because it could not be enumerated).
    """

    side: Side
    path: Path
    operation: str
    message: str


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Manifest records plus the entries that could not be read."""

    records: list[ManifestRecord]
    issues: list[ScanIssue]


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


@dataclass(slots=True)
class _WalkContext:
    root: Path
    side: Side
    issues: list[ScanIssue]


def _record_issue(
    ctx: _WalkContext,
    path: Path,
    operation: str,
    exc: OSError,
) -> None:
    _LOG.error("cannot %s %s: %s", operation, path, exc)
    ctx.issues.append(
        ScanIssue(
            side=ctx.side,
            path=path,
            operation=operation,
            message=str(exc),
        ),
    )


def _candidate_from_path(
    ctx: _WalkContext,
    path: Path,
    depth: int,
    entry_type: EntryType,
) -> _Candidate | None:
    try:
        stat = path.stat(follow_symlinks=False)
    except OSError as exc:
        _record_issue(ctx, path, "stat", exc)
        return None
    return _Candidate(
        side=ctx.side,
        rel_path=path.relative_to(ctx.root).as_posix(),
        abs_path=path,
        inode=stat.st_ino,
        size=stat.st_size,
        mtime_ns=stat.st_mtime_ns,
        depth=depth,
        entry_type=entry_type,
    )


def _directory_candidates(
    ctx: _WalkContext,
    current: Path,
    dirnames: list[str],
    depth: int,
) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for name in dirnames:
        abs_path = current / name
        try:
            is_symlink = abs_path.is_symlink()
        except OSError as exc:
            _record_issue(ctx, abs_path, "stat", exc)
            continue
        if is_symlink:
            _LOG.debug("skipping symlinked directory: %s", abs_path)
            continue
        candidate = _candidate_from_path(
            ctx,
            abs_path,
            depth,
            EntryType.DIRECTORY,
        )
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def _file_candidates(
    ctx: _WalkContext,
    current: Path,
    filenames: list[str],
    depth: int,
) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for name in filenames:
        abs_path = current / name
        try:
            is_regular = not abs_path.is_symlink() and abs_path.is_file()
        except OSError as exc:
            _record_issue(ctx, abs_path, "stat", exc)
            continue
        if not is_regular:
            _LOG.debug("skipping non-regular file: %s", abs_path)
            continue
        candidate = _candidate_from_path(ctx, abs_path, depth, EntryType.FILE)
        if candidate is None:
            continue
        _LOG.debug(
            "found %s file: %s (inode=%d size=%d)",
            ctx.side.value,
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
    issues: list[ScanIssue],
) -> list[_Candidate]:
    if not root.is_dir():
        msg = f"{side.value} root is not a directory: {root}"
        raise ScanError(msg)

    candidates: list[_Candidate] = []
    root = root.resolve()
    ctx = _WalkContext(root=root, side=side, issues=issues)
    _LOG.info("enumerating %s tree: %s", side.value, root)

    def on_walk_error(exc: OSError) -> None:
        _record_issue(ctx, Path(exc.filename or root), "list", exc)

    walker = os.walk(root, followlinks=False, onerror=on_walk_error)
    for dirpath, dirnames, filenames in walker:
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

        candidates.extend(_directory_candidates(ctx, current, dirnames, dir_depth))

        # Do not descend into children beyond max_depth.
        if max_depth is not None and dir_depth >= max_depth:
            dirnames.clear()

        candidates.extend(_file_candidates(ctx, current, filenames, dir_depth))

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


def _hash_file(
    item: _Candidate,
    index: int,
    total: int,
    issues: list[ScanIssue],
) -> str | None:
    """Hash a file, or return ``None`` if its content cannot be read."""
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
        _LOG.error("cannot hash %s: %s", item.abs_path, exc)
        issues.append(
            ScanIssue(
                side=item.side,
                path=item.abs_path,
                operation="hash",
                message=str(exc),
            ),
        )
        return None


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


def _inode_map(
    candidates: list[_Candidate],
) -> dict[tuple[EntryType, int], str]:
    inode_to_logical: dict[tuple[EntryType, int], str] = {}
    for item in candidates:
        if item.side is not Side.DECRYPTED:
            continue
        key = (item.entry_type, item.inode)
        previous = inode_to_logical.get(key)
        if previous is not None and previous != item.rel_path:
            _LOG.warning(
                "duplicate decrypted inode %d (%s): keeping %r, ignoring %r",
                item.inode,
                item.entry_type.value,
                previous,
                item.rel_path,
            )
            continue
        inode_to_logical[key] = item.rel_path
    return inode_to_logical


def _build_records(
    candidates: list[_Candidate],
    issues: list[ScanIssue],
) -> list[ManifestRecord]:
    inode_to_logical = _inode_map(candidates)
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
            digest = _hash_file(item, hash_index, hash_count, issues)
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
            _LOG.info("recording %s directory: %s", item.side.value, item.rel_path)
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
) -> ScanResult:
    """Scan both trees, hash files, and map encrypted paths via inode.

    Enumeration is deterministic: decrypted files (path-sorted), then encrypted
    files (path-sorted). ``max_files`` applies globally across both sides.
    Depth is counted from root = 0.

    Per-entry I/O errors never abort the scan: unreadable files are recorded
    with ``sha256: null`` and every failure is collected in
    :attr:`ScanResult.issues`.
    """
    limits = limits or ScanLimits()
    if limits.max_depth is not None and limits.max_depth < 0:
        msg = "max_depth must be >= 0"
        raise ScanError(msg)
    if limits.max_files is not None and limits.max_files < 0:
        msg = "max_files must be >= 0"
        raise ScanError(msg)

    _LOG.info(
        "starting scan encrypted=%s decrypted=%s max_depth=%s max_files=%s",
        encrypted,
        decrypted,
        limits.max_depth,
        limits.max_files,
    )

    issues: list[ScanIssue] = []
    decrypted_candidates = _iter_candidates(
        decrypted,
        Side.DECRYPTED,
        limits.max_depth,
        issues,
    )
    encrypted_candidates = _iter_candidates(
        encrypted,
        Side.ENCRYPTED,
        limits.max_depth,
        issues,
    )

    combined = _apply_file_limit(
        decrypted_candidates + encrypted_candidates,
        limits.max_files,
    )
    records = _build_records(combined, issues)

    mapped = sum(
        1 for record in records if record.side is Side.ENCRYPTED and record.logical_path
    )
    unmatched = sum(
        1
        for record in records
        if record.side is Side.ENCRYPTED and record.logical_path is None
    )
    _LOG.info(
        "scan complete: %d records (mapped_encrypted=%d unmatched_encrypted=%d "
        "unreadable=%d)",
        len(records),
        mapped,
        unmatched,
        len(issues),
    )
    return ScanResult(records=records, issues=issues)
