"""Tests for manifest JSONL I/O."""

from pathlib import Path

import pytest

from crypttreesum.exceptions import ManifestError
from crypttreesum.manifest import read_manifest, write_manifest
from crypttreesum.models import SCHEMA_VERSION, FileRecord, Side


def _record(**kwargs: object) -> FileRecord:
    base = {
        "schema_version": SCHEMA_VERSION,
        "side": Side.DECRYPTED,
        "inode": 1,
        "path": "a.txt",
        "logical_path": "a.txt",
        "sha256": "abc",
        "size": 3,
        "mtime_ns": 0,
    }
    base.update(kwargs)
    return FileRecord(**base)  # type: ignore[arg-type]


def test_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "out.jsonl"
    records = [
        _record(path="a.txt", logical_path="a.txt", inode=10),
        _record(
            side=Side.ENCRYPTED,
            path="cipher",
            logical_path="a.txt",
            inode=10,
            sha256="def",
        ),
        _record(
            side=Side.ENCRYPTED,
            path="gocryptfs.conf",
            logical_path=None,
            inode=99,
            sha256="meta",
        ),
    ]
    write_manifest(path, records)
    loaded = read_manifest(path)
    assert loaded == records


def test_read_rejects_bad_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text("{not-json}\n", encoding="utf-8")
    with pytest.raises(ManifestError, match="invalid JSON"):
        read_manifest(path)


def test_read_rejects_missing(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="not found"):
        read_manifest(tmp_path / "nope.jsonl")
